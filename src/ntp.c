/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2012  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <glib.h>

#include "connman.h"

struct ntp_short {
	uint16_t seconds;
	uint16_t fraction;
} __attribute__ ((packed));

struct ntp_time {
	uint32_t seconds;
	uint32_t fraction;
} __attribute__ ((packed));

struct ntp_msg {
	uint8_t flags;			/* Mode, version and leap indicator */
	uint8_t stratum;		/* Stratum details */
	int8_t poll;			/* Maximum interval in log2 seconds */
	int8_t precision;		/* Clock precision in log2 seconds */
	struct ntp_short rootdelay;	/* Root delay */
	struct ntp_short rootdisp;	/* Root dispersion */
	uint32_t refid;			/* Reference ID */
	struct ntp_time reftime;	/* Reference timestamp */
	struct ntp_time orgtime;	/* Origin timestamp */
	struct ntp_time rectime;	/* Receive timestamp */
	struct ntp_time xmttime;	/* Transmit timestamp */
} __attribute__ ((packed));

#define OFFSET_1900_1970  2208988800UL	/* 1970 - 1900 in seconds */

#define STEPTIME_MIN_OFFSET  0.128

#define LOGTOD(a)  ((a) < 0 ? 1. / (1L << -(a)) : 1L << (int)(a))

static guint channel_watch = 0;
static struct timeval transmit_timeval;
static int transmit_fd = 0;

static char *timeserver = NULL;
static gint poll_id = 0;
static gint timeout_id = 0;

static void send_packet(int fd, const char *server)
{
	struct ntp_msg msg;
	struct sockaddr_in addr;
	ssize_t len;

	memset(&msg, 0, sizeof(msg));
	msg.flags = 0x23;
	msg.poll = 4;	// min
	msg.poll = 10;	// max
	msg.xmttime.seconds = random();
	msg.xmttime.fraction = random();

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(123);
	addr.sin_addr.s_addr = inet_addr(server);

	gettimeofday(&transmit_timeval, NULL);

	len = sendto(fd, &msg, sizeof(msg), MSG_DONTWAIT,
						&addr, sizeof(addr));
	if (len < 0) {
		connman_error("Time request for server %s failed", server);
		return;
	}

	if (len != sizeof(msg)) {
		connman_error("Broken time request for server %s", server);
		return;
	}
}

static gboolean next_server(gpointer user_data)
{
	if (timeserver != NULL) {
		g_free(timeserver);
		timeserver = NULL;
	}

	__connman_timeserver_sync_next();

	return FALSE;
}

static gboolean next_poll(gpointer user_data)
{
	if (timeserver == NULL || transmit_fd == 0)
		return FALSE;

	send_packet(transmit_fd, timeserver);

	return FALSE;
}

static void decode_msg(void *base, size_t len, struct timeval *tv)
{
	struct ntp_msg *msg = base;
	double org, rec, xmt, dst;
	double delay, offset;
	static guint transmit_delay;

	if (len < sizeof(*msg)) {
		connman_error("Invalid response from time server");
		return;
	}

	if (tv == NULL) {
		connman_error("Invalid packet timestamp from time server");
		return;
	}

	DBG("flags      : 0x%02x", msg->flags);
	DBG("stratum    : %u", msg->stratum);
	DBG("poll       : %f seconds (%d)",
				LOGTOD(msg->poll), msg->poll);
	DBG("precision  : %f seconds (%d)",
				LOGTOD(msg->precision), msg->precision);
	DBG("root delay : %u seconds (fraction %u)",
			msg->rootdelay.seconds, msg->rootdelay.fraction);
	DBG("root disp. : %u seconds (fraction %u)",
			msg->rootdisp.seconds, msg->rootdisp.fraction);
	DBG("reference  : 0x%04x", msg->refid);

	transmit_delay = LOGTOD(msg->poll);

	if (msg->flags != 0x24)
		return;

	org = transmit_timeval.tv_sec +
			(1.0e-6 * transmit_timeval.tv_usec) + OFFSET_1900_1970;
	rec = ntohl(msg->rectime.seconds) +
			((double) ntohl(msg->rectime.fraction) / UINT_MAX);
	xmt = ntohl(msg->xmttime.seconds) +
			((double) ntohl(msg->xmttime.fraction) / UINT_MAX);
	dst = tv->tv_sec + (1.0e-6 * tv->tv_usec) + OFFSET_1900_1970;

	DBG("org=%f rec=%f xmt=%f dst=%f", org, rec, xmt, dst);

	offset = ((rec - org) + (xmt - dst)) / 2;
	delay = (dst - org) - (xmt - rec);

	DBG("offset=%f delay=%f", offset, delay);

	/* Remove the timeout, as timeserver has responded */
	if (timeout_id > 0)
		g_source_remove(timeout_id);

	/*
	 * Now poll the server every transmit_delay seconds
	 * for time correction.
	 */
	if (poll_id > 0)
		g_source_remove(poll_id);

	DBG("Timeserver %s, next sync in %d seconds", timeserver, transmit_delay);

	poll_id = g_timeout_add_seconds(transmit_delay, next_poll, NULL);

	connman_info("ntp: time slew %+.6f s", offset);

	if (offset < STEPTIME_MIN_OFFSET && offset > -STEPTIME_MIN_OFFSET) {
		struct timeval adj;

		adj.tv_sec = (long) offset;
		adj.tv_usec = (offset - adj.tv_sec) * 1000000;

		DBG("adjusting time");

		if (adjtime(&adj, &adj) < 0) {
			connman_error("Failed to adjust time");
			return;
		}

		DBG("%lu seconds, %lu msecs", adj.tv_sec, adj.tv_usec);
	} else {
		struct timeval cur;
		double dtime;

		gettimeofday(&cur, NULL);
		dtime = offset + cur.tv_sec + 1.0e-6 * cur.tv_usec;
		cur.tv_sec = (long) dtime;
		cur.tv_usec = (dtime - cur.tv_sec) * 1000000;

		DBG("setting time");

		if (settimeofday(&cur, NULL) < 0) {
			connman_error("Failed to set time");
			return;
		}

		DBG("%lu seconds, %lu msecs", cur.tv_sec, cur.tv_usec);
	}
}

static gboolean received_data(GIOChannel *channel, GIOCondition condition,
							gpointer user_data)
{
	unsigned char buf[128];
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmsg;
	struct timeval *tv;
	char aux[128];
	ssize_t len;
	int fd;

	if (condition & (G_IO_HUP | G_IO_ERR | G_IO_NVAL)) {
		connman_error("Problem with timer server channel");
		channel_watch = 0;
		return FALSE;
	}

	fd = g_io_channel_unix_get_fd(channel);

	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = aux;
	msg.msg_controllen = sizeof(aux);

	len = recvmsg(fd, &msg, MSG_DONTWAIT);
	if (len < 0)
		return TRUE;

	tv = NULL;

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level != SOL_SOCKET)
			continue;

		switch (cmsg->cmsg_type) {
		case SCM_TIMESTAMP:
			tv = (struct timeval *) CMSG_DATA(cmsg);
			break;
		}
	}

	decode_msg(iov.iov_base, iov.iov_len, tv);

	return TRUE;
}

static void start_ntp(char *server)
{
	GIOChannel *channel;
	struct sockaddr_in addr;
	int tos = IPTOS_LOWDELAY, timestamp = 1;

	if (server == NULL)
		return;

	DBG("server %s", server);

	if (channel_watch > 0)
		goto send;

	transmit_fd = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (transmit_fd < 0) {
		connman_error("Failed to open time server socket");
		return;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;

	if (bind(transmit_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		connman_error("Failed to bind time server socket");
		close(transmit_fd);
		return;
	}

	if (setsockopt(transmit_fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) < 0) {
		connman_error("Failed to set type of service option");
		close(transmit_fd);
		return;
	}

	if (setsockopt(transmit_fd, SOL_SOCKET, SO_TIMESTAMP, &timestamp,
						sizeof(timestamp)) < 0) {
		connman_error("Failed to enable timestamp support");
		close(transmit_fd);
		return;
	}

	channel = g_io_channel_unix_new(transmit_fd);
	if (channel == NULL) {
		close(transmit_fd);
		return;
	}

	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);

	g_io_channel_set_close_on_unref(channel, TRUE);

	channel_watch = g_io_add_watch_full(channel, G_PRIORITY_DEFAULT,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				received_data, NULL, NULL);

	g_io_channel_unref(channel);

send:
	send_packet(transmit_fd, server);
}

int __connman_ntp_start(char *server)
{
	DBG("%s", server);

	if (server == NULL)
		return -EINVAL;

	if (timeserver != NULL)
		g_free(timeserver);

	timeserver = g_strdup(server);

	start_ntp(timeserver);

	/*
	 * Add a fallback timeout , preferably short, 5 sec here,
	 * to fallback on the next server.
	 */

	timeout_id = g_timeout_add_seconds(5, next_server, NULL);

	return 0;
}

void __connman_ntp_stop()
{
	DBG("");

	if (poll_id > 0)
		g_source_remove(poll_id);

	if (timeout_id > 0)
		g_source_remove(timeout_id);

	if (channel_watch > 0) {
		g_source_remove(channel_watch);
		channel_watch = 0;
		transmit_fd = 0;
	}

	if (timeserver != NULL) {
		g_free(timeserver);
		timeserver = NULL;
	}
}
