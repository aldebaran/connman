/*
 *
 *  Resolver library with GLib integration
 *
 *  Copyright (C) 2009-2010  Intel Corporation. All rights reserved.
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

#include <errno.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <resolv.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>

#include "gresolv.h"

struct resolv_nameserver {
	GResolv *resolv;

	char *address;
	uint16_t port;
	unsigned long flags;

	GIOChannel *udp_channel;
	guint udp_watch;
};

struct _GResolv {
	gint ref_count;

	int index;
	GList *nameserver_list;

	GResolvDebugFunc debug_func;
	gpointer debug_data;
};

static inline void debug(GResolv *resolv, const char *format, ...)
{
	char str[256];
	va_list ap;

	if (resolv->debug_func == NULL)
		return;

	va_start(ap, format);

	if (vsnprintf(str, sizeof(str), format, ap) > 0)
		resolv->debug_func(str, resolv->debug_data);

	va_end(ap);
}

static void free_nameserver(struct resolv_nameserver *nameserver)
{
	if (nameserver == NULL)
		return;

	if (nameserver->udp_watch > 0)
		g_source_remove(nameserver->udp_watch);

	if (nameserver->udp_channel != NULL)
		g_io_channel_unref(nameserver->udp_channel);

	g_free(nameserver->address);
	g_free(nameserver);
}

static void flush_nameservers(GResolv *resolv)
{
	GList *list;

	for (list = g_list_first(resolv->nameserver_list);
					list; list = g_list_next(list))
		free_nameserver(list->data);

	g_list_free(resolv->nameserver_list);
	resolv->nameserver_list = NULL;
}

static int send_query(GResolv *resolv, const unsigned char *buf, int len)
{
	GList *list;

	if (resolv->nameserver_list == NULL)
		return -ENOENT;

	for (list = g_list_first(resolv->nameserver_list);
					list; list = g_list_next(list)) {
		struct resolv_nameserver *nameserver = list->data;
		int sk, sent;

		if (nameserver->udp_channel == NULL)
			continue;

		sk = g_io_channel_unix_get_fd(nameserver->udp_channel);

		sent = send(sk, buf, len, 0);
	}

	return 0;
}

static void parse_response(struct resolv_nameserver *nameserver,
					const unsigned char *buf, int len)
{
	GResolv *resolv = nameserver->resolv;
	ns_msg msg;
	ns_rr rr;
	int i, rcode;

	debug(resolv, "response from %s", nameserver->address);

	ns_initparse(buf, len, &msg);

	rcode = ns_msg_getflag(msg, ns_f_rcode);

	debug(resolv, "msg id: 0x%04x rcode: %d count: %d",
			ns_msg_id(msg), rcode, ns_msg_count(msg, ns_s_an));

	for (i = 0; i < ns_msg_count(msg, ns_s_an); i++) {
		char result[100];

		ns_parserr(&msg, ns_s_an, i, &rr);

		if (ns_rr_class(rr) != ns_c_in)
			continue;

		if (ns_rr_type(rr) != ns_t_a)
			continue;

		if (ns_rr_rdlen(rr) != NS_INADDRSZ)
			continue;

		inet_ntop(AF_INET, ns_rr_rdata(rr), result, sizeof(result));

		debug(resolv, "result: %s", result);
	}
}

static gboolean received_udp_data(GIOChannel *channel, GIOCondition cond,
							gpointer user_data)
{
	struct resolv_nameserver *nameserver = user_data;
	unsigned char buf[4096];
	int sk, len;

	if (cond & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		nameserver->udp_watch = 0;
		return FALSE;
	}

	sk = g_io_channel_unix_get_fd(nameserver->udp_channel);

	len = recv(sk, buf, sizeof(buf), 0);
	if (len < 12)
		return TRUE;

	parse_response(nameserver, buf, len);

	return TRUE;
}

static int connect_udp_channel(struct resolv_nameserver *nameserver)
{
	struct sockaddr_in sin;
	int sk;

	sk = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sk < 0)
		return -EIO;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(nameserver->port);
	sin.sin_addr.s_addr = inet_addr(nameserver->address);

	if (connect(sk, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
		close(sk);
		return -EIO;
	}

	nameserver->udp_channel = g_io_channel_unix_new(sk);
	if (nameserver->udp_channel == NULL) {
		close(sk);
		return -ENOMEM;
	}

	g_io_channel_set_close_on_unref(nameserver->udp_channel, TRUE);

	nameserver->udp_watch = g_io_add_watch(nameserver->udp_channel,
						G_IO_IN, received_udp_data,
								nameserver);

	return 0;
}

GResolv *g_resolv_new(int index)
{
	GResolv *resolv;

	if (index < 0)
		return NULL;

	resolv = g_try_new0(GResolv, 1);
	if (resolv == NULL)
		return NULL;

	resolv->ref_count = 1;

	resolv->index = index;
	resolv->nameserver_list = NULL;

	return resolv;
}

GResolv *g_resolv_ref(GResolv *resolv)
{
	if (resolv == NULL)
		return NULL;

	g_atomic_int_inc(&resolv->ref_count);

	return resolv;
}

void g_resolv_unref(GResolv *resolv)
{
	if (resolv == NULL)
		return;

	if (g_atomic_int_dec_and_test(&resolv->ref_count) == FALSE)
		return;

	flush_nameservers(resolv);

	g_free(resolv);
}

void g_resolv_set_debug(GResolv *resolv,
                                GResolvDebugFunc func, gpointer data)
{
	if (resolv == NULL)
		return;

	resolv->debug_func = func;
	resolv->debug_data = data;
}

int g_resolv_add_nameserver(GResolv *resolv, const char *address,
					uint16_t port, unsigned long flags)
{
	struct resolv_nameserver *nameserver;

	if (resolv == NULL)
		return -EINVAL;

	nameserver = g_try_new0(struct resolv_nameserver, 1);
	if (nameserver == NULL)
		return -ENOMEM;

	nameserver->address = g_strdup(address);
	nameserver->port = port;
	nameserver->flags = flags;

	if (connect_udp_channel(nameserver) < 0) {
		free_nameserver(nameserver);
		return -EIO;
	}

	nameserver->resolv = resolv;

	resolv->nameserver_list = g_list_append(resolv->nameserver_list,
								nameserver);

	debug(resolv, "setting nameserver %s", address);

	return 0;
}

void g_resolv_flush_nameservers(GResolv *resolv)
{
	if (resolv == NULL)
		return;

	flush_nameservers(resolv);
}

int g_resolv_lookup_hostname(GResolv *resolv, const char *hostname)
{
	unsigned char buf[4096];
	int len;

	debug(resolv, "lookup hostname %s", hostname);

	len = res_mkquery(ns_o_query, hostname, ns_c_in, ns_t_a,
					NULL, 0, NULL, buf, sizeof(buf));

	if (send_query(resolv, buf, len) < 0)
		return -EIO;

	return 0;
}
