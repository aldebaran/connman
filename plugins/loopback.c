/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2009  Intel Corporation. All rights reserved.
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
#include <limits.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <glib.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/log.h>

static in_addr_t loopback_address;
static in_addr_t loopback_netmask;

#if 0
static GIOChannel *inotify_channel = NULL;

static int hostname_descriptor = -1;

static gboolean inotify_event(GIOChannel *channel,
					GIOCondition condition, gpointer data)
{
	unsigned char buf[129], *ptr = buf;
	gsize len;
	GIOError err;

	if (condition & (G_IO_HUP | G_IO_ERR))
		return FALSE;

	memset(buf, 0, sizeof(buf));

	err = g_io_channel_read(channel, (gchar *) buf, sizeof(buf) - 1, &len);
	if (err != G_IO_ERROR_NONE) {
		if (err == G_IO_ERROR_AGAIN)
			return TRUE;
		connman_error("Reading from inotify channel failed");
		return FALSE;
	}

	while (len >= sizeof(struct inotify_event)) {
		struct inotify_event *evt = (struct inotify_event *) ptr;

		if (evt->wd == hostname_descriptor) {
			if (evt->mask & (IN_CREATE | IN_MOVED_TO))
				connman_info("create hostname file");

			if (evt->mask & (IN_DELETE | IN_MOVED_FROM))
				connman_info("delete hostname file");

			if (evt->mask & (IN_MODIFY | IN_MOVE_SELF))
				connman_info("modify hostname file");
		}

		len -= sizeof(struct inotify_event) + evt->len;
		ptr += sizeof(struct inotify_event) + evt->len;
	}

	return TRUE;
}

static int create_watch(void)
{
	int fd;

	fd = inotify_init();
	if (fd < 0) {
		connman_error("Creation of inotify context failed");
		return -EIO;
	}

	inotify_channel = g_io_channel_unix_new(fd);
	if (inotify_channel == NULL) {
		connman_error("Creation of inotify channel failed");
		close(fd);
		return -EIO;
	}

	hostname_descriptor = inotify_add_watch(fd, "/etc/hostname",
				IN_MODIFY | IN_DELETE_SELF | IN_MOVE_SELF);
	if (hostname_descriptor < 0) {
		connman_error("Creation of hostname watch failed");
		g_io_channel_unref(inotify_channel);
		inotify_channel = NULL;
		close(fd);
		return -EIO;
	}

	g_io_add_watch(inotify_channel, G_IO_IN | G_IO_ERR | G_IO_HUP,
							inotify_event, NULL);

	return 0;
}

static void remove_watch(void)
{
	int fd;

	if (inotify_channel == NULL)
		return;

	fd = g_io_channel_unix_get_fd(inotify_channel);

	if (hostname_descriptor >= 0)
		inotify_rm_watch(fd, hostname_descriptor);

	g_io_channel_unref(inotify_channel);

	close(fd);
}
#endif

static void create_hostname(void)
{
	const char *name = "localhost";

	if (sethostname(name, strlen(name)) < 0)
		connman_error("Failed to set hostname to %s", name);
}

static int setup_hostname(void)
{
	char name[HOST_NAME_MAX + 1];

	memset(name, 0, sizeof(name));

	if (gethostname(name, HOST_NAME_MAX) < 0) {
		connman_error("Failed to get current hostname");
		return -EIO;
	}

	if (strlen(name) > 0 && strcmp(name, "(none)") != 0)
		connman_info("System hostname is %s", name);
	else
		create_hostname();

	memset(name, 0, sizeof(name));

	if (getdomainname(name, HOST_NAME_MAX) < 0) {
		connman_error("Failed to get current domainname");
		return -EIO;
	}

	if (strlen(name) > 0 && strcmp(name, "(none)") != 0)
		connman_info("System domainname is %s", name);

	return 0;
}

static gboolean valid_loopback(int sk, struct ifreq *ifr)
{
	struct sockaddr_in *addr;
	int err;

	err = ioctl(sk, SIOCGIFADDR, ifr);
	if (err < 0) {
		err = -errno;
		connman_error("Getting address failed (%s)", strerror(-err));
		return TRUE;
	}

	addr = (struct sockaddr_in *) &ifr->ifr_addr;
	if (addr->sin_addr.s_addr != loopback_address)
		return FALSE;

	err = ioctl(sk, SIOCGIFNETMASK, ifr);
	if (err < 0) {
		err = -errno;
		connman_error("Getting netmask failed (%s)", strerror(-err));
		return TRUE;
	}

	addr = (struct sockaddr_in *) &ifr->ifr_netmask;
	if (addr->sin_addr.s_addr != loopback_netmask)
		return FALSE;

	return TRUE;
}

static int setup_loopback(void)
{
	struct ifreq ifr;
	struct sockaddr_in addr;
	int sk, err;

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, "lo");

	if (ioctl(sk, SIOCGIFFLAGS, &ifr) < 0) {
		err = -errno;
		goto done;
	}

	if (ifr.ifr_flags & IFF_UP) {
		connman_info("Checking loopback interface settings");
		if (valid_loopback(sk, &ifr) == TRUE) {
			err = -EALREADY;
			goto done;
		}

		connman_warn("Correcting wrong lookback settings");
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	memcpy(&ifr.ifr_addr, &addr, sizeof(ifr.ifr_addr));

	err = ioctl(sk, SIOCSIFADDR, &ifr);
	if (err < 0) {
		err = -errno;
		connman_error("Setting address failed (%s)", strerror(-err));
		goto done;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("255.0.0.0");
	memcpy(&ifr.ifr_netmask, &addr, sizeof(ifr.ifr_netmask));

	err = ioctl(sk, SIOCSIFNETMASK, &ifr);
	if (err < 0) {
		err = -errno;
		connman_error("Setting netmask failed (%s)", strerror(-err));
		goto done;
	}

	if (ioctl(sk, SIOCGIFFLAGS, &ifr) < 0) {
		err = -errno;
		goto done;
	}

	ifr.ifr_flags |= IFF_UP;

	if (ioctl(sk, SIOCSIFFLAGS, &ifr) < 0) {
		err = -errno;
		connman_error("Activating loopback interface failed (%s)",
							strerror(-err));
		goto done;
	}

done:
	close(sk);

	return err;
}

static int loopback_init(void)
{
	loopback_address = inet_addr("127.0.0.1");
	loopback_netmask = inet_addr("255.0.0.0");

	setup_loopback();

	setup_hostname();

	//create_watch();

	return 0;
}

static void loopback_exit(void)
{
	//remove_watch();
}

CONNMAN_PLUGIN_DEFINE(loopback, "Loopback device plugin", VERSION,
		CONNMAN_PLUGIN_PRIORITY_HIGH, loopback_init, loopback_exit)
