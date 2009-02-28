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
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/log.h>

static int loopback_init(void)
{
	struct ifreq ifr;
	struct sockaddr_in *addr;
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
		err = -EALREADY;
		connman_info("The loopback interface is already up");
		goto done;
	}

	addr = (struct sockaddr_in *) &ifr.ifr_addr;
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = inet_addr("127.0.0.0");

	err = ioctl(sk, SIOCSIFADDR, &ifr);
	if (err < 0) {
		err = -errno;
		connman_error("Setting address failed (%s)", strerror(-err));
		goto done;
	}

	addr = (struct sockaddr_in *) &ifr.ifr_netmask;
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = inet_addr("255.0.0.0");

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

static void loopback_exit(void)
{
}

CONNMAN_PLUGIN_DEFINE(loopback, "Loopback device plugin", VERSION,
		CONNMAN_PLUGIN_PRIORITY_HIGH, loopback_init, loopback_exit)
