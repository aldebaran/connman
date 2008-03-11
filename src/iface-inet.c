/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007  Intel Corporation. All rights reserved.
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
#include <net/if.h>
#include <net/ethernet.h>

#include "connman.h"

int __connman_iface_create_identifier(struct connman_iface *iface)
{
	struct ifreq ifr;
	struct ether_addr *eth;
	int sk, err;

	DBG("iface %p", iface);

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0)
		return -EIO;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = iface->index;

	err = ioctl(sk, SIOCGIFNAME, &ifr);

	if (err == 0)
		err = ioctl(sk, SIOCGIFHWADDR, &ifr);

	close(sk);

	if (err < 0)
		return -EIO;

	iface->identifier = malloc(18);
	if (iface->identifier == NULL)
		return -ENOMEM;

	eth = (void *) &ifr.ifr_hwaddr.sa_data;
	sprintf(iface->identifier, "%02X-%02X-%02X-%02X-%02X-%02X",
						eth->ether_addr_octet[0],
						eth->ether_addr_octet[1],
						eth->ether_addr_octet[2],
						eth->ether_addr_octet[3],
						eth->ether_addr_octet[4],
						eth->ether_addr_octet[5]);

	return 0;
}

int __connman_iface_init_via_inet(struct connman_iface *iface)
{
	struct ifreq ifr;
	int sk, err;

	DBG("iface %p", iface);

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0)
		return -EIO;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = iface->index;

	err = ioctl(sk, SIOCGIFNAME, &ifr);

	if (err == 0)
		err = ioctl(sk, SIOCGIFFLAGS, &ifr);

	close(sk);

	if (err < 0)
		return -EIO;

	if (ifr.ifr_flags & IFF_UP)
		iface->state = CONNMAN_IFACE_STATE_ENABLED;
	else
		iface->state = CONNMAN_IFACE_STATE_OFF;

	if (ifr.ifr_flags & IFF_RUNNING)
		iface->state = CONNMAN_IFACE_STATE_CARRIER;

	return 0;
}

int __connman_iface_up(struct connman_iface *iface)
{
	struct ifreq ifr;
	int sk, err;

	DBG("iface %p", iface);

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0)
		return -errno;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = iface->index;

	if (ioctl(sk, SIOCGIFNAME, &ifr) < 0) {
		err = -errno;
		goto done;
	}

	if (ioctl(sk, SIOCGIFFLAGS, &ifr) < 0) {
		err = -errno;
		goto done;
	}

	if (ifr.ifr_flags & IFF_UP) {
		err = -EALREADY;
		goto done;
	}

	ifr.ifr_flags |= IFF_UP;

	if (ioctl(sk, SIOCSIFFLAGS, &ifr) < 0) {
		err = -errno;
		goto done;
	}

	err = 0;

done:
	close(sk);

	return err;
}

int __connman_iface_down(struct connman_iface *iface)
{
	struct ifreq ifr;
	int sk, err;

	DBG("iface %p", iface);

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0)
		return -errno;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = iface->index;

	if (ioctl(sk, SIOCGIFNAME, &ifr) < 0) {
		err = -errno;
		goto done;
	}

	if (ioctl(sk, SIOCGIFFLAGS, &ifr) < 0) {
		err = -errno;
		goto done;
	}

	if (!(ifr.ifr_flags & IFF_UP)) {
		err = -EALREADY;
		goto done;
	}

	ifr.ifr_flags &= ~IFF_UP;

	if (ioctl(sk, SIOCSIFFLAGS, &ifr) < 0)
		err = -errno;
	else
		err = 0;

done:
	close(sk);

	return err;
}
