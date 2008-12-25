/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2008  Intel Corporation. All rights reserved.
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

#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <connman/plugin.h>
#include <connman/device.h>
#include <connman/rtnl.h>
#include <connman/log.h>

struct ethernet_data {
	int index;
	unsigned flags;
};

static GSList *ethernet_list = NULL;

static void ethernet_newlink(unsigned short type, int index,
					unsigned flags, unsigned change)
{
	GSList *list;

	DBG("index %d flags %ld change %ld", index, flags, change);

	for (list = ethernet_list; list; list = list->next) {
		struct connman_device *device = list->data;
		struct ethernet_data *ethernet;

		ethernet = connman_device_get_data(device);
		if (ethernet == NULL)
			continue;

		if (ethernet->index != index)
			continue;

		if ((ethernet->flags & IFF_UP) != (flags & IFF_UP)) {
			if (flags & IFF_UP) {
				DBG("power on");
				connman_device_set_powered(device, TRUE);
			} else {
				DBG("power off");
				connman_device_set_powered(device, FALSE);
			}
		}

		if ((ethernet->flags & IFF_LOWER_UP) != (flags & IFF_LOWER_UP)) {
			if (flags & IFF_LOWER_UP) {
				DBG("carrier on");
				connman_device_set_carrier(device, TRUE);
			} else {
				DBG("carrier off");
				connman_device_set_carrier(device, FALSE);
			}
		}

		ethernet->flags = flags;
	}
}

static struct connman_rtnl ethernet_rtnl = {
	.name		= "ethernet",
	.newlink	= ethernet_newlink,
};

static int iface_up(struct ethernet_data *ethernet)
{
	struct ifreq ifr;
	int sk, err;

	DBG("index %d flags %d", ethernet->index, ethernet->flags);

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0)
		return -errno;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = ethernet->index;

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

static int iface_down(struct ethernet_data *ethernet)
{
	struct ifreq ifr;
	int sk, err;

	DBG("index %d flags %d", ethernet->index, ethernet->flags);

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0)
		return -errno;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = ethernet->index;

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

static int ethernet_probe(struct connman_device *device)
{
	struct ethernet_data *ethernet;

	DBG("device %p", device);

	ethernet = g_try_new0(struct ethernet_data, 1);
	if (ethernet == NULL)
		return -ENOMEM;

	ethernet_list = g_slist_append(ethernet_list, device);

	connman_device_set_data(device, ethernet);

	ethernet->index = connman_device_get_index(device);

	connman_rtnl_send_getlink();

	return 0;
}

static void ethernet_remove(struct connman_device *device)
{
	struct ethernet_data *ethernet = connman_device_get_data(device);

	DBG("device %p", device);

	connman_device_set_data(device, NULL);

	ethernet_list = g_slist_remove(ethernet_list, device);

	g_free(ethernet);
}

static int ethernet_enable(struct connman_device *device)
{
	struct ethernet_data *ethernet = connman_device_get_data(device);

	DBG("device %p", device);

	return iface_up(ethernet);
}

static int ethernet_disable(struct connman_device *device)
{
	struct ethernet_data *ethernet = connman_device_get_data(device);

	DBG("device %p", device);

	return iface_down(ethernet);
}

static struct connman_device_driver ethernet_driver = {
	.name		= "ethernet",
	.type		= CONNMAN_DEVICE_TYPE_ETHERNET,
	.probe		= ethernet_probe,
	.remove		= ethernet_remove,
	.enable		= ethernet_enable,
	.disable	= ethernet_disable,
};

static int ethernet_init(void)
{
	int err;

	err = connman_rtnl_register(&ethernet_rtnl);
	if (err < 0)
		return err;

	err = connman_device_driver_register(&ethernet_driver);
	if (err < 0) {
		connman_rtnl_unregister(&ethernet_rtnl);
		return err;
	}

	return 0;
}

static void ethernet_exit(void)
{
	connman_device_driver_unregister(&ethernet_driver);

	connman_rtnl_unregister(&ethernet_rtnl);
}

CONNMAN_PLUGIN_DEFINE(ethernet, "Ethernet interface plugin", VERSION,
						ethernet_init, ethernet_exit)
