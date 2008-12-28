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

#include "inet.h"

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

	return inet_ifup(ethernet->index);
}

static int ethernet_disable(struct connman_device *device)
{
	struct ethernet_data *ethernet = connman_device_get_data(device);

	DBG("device %p", device);

	return inet_ifdown(ethernet->index);
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
