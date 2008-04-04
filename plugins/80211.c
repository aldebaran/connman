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

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/wireless.h>

#include <glib.h>

#include <connman/plugin.h>
#include <connman/iface.h>
#include <connman/log.h>

#include "supplicant.h"

struct iface_data {
	char ifname[IFNAMSIZ];
};

static int wifi_probe(struct connman_iface *iface)
{
	struct iface_data *data;
	struct ifreq ifr;
	int sk, err;

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0)
		return -EIO;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = iface->index;

	err = ioctl(sk, SIOCGIFNAME, &ifr);

	close(sk);

	if (err < 0)
		return -EIO;

	DBG("iface %p %s", iface, ifr.ifr_name);

	data = malloc(sizeof(*data));
	if (data == NULL)
		return -ENOMEM;

	memset(data, 0, sizeof(*data));

	memcpy(data->ifname, ifr.ifr_name, IFNAMSIZ);

	iface->type = CONNMAN_IFACE_TYPE_80211;

	iface->flags = CONNMAN_IFACE_FLAG_RTNL |
				CONNMAN_IFACE_FLAG_IPV4 |
				CONNMAN_IFACE_FLAG_SCANNING |
				CONNMAN_IFACE_FLAG_NOCARRIER;

	connman_iface_set_data(iface, data);

	return 0;
}

static void wifi_remove(struct connman_iface *iface)
{
	struct iface_data *data = connman_iface_get_data(iface);

	DBG("iface %p %s", iface, data->ifname);

	__supplicant_stop(iface);

	connman_iface_set_data(iface, NULL);

	free(data);
}

static int wifi_start(struct connman_iface *iface)
{
	struct iface_data *data = connman_iface_get_data(iface);

	DBG("iface %p %s", iface, data->ifname);

	__supplicant_start(iface);

	return 0;
}

static int wifi_stop(struct connman_iface *iface)
{
	struct iface_data *data = connman_iface_get_data(iface);

	DBG("iface %p %s", iface, data->ifname);

	__supplicant_stop(iface);

	return 0;
}

static int wifi_scan(struct connman_iface *iface)
{
	struct iface_data *data = connman_iface_get_data(iface);

	DBG("iface %p %s", iface, data->ifname);

	__supplicant_scan(iface);

	return 0;
}

static int wifi_connect(struct connman_iface *iface,
					struct connman_network *network)
{
	struct iface_data *data = connman_iface_get_data(iface);

	DBG("iface %p %s", iface, data->ifname);

	__supplicant_connect(iface, network->identifier, network->passphrase);

	return 0;
}

static int wifi_disconnect(struct connman_iface *iface)
{
	struct iface_data *data = connman_iface_get_data(iface);

	DBG("iface %p %s", iface, data->ifname);

	__supplicant_disconnect(iface);

	return 0;
}

static struct connman_iface_driver wifi_driver = {
	.name		= "80211",
	.capability	= "net.80211",
	.probe		= wifi_probe,
	.remove		= wifi_remove,
	.start		= wifi_start,
	.stop		= wifi_stop,
	.scan		= wifi_scan,
	.connect	= wifi_connect,
	.disconnect	= wifi_disconnect,
};

static int wifi_init(void)
{
	return connman_iface_register(&wifi_driver);
}

static void wifi_exit(void)
{
	connman_iface_unregister(&wifi_driver);
}

CONNMAN_PLUGIN_DEFINE("80211", "IEEE 802.11 interface plugin", VERSION,
							wifi_init, wifi_exit)
