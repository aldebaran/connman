/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2010  Intel Corporation. All rights reserved.
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
#include <net/if.h>

#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP	0x10000
#endif

#include <dbus/dbus.h>
#include <glib.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/device.h>
#include <connman/rtnl.h>
#include <connman/log.h>

#include "supplicant.h"

#define CLEANUP_TIMEOUT   8	/* in seconds */
#define INACTIVE_TIMEOUT  12	/* in seconds */

struct wifi_data {
	char *identifier;
	connman_bool_t connected;
	int index;
	unsigned flags;
	unsigned int watch;
};

static int network_probe(struct connman_network *network)
{
	DBG("network %p", network);

	return 0;
}

static void network_remove(struct connman_network *network)
{
	DBG("network %p", network);
}

static int network_connect(struct connman_network *network)
{
	DBG("network %p", network);

	return supplicant_connect(network);
}

static int network_disconnect(struct connman_network *network)
{
	DBG("network %p", network);

	return supplicant_disconnect(network);
}

static struct connman_network_driver network_driver = {
	.name		= "wifi",
	.type		= CONNMAN_NETWORK_TYPE_WIFI,
	.probe		= network_probe,
	.remove		= network_remove,
	.connect	= network_connect,
	.disconnect	= network_disconnect,
};

static void wifi_newlink(unsigned flags, unsigned change, void *user_data)
{
	struct connman_device *device = user_data;
	struct wifi_data *wifi = connman_device_get_data(device);

	DBG("index %d flags %d change %d", wifi->index, flags, change);

	if (!change)
		return;

	if ((wifi->flags & IFF_UP) != (flags & IFF_UP)) {
		if (flags & IFF_UP) {
			DBG("interface up");
		} else {
			DBG("interface down");
		}
	}

	if ((wifi->flags & IFF_LOWER_UP) != (flags & IFF_LOWER_UP)) {
		if (flags & IFF_LOWER_UP) {
			DBG("carrier on");
		} else {
			DBG("carrier off");
		}
	}

	wifi->flags = flags;
}

static int wifi_probe(struct connman_device *device)
{
	struct wifi_data *wifi;

	DBG("device %p", device);

	wifi = g_try_new0(struct wifi_data, 1);
	if (wifi == NULL)
		return -ENOMEM;

	wifi->connected = FALSE;

	connman_device_set_data(device, wifi);

	wifi->index = connman_device_get_index(device);
	wifi->flags = 0;

	wifi->watch = connman_rtnl_add_newlink_watch(wifi->index,
							wifi_newlink, device);

	return 0;
}

static void wifi_remove(struct connman_device *device)
{
	struct wifi_data *wifi = connman_device_get_data(device);

	DBG("device %p", device);

	connman_device_set_data(device, NULL);

	connman_rtnl_remove_watch(wifi->watch);

	g_free(wifi->identifier);
	g_free(wifi);
}

static int wifi_enable(struct connman_device *device)
{
	DBG("device %p", device);

	return supplicant_start(device);
}

static int wifi_disable(struct connman_device *device)
{
	struct wifi_data *wifi = connman_device_get_data(device);

	DBG("device %p", device);

	wifi->connected = FALSE;

	return supplicant_stop(device);
}

static int wifi_scan(struct connman_device *device)
{
	DBG("device %p", device);

	return supplicant_scan(device);
}

static struct connman_device_driver wifi_driver = {
	.name		= "wifi",
	.type		= CONNMAN_DEVICE_TYPE_WIFI,
	.probe		= wifi_probe,
	.remove		= wifi_remove,
	.enable		= wifi_enable,
	.disable	= wifi_disable,
	.scan		= wifi_scan,
};

static void wifi_register(void)
{
	DBG("");

	if (connman_device_driver_register(&wifi_driver) < 0)
		connman_error("Failed to register WiFi driver");
}

static void wifi_unregister(void)
{
	DBG("");

	connman_device_driver_unregister(&wifi_driver);
}

static struct supplicant_driver supplicant = {
	.name		= "wifi",
	.probe		= wifi_register,
	.remove		= wifi_unregister,
};

static int wifi_init(void)
{
	int err;

	err = connman_network_driver_register(&network_driver);
	if (err < 0)
		return err;

	err = supplicant_register(&supplicant);
	if (err < 0) {
		connman_network_driver_unregister(&network_driver);
		return err;
	}

	return 0;
}

static void wifi_exit(void)
{
	supplicant_unregister(&supplicant);

	connman_network_driver_unregister(&network_driver);
}

CONNMAN_PLUGIN_DEFINE(wifi_legacy, "WiFi interface plugin", VERSION,
		CONNMAN_PLUGIN_PRIORITY_DEFAULT, wifi_init, wifi_exit)
