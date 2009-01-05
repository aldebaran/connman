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

#include <dbus/dbus.h>
#include <glib.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/device.h>
#include <connman/log.h>

#include "inet.h"
#include "supplicant.h"

#define CLEANUP_TIMEOUT   8	/* in seconds */
#define INACTIVE_TIMEOUT  12	/* in seconds */

struct wifi_data {
	char *identifier;
	connman_bool_t connected;
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

static int wifi_probe(struct connman_device *device)
{
	struct wifi_data *data;

	DBG("device %p", device);

	data = g_try_new0(struct wifi_data, 1);
	if (data == NULL)
		return -ENOMEM;

	data->connected = FALSE;

	connman_device_set_data(device, data);

	return 0;
}

static void wifi_remove(struct connman_device *device)
{
	struct wifi_data *data = connman_device_get_data(device);

	DBG("device %p", device);

	connman_device_set_data(device, NULL);

	g_free(data->identifier);
	g_free(data);
}

static int wifi_enable(struct connman_device *device)
{
	DBG("device %p", device);

	return supplicant_start(device);
}

static int wifi_disable(struct connman_device *device)
{
	struct wifi_data *data = connman_device_get_data(device);

	DBG("device %p", device);

	data->connected = FALSE;

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

CONNMAN_PLUGIN_DEFINE(wifi, "WiFi interface plugin", VERSION,
							wifi_init, wifi_exit)
