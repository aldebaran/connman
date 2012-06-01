/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2012  BMW Car IT GmbH. All rights reserved.
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

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/device.h>
#include <connman/network.h>
#include <connman/dbus.h>

static DBusConnection *connection;

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

	return 0;
}

static int network_disconnect(struct connman_network *network)
{
	DBG("network %p", network);

	return 0;
}

static struct connman_network_driver network_driver = {
	.name		= "network",
	.type		= CONNMAN_NETWORK_TYPE_BLUETOOTH_DUN,
	.probe		= network_probe,
	.remove		= network_remove,
	.connect	= network_connect,
	.disconnect	= network_disconnect,
};

static int dundee_probe(struct connman_device *device)
{
	DBG("device %p", device);

	return 0;
}

static void dundee_remove(struct connman_device *device)
{
	DBG("device %p", device);
}

static int dundee_enable(struct connman_device *device)
{
	DBG("device %p", device);

	return 0;
}

static int dundee_disable(struct connman_device *device)
{
	DBG("device %p", device);

	return 0;
}

static struct connman_device_driver dundee_driver = {
	.name		= "dundee",
	.type		= CONNMAN_DEVICE_TYPE_BLUETOOTH,
	.probe		= dundee_probe,
	.remove		= dundee_remove,
	.enable		= dundee_enable,
	.disable	= dundee_disable,
};

static int dundee_init(void)
{
	int err;

	connection = connman_dbus_get_connection();
	if (connection == NULL)
		return -EIO;

	err = connman_network_driver_register(&network_driver);
	if (err < 0)
		goto remove;

	err = connman_device_driver_register(&dundee_driver);
	if (err < 0) {
		connman_network_driver_unregister(&network_driver);
		goto remove;
	}

	return 0;

remove:
	dbus_connection_unref(connection);

	return err;
}

static void dundee_exit(void)
{
	connman_device_driver_unregister(&dundee_driver);
	connman_network_driver_unregister(&network_driver);

	dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE(dundee, "Dundee plugin", VERSION,
		CONNMAN_PLUGIN_PRIORITY_DEFAULT, dundee_init, dundee_exit)
