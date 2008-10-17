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

#include <errno.h>

#include <gdbus.h>

#include <connman/plugin.h>
#include <connman/device.h>
#include <connman/log.h>

#define BLUEZ_SERVICE "org.bluez"

static int bluetooth_probe(struct connman_device *device)
{
	DBG("device %p", device);

	return 0;
}

static void bluetooth_remove(struct connman_device *device)
{
	DBG("device %p", device);
}

static struct connman_device_driver bluetooth_driver = {
	.name	= "bluetooth",
	.type	= CONNMAN_DEVICE_TYPE_BLUETOOTH,
	.probe	= bluetooth_probe,
	.remove	= bluetooth_remove,
};

static void bluetooth_connect(DBusConnection *connection, void *user_data)
{
	DBG("connection %p", connection);
}

static void bluetooth_disconnect(DBusConnection *connection, void *user_data)
{
	DBG("connection %p", connection);
}

static DBusConnection *connection;
static guint watch;

static int bluetooth_init(void)
{
	int err;

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (connection == NULL)
		return -EIO;

	err = connman_device_driver_register(&bluetooth_driver);
	if (err < 0) {
		dbus_connection_unref(connection);
		return -EIO;
	}

	watch = g_dbus_add_service_watch(connection, BLUEZ_SERVICE,
			bluetooth_connect, bluetooth_disconnect, NULL, NULL);
	if (watch == 0) {
		connman_device_driver_unregister(&bluetooth_driver);
		dbus_connection_unref(connection);
		return -EIO;
	}

	return 0;
}

static void bluetooth_exit(void)
{
	g_dbus_remove_watch(connection, watch);

	connman_device_driver_unregister(&bluetooth_driver);

	dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE("bluetooth", "Bluetooth technology plugin", VERSION,
						bluetooth_init, bluetooth_exit)
