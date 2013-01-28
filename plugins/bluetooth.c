/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2013  Intel Corporation. All rights reserved.
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
#include <connman/dbus.h>
#include <connman/technology.h>

static DBusConnection *connection;

static int bluetooth_tech_probe(struct connman_technology *technology)
{
	return 0;
}

static void bluetooth_tech_remove(struct connman_technology *technology)
{

}

static struct connman_technology_driver tech_driver = {
	.name		= "bluetooth",
	.type		= CONNMAN_SERVICE_TYPE_BLUETOOTH,
	.probe          = bluetooth_tech_probe,
	.remove         = bluetooth_tech_remove,
};

static int bluetooth_init(void)
{
	connection = connman_dbus_get_connection();
	if (connection == NULL)
		goto out;

	if (connman_technology_driver_register(&tech_driver) < 0) {
		connman_warn("Failed to initialize technology for Bluez 5");
		goto out;
	}

	return 0;

out:
	if (connection != NULL)
		dbus_connection_unref(connection);

	return -EIO;
}

static void bluetooth_exit(void)
{
	connman_technology_driver_unregister(&tech_driver);
	dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE(bluetooth, "Bluetooth technology plugin", VERSION,
                CONNMAN_PLUGIN_PRIORITY_DEFAULT, bluetooth_init, bluetooth_exit)
