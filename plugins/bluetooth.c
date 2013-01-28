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

static DBusConnection *connection;

static int bluetooth_init(void)
{
	connection = connman_dbus_get_connection();
	if (connection == NULL)
		return -EIO;

	return 0;
}

static void bluetooth_exit(void)
{
	dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE(bluetooth, "Bluetooth technology plugin", VERSION,
                CONNMAN_PLUGIN_PRIORITY_DEFAULT, bluetooth_init, bluetooth_exit)
