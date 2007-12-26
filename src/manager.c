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

#include <gdbus.h>

#include "connman.h"

static DBusMessage *list_interfaces(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	DBusMessageIter array, iter;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &array);

	dbus_message_iter_open_container(&array, DBUS_TYPE_ARRAY,
				DBUS_TYPE_OBJECT_PATH_AS_STRING, &iter);

	__connman_iface_list(&iter);

	dbus_message_iter_close_container(&array, &iter);

	return reply;
}

static GDBusMethodTable manager_methods[] = {
	{ "ListInterfaces", "", "ao", list_interfaces },
	{ },
};

static GDBusSignalTable manager_signals[] = {
	{ "InterfaceAdded",   "o" },
	{ "InterfaceRemoved", "o" },
	{ },
};

static DBusConnection *connection = NULL;

int __connman_manager_init(DBusConnection *conn)
{
	DBG("conn %p", conn);

	connection = dbus_connection_ref(conn);
	if (connection == NULL)
		return -1;

	g_dbus_register_object(connection, CONNMAN_MANAGER_PATH, NULL, NULL);

	g_dbus_register_interface(connection, CONNMAN_MANAGER_PATH,
						CONNMAN_MANAGER_INTERFACE,
						manager_methods,
						manager_signals, NULL);

	return 0;
}

void __connman_manager_cleanup(void)
{
	DBG("conn %p", connection);

	g_dbus_unregister_interface(connection, CONNMAN_MANAGER_PATH,
						CONNMAN_MANAGER_INTERFACE);

	g_dbus_unregister_object(connection, CONNMAN_MANAGER_PATH);

	dbus_connection_unref(connection);
}
