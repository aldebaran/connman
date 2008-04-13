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

static DBusMessage *get_state(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	const char *state;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	if (__connman_iface_is_connected() == TRUE)
		state = "online";
	else
		state = "offline";

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &state,
							DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *register_agent(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	const char *sender, *path;

	DBG("conn %p", conn);

	sender = dbus_message_get_sender(msg);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_INVALID);

	__connman_agent_register(sender, path);

	return reply;
}

static DBusMessage *unregister_agent(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	const char *sender, *path;

	DBG("conn %p", conn);

	sender = dbus_message_get_sender(msg);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_INVALID);

	__connman_agent_unregister(sender, path);

	return reply;
}

static GDBusMethodTable manager_methods[] = {
	{ "ListInterfaces",  "",  "ao", list_interfaces  },
	{ "GetState",        "",  "s",  get_state        },
	{ "RegisterAgent",   "o", "",   register_agent   },
	{ "UnregisterAgent", "o", "",   unregister_agent },
	{ },
};

static GDBusSignalTable manager_signals[] = {
	{ "InterfaceAdded",   "o" },
	{ "InterfaceRemoved", "o" },
	{ "StateChanged",     "s" },
	{ },
};

static DBusMessage *nm_sleep(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *nm_wake(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_INVALID);

	return reply;
}

enum {
	NM_STATE_UNKNOWN = 0,
	NM_STATE_ASLEEP,
	NM_STATE_CONNECTING,
	NM_STATE_CONNECTED,
	NM_STATE_DISCONNECTED
};

static DBusMessage *nm_state(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	dbus_uint32_t state;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	if (__connman_iface_is_connected() == TRUE)
		state = NM_STATE_CONNECTED;
	else
		state = NM_STATE_DISCONNECTED;

	dbus_message_append_args(reply, DBUS_TYPE_UINT32, &state,
							DBUS_TYPE_INVALID);

	return reply;
}

static GDBusMethodTable nm_methods[] = {
	{ "sleep",                 "",  "",   nm_sleep        },
	{ "wake",                  "",  "",   nm_wake         },
	{ "state",                 "",  "u",  nm_state        },
	{ },
};

static DBusConnection *connection = NULL;
static int nm_compat = 0;

int __connman_manager_init(DBusConnection *conn, int compat)
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

	if (compat) {
		g_dbus_register_object(connection, NM_PATH, NULL, NULL);

		g_dbus_register_interface(connection, NM_PATH, NM_INTERFACE,
						nm_methods, NULL, NULL);

		nm_compat = 1;
	}

	return 0;
}

void __connman_manager_cleanup(void)
{
	DBG("conn %p", connection);

	if (nm_compat) {
		g_dbus_unregister_interface(connection, NM_PATH, NM_INTERFACE);

		g_dbus_unregister_object(connection, NM_PATH);
	}

	g_dbus_unregister_interface(connection, CONNMAN_MANAGER_PATH,
						CONNMAN_MANAGER_INTERFACE);

	g_dbus_unregister_object(connection, CONNMAN_MANAGER_PATH);

	dbus_connection_unref(connection);
}
