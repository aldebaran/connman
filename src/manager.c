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

static const char *master_state = "unknown";

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

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &master_state,
							DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *register_agent(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	const char *path;

	DBG("conn %p", conn);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_INVALID);

	__connman_agent_register(path);

	return reply;
}

static DBusMessage *unregister_agent(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	const char *path;

	DBG("conn %p", conn);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_INVALID);

	__connman_agent_unregister(path);

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

static DBusMessage *activate_device(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	const char *path;

	DBG("conn %p", conn);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID);

	DBG("device %s", path);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *set_wireless(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	dbus_bool_t enabled;

	DBG("conn %p", conn);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_BOOLEAN, &enabled,
							DBUS_TYPE_INVALID);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *get_wireless(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	dbus_bool_t enabled = TRUE;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_BOOLEAN, &enabled,
							DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *do_sleep(DBusConnection *conn,
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

static DBusMessage *do_wake(DBusConnection *conn,
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

static DBusMessage *do_state(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	dbus_uint32_t state = NM_STATE_DISCONNECTED;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_UINT32, &state,
							DBUS_TYPE_INVALID);

	return reply;
}

static GDBusMethodTable nm_methods[] = {
	{ "getDevices",            "",  "ao", list_interfaces },
	{ "setActiveDevice",       "o", "",   activate_device },
	{ "setWirelessEnabled",    "b", "",   set_wireless    },
	{ "getWirelessEnabled",    "",  "b",  get_wireless    },
	{ "sleep",                 "",  "",   do_sleep        },
	{ "wake",                  "",  "",   do_wake         },
	{ "state",                 "",  "u",  do_state        },
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
