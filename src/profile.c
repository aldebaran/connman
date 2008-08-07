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

#include <glib.h>
#include <gdbus.h>

#include "connman.h"

void __connman_profile_list(DBusMessageIter *iter)
{
	const char *path = "/profile/default";

	DBG("");

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &path);
}

static void append_string(DBusMessageIter *dict, const char *key, void *val)
{
	DBusMessageIter entry, value;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
								NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
					DBUS_TYPE_STRING_AS_STRING, &value);
	dbus_message_iter_append_basic(&value, DBUS_TYPE_STRING, val);
	dbus_message_iter_close_container(&entry, &value);

	dbus_message_iter_close_container(dict, &entry);
}

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *name = "Default";
	DBusMessage *reply;
	DBusMessageIter array, dict;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &array);

	dbus_message_iter_open_container(&array, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	append_string(&dict, "Name", &name);

	dbus_message_iter_close_container(&array, &dict);

	return reply;
}

static GDBusMethodTable profile_methods[] = {
	{ "GetProperties", "", "a{sv}", get_properties },
	{ },
};

static DBusConnection *connection = NULL;

int __connman_profile_init(DBusConnection *conn)
{
	DBG("conn %p", conn);

	connection = dbus_connection_ref(conn);
	if (connection == NULL)
		return -1;

	g_dbus_register_interface(connection, "/profile/default",
						CONNMAN_PROFILE_INTERFACE,
						profile_methods,
						NULL, NULL, NULL, NULL);

	return 0;
}

void __connman_profile_cleanup(void)
{
	DBG("conn %p", connection);

	g_dbus_unregister_interface(connection, "/profile/default",
						CONNMAN_PROFILE_INTERFACE);

	if (connection == NULL)
		return;

	dbus_connection_unref(connection);
}
