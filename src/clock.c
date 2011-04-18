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

#include <gdbus.h>

#include "connman.h"

static char **timeservers_config = NULL;

static void append_timeservers(DBusMessageIter *iter, void *user_data)
{
	int i;

	if (timeservers_config == NULL)
		return;

	for (i = 0; timeservers_config[i] != NULL; i++) {
		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &timeservers_config[i]);
	}
}

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	DBusMessageIter array, dict;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &array);

	connman_dbus_dict_open(&array, &dict);

	connman_dbus_dict_append_array(&dict, "Timeservers",
				DBUS_TYPE_STRING, append_timeservers, NULL);

	connman_dbus_dict_close(&array, &dict);

	return reply;
}

static DBusMessage *set_property(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessageIter iter, value;
	const char *name;
	int type;

	DBG("conn %p", conn);

	if (dbus_message_iter_init(msg, &iter) == FALSE)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &name);
	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &value);

	type = dbus_message_iter_get_arg_type(&value);

	if (g_str_equal(name, "Timeservers") == TRUE) {
		DBusMessageIter entry;
		GString *str;

		if (type != DBUS_TYPE_ARRAY)
			return __connman_error_invalid_arguments(msg);

		str = g_string_new(NULL);
		if (str == NULL)
			return __connman_error_invalid_arguments(msg);

		dbus_message_iter_recurse(&value, &entry);

		while (dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_STRING) {
			const char *val;

			dbus_message_iter_get_basic(&entry, &val);
			dbus_message_iter_next(&entry);

			if (str->len > 0)
				g_string_append_printf(str, " %s", val);
			else
				g_string_append(str, val);
		}

		g_strfreev(timeservers_config);

		if (str->len > 0)
			timeservers_config = g_strsplit_set(str->str, " ", 0);
		else
			timeservers_config = NULL;

		g_string_free(str, TRUE);

		connman_dbus_property_changed_array(CONNMAN_MANAGER_PATH,
				CONNMAN_CLOCK_INTERFACE, "Timeservers",
				DBUS_TYPE_STRING, append_timeservers, NULL);
	} else
		return __connman_error_invalid_property(msg);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static GDBusMethodTable clock_methods[] = {
	{ "GetProperties", "",   "a{sv}", get_properties },
	{ "SetProperty",   "sv", "",      set_property   },
	{ },
};

static GDBusSignalTable clock_signals[] = {
	{ "PropertyChanged", "sv" },
	{ },
};

static DBusConnection *connection = NULL;

int __connman_clock_init(void)
{
	DBG("");

	connection = connman_dbus_get_connection();
	if (connection == NULL)
		return -1;

	g_dbus_register_interface(connection, CONNMAN_MANAGER_PATH,
						CONNMAN_CLOCK_INTERFACE,
						clock_methods, clock_signals,
						NULL, NULL, NULL);

	return 0;
}

void __connman_clock_cleanup(void)
{
	DBG("");

	if (connection == NULL)
		return;

	g_dbus_unregister_interface(connection, CONNMAN_MANAGER_PATH,
						CONNMAN_CLOCK_INTERFACE);

	dbus_connection_unref(connection);

	g_strfreev(timeservers_config);
}
