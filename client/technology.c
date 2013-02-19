/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <glib.h>

#include "technology.h"
#include "dbus.h"

void extract_properties(DBusMessageIter *dict)
{
	while (dbus_message_iter_get_arg_type(dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key, *sdata;
		dbus_bool_t bdata;

		dbus_message_iter_recurse(dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);
		printf("  [%s] = ", key);

		dbus_message_iter_next(&entry);

		dbus_message_iter_recurse(&entry, &value);

		if (dbus_message_iter_get_arg_type(&value) ==
							DBUS_TYPE_BOOLEAN) {
			dbus_message_iter_get_basic(&value, &bdata);
			printf("%s\n", bdata ? "True" : "False");
		} else if (dbus_message_iter_get_arg_type(&value) ==
							DBUS_TYPE_STRING) {
			dbus_message_iter_get_basic(&value, &sdata);
			printf("%s\n", sdata);
		}
		dbus_message_iter_next(dict);
	}
}

void match_tech_name(DBusMessage *message, char *tech_name,
						struct tech_data *tech)
{
	DBusMessageIter iter, array;

	dbus_message_iter_init(message, &iter);
	dbus_message_iter_recurse(&iter, &array);
	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_STRUCT) {
		DBusMessageIter entry;
		const char *path;
		const char *name;

		dbus_message_iter_recurse(&array, &entry);
		dbus_message_iter_get_basic(&entry, &path);
		tech->path = g_strdup(path);
		name = strrchr(path, '/') + 1;
		tech->name = g_strdup(name);
		if (g_strcmp0(tech_name, tech->name) == 0) {
			break;
		} else
			dbus_message_iter_next(&array);
	}

}

void extract_tech(DBusMessage *message)
{
	DBusMessageIter iter, array;

	dbus_message_iter_init(message, &iter);
	dbus_message_iter_recurse(&iter, &array);
	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_STRUCT) {
		DBusMessageIter entry, dict;

		const char *path;

		dbus_message_iter_recurse(&array, &entry);
		dbus_message_iter_get_basic(&entry, &path);

		printf("{ %s }\n", path);

		dbus_message_iter_next(&entry);

		dbus_message_iter_recurse(&entry, &dict);
		extract_properties(&dict);

		dbus_message_iter_next(&array);
	}
}

int scan_technology(DBusConnection *connection, DBusMessage *message,
								char *tech)
{
	DBusMessage *message_send;
	struct tech_data technology;
	DBusError err;

	match_tech_name(message, tech, &technology);
	if (g_strcmp0(tech, technology.name) != 0) {
		return -ENXIO;
	}

	message_send = dbus_message_new_method_call("net.connman",
						technology.path,
						"net.connman.Technology",
						"Scan");
	if (message_send == NULL)
		return -ENOMEM;

	dbus_error_init(&err);
	dbus_connection_send_with_reply_and_block(connection, message_send, -1,
									&err);

	if (dbus_error_is_set(&err)) {
		printf("Error '%s' %s\n", technology.path, err.message);
		dbus_error_free(&err);
		return -ENXIO;
	}

	dbus_message_unref(message_send);
	g_free(technology.name);
	g_free(technology.path);

	return 0;
}

int set_technology(DBusConnection *connection, DBusMessage *message, char *key,
						char *tech, dbus_bool_t value)
{
	DBusMessage *message_send;
	DBusMessageIter iter;
	struct tech_data technology;
	DBusError err;

	match_tech_name(message, tech, &technology);
	if (g_strcmp0(tech, technology.name) != 0) {
		return -ENXIO;
	}

	message_send = dbus_message_new_method_call("net.connman",
							technology.path,
							"net.connman.Technology",
							"SetProperty");
	if (message_send == NULL)
		return -ENOMEM;

	dbus_message_iter_init_append(message_send, &iter);
	dbus_property_append_basic(&iter, (const char *) key,
						DBUS_TYPE_BOOLEAN, &value);

	dbus_error_init(&err);
	dbus_connection_send_with_reply_and_block(connection, message_send,
			-1, &err);
	if (dbus_error_is_set(&err) == TRUE) {
		printf("Error '%s' %s\n", technology.path, err.message);
		dbus_error_free(&err);
	}

	g_free(technology.name);
	g_free(technology.path);

	return 0;
}
