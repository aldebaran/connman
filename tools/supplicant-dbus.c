/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2009  Intel Corporation. All rights reserved.
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
#include <stdlib.h>
#include <string.h>
#include <dbus/dbus.h>

#include "supplicant-dbus.h"

#define TIMEOUT 5000

static DBusConnection *connection;

void supplicant_dbus_setup(DBusConnection *conn)
{
	connection = conn;
}

void supplicant_dbus_array_foreach(DBusMessageIter *iter,
				supplicant_dbus_array_function function,
							void *user_data)
{
	DBusMessageIter entry;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
		return;

	dbus_message_iter_recurse(iter, &entry);

	while (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_INVALID) {
		if (function != NULL)
			function(&entry, user_data);

		dbus_message_iter_next(&entry);
	}
}

void supplicant_dbus_property_foreach(DBusMessageIter *iter,
				supplicant_dbus_property_function function,
							void *user_data)
{
	DBusMessageIter dict;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
		return;

	dbus_message_iter_recurse(iter, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;

		dbus_message_iter_recurse(&dict, &entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			return;

		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_VARIANT)
			return;

		dbus_message_iter_recurse(&entry, &value);

		if (key != NULL) {
			if (strcmp(key, "Properties") == 0)
				supplicant_dbus_property_foreach(&value,
							function, user_data);
			else if (function != NULL)
				function(key, &value, user_data);
		}

		dbus_message_iter_next(&dict);
	}
}

struct property_data {
	supplicant_dbus_property_function function;
	void *user_data;
};

static void property_get_all_reply(DBusPendingCall *call, void *user_data)
{
	struct property_data *data = user_data;
	DBusMessage *reply;
	DBusMessageIter iter;

	reply = dbus_pending_call_steal_reply(call);
	if (reply == NULL)
		return;

	if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR)
		goto done;

	if (dbus_message_iter_init(reply, &iter) == FALSE)
		goto done;

	supplicant_dbus_property_foreach(&iter, data->function,
							data->user_data);

	if (data->function != NULL)
		data->function(NULL, NULL, data->user_data);

done:
	dbus_message_unref(reply);
}

int supplicant_dbus_property_get_all(const char *path, const char *interface,
				supplicant_dbus_property_function function,
							void *user_data)
{
	struct property_data *data;
	DBusMessage *message;
	DBusPendingCall *call;

	if (path == NULL || interface == NULL)
		return -EINVAL;

	data = dbus_malloc0(sizeof(*data));
	if (data == NULL)
		return -ENOMEM;

	message = dbus_message_new_method_call(SUPPLICANT_SERVICE, path,
					DBUS_INTERFACE_PROPERTIES, "GetAll");
	if (message == NULL) {
		dbus_free(data);
		return -ENOMEM;
	}

	dbus_message_set_auto_start(message, FALSE);

	dbus_message_append_args(message, DBUS_TYPE_STRING, &interface, NULL);

	if (dbus_connection_send_with_reply(connection, message,
						&call, TIMEOUT) == FALSE) {
		dbus_message_unref(message);
		dbus_free(data);
		return -EIO;
	}

	if (call == NULL) {
		dbus_message_unref(message);
		dbus_free(data);
		return -EIO;
	}

	data->function = function;
	data->user_data = user_data;

	dbus_pending_call_set_notify(call, property_get_all_reply,
							data, dbus_free);

	dbus_message_unref(message);

	return 0;
}
