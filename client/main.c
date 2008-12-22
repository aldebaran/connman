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

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <dbus/dbus.h>

#define CONNMAN_SERVICE			"org.moblin.connman"

#define CONNMAN_MANAGER_INTERFACE	CONNMAN_SERVICE ".Manager"
#define CONNMAN_MANAGER_PATH		"/"

static const char *extract_state(DBusMessage *message)
{
	DBusMessageIter array, dict;

	dbus_message_iter_init(message, &array);
	dbus_message_iter_recurse(&array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);

		dbus_message_iter_recurse(&entry, &value);

		//type = dbus_message_iter_get_arg_type(&value);
		//dbus_message_iter_get_basic(&value, &val);

		if (strcmp(key, "State") == 0) {
			const char *val;
			dbus_message_iter_get_basic(&value, &val);
			return val;
		}

		dbus_message_iter_next(&dict);
	}

	return NULL;
}

static int cmd_status(DBusConnection *connection)
{
	DBusMessage *message, *reply;
	DBusError error;
	const char *state;

	message = dbus_message_new_method_call(CONNMAN_SERVICE,
						CONNMAN_MANAGER_PATH,
						CONNMAN_MANAGER_INTERFACE,
							"GetProperties");
	if (message == NULL)
		return -ENOMEM;

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(connection,
							message, -1, &error);
	if (reply == NULL) {
		if (dbus_error_is_set(&error) == TRUE) {
			fprintf(stderr, "%s\n", error.message);
			dbus_error_free(&error);
		} else
			fprintf(stderr, "Failed to get properties\n");
		dbus_message_unref(message);
		return -EIO;
	}

	dbus_message_unref(message);

	dbus_error_init(&error);

	state = extract_state(reply);

	dbus_message_unref(reply);

	if (state == NULL)
		return -EINVAL;

	printf("System is %s\n", state);

	return 0;
}

int main(int argc, char *argv[])
{
	DBusConnection *conn;

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (!conn) {
		fprintf(stderr, "Can't get on system bus\n");
		exit(1);
	}

	cmd_status(conn);

	dbus_connection_unref(conn);

	return 0;
}
