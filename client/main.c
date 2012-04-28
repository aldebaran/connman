/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2012  Intel Corporation. All rights reserved.
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

#define CONNMAN_SERVICE			"net.connman"

#define CONNMAN_MANAGER_INTERFACE	CONNMAN_SERVICE ".Manager"
#define CONNMAN_MANAGER_PATH		"/"

struct service_data {
	const char *path;
	const char *name;
	dbus_bool_t favorite;
};

static DBusMessage *get_services(DBusConnection *connection)
{
	DBusMessage *message, *reply;
	DBusError error;

	message = dbus_message_new_method_call(CONNMAN_SERVICE,
						CONNMAN_MANAGER_PATH,
						CONNMAN_MANAGER_INTERFACE,
							"GetServices");
	if (message == NULL)
		return NULL;

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
		return NULL;
	}

	dbus_message_unref(message);

	return reply;
}

static DBusMessage *lookup_service(DBusConnection *connection,
							const char *pattern)
{
	DBusMessage *message, *reply;
	DBusError error;

	message = dbus_message_new_method_call(CONNMAN_SERVICE,
						CONNMAN_MANAGER_PATH,
						CONNMAN_MANAGER_INTERFACE,
							"LookupService");
	if (message == NULL)
		return NULL;

	dbus_message_append_args(message, DBUS_TYPE_STRING, &pattern,
							DBUS_TYPE_INVALID);

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
		return NULL;
	}

	dbus_message_unref(message);

	return reply;
}

static void extract_properties(DBusMessageIter *dict,
					struct service_data *service)
{
	while (dbus_message_iter_get_arg_type(dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;

		dbus_message_iter_recurse(dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);

		dbus_message_iter_recurse(&entry, &value);

		//type = dbus_message_iter_get_arg_type(&value);
		//dbus_message_iter_get_basic(&value, &val);

		if (strcmp(key, "Name") == 0)
			dbus_message_iter_get_basic(&value, &service->name);
		else if (strcmp(key, "Favorite") == 0)
			dbus_message_iter_get_basic(&value, &service->favorite);

		dbus_message_iter_next(dict);
	}
}

static void extract_services(DBusMessage *message)
{
	DBusMessageIter iter, array;

	dbus_message_iter_init(message, &iter);
	dbus_message_iter_recurse(&iter, &array);

	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_STRUCT) {
		DBusMessageIter entry, dict;
		struct service_data service;
		const char *path;

		dbus_message_iter_recurse(&array, &entry);
		dbus_message_iter_get_basic(&entry, &path);

		service.path = strrchr(path, '/') + 1;

		dbus_message_iter_next(&entry);

		dbus_message_iter_recurse(&entry, &dict);
		extract_properties(&dict, &service);

		printf("%c %-20s { %-50s }\n",
				service.favorite == TRUE ? '*' : ' ',
						service.name, service.path);

		dbus_message_iter_next(&array);
	}
}

static int cmd_list_services(DBusConnection *connection)
{
	DBusMessage *message;

	message = get_services(connection);
	if (message == NULL)
		return -1;

	extract_services(message);

	dbus_message_unref(message);

	return 0;
}

static int cmd_show_service(DBusConnection *connection, const char *pattern)
{
	DBusMessage *message;
	const char *path;

	message = lookup_service(connection, pattern);
	if (message == NULL)
		return -1;

	dbus_message_get_args(message, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID);

	printf("Service: %s\n", path);

	dbus_message_unref(message);

	return 0;
}

static void usage(const char *program)
{
	printf("ConnMan utility ver %s\n\n", VERSION);

	printf("Usage:\n"
		"\t%s <command> [options]\n\n", program);

	printf("Commands:\n"
		"\thelp\n"
		"\tlist\n"
		"\tshow <service>\n"
		"\n");
}

int main(int argc, char *argv[])
{
	DBusConnection *conn;

	if (argc > 1 && strcmp(argv[1], "help") == 0) {
		usage(argv[0]);
		exit(0);
	}

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (!conn) {
		fprintf(stderr, "Can't get on system bus\n");
		exit(1);
	}

	if (argc > 1) {
		if (strcmp(argv[1], "list") == 0)
			cmd_list_services(conn);
		else if (strcmp(argv[1], "show") == 0) {
			if (argc > 2)
				cmd_show_service(conn, argv[2]);
			else
				usage(argv[0]);
		}
	} else
		usage(argv[0]);

	dbus_connection_unref(conn);

	return 0;
}
