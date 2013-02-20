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
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <glib.h>
#include <gdbus.h>

#include "monitor.h"
#include "services.h"
#include "technology.h"
#include "data_manager.h"

static const char *get_service_name(DBusMessage *message, char *dbus_path)
{
	DBusMessageIter iter, array;

	dbus_message_iter_init(message, &iter);
	dbus_message_iter_recurse(&iter, &array);

	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_STRUCT) {
		DBusMessageIter entry, dict;
		struct service_data service;
		char *path;

		dbus_message_iter_recurse(&array, &entry);
		dbus_message_iter_get_basic(&entry, &path);

		if (g_strcmp0(path, dbus_path) == 0) {
			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &dict);
			extract_service_name(&dict, &service);
			return service.name;
		} else {
			dbus_message_iter_next(&array);
		}
	}
	return NULL;
}

static void extract_tech_signal(DBusMessage *message)
{
	DBusMessageIter iter, dict;
	char *path;

	dbus_message_iter_init(message, &iter);

	if (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_OBJECT_PATH) {
		dbus_message_iter_get_basic(&iter, &path);
		printf(" { %s }\n", path);
	}
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_INVALID) {
		dbus_message_iter_recurse(&iter, &dict);
		extract_properties(&dict);
	}
}

static void extract_signal_args(DBusMessage *message)
{
	DBusMessageIter iter, array, dict;
	char *string, *value;
	uint16_t key_int;
	dbus_bool_t bvalue;

	value = NULL;
	key_int = 0;

	dbus_message_iter_init(message, &iter);

	while (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_INVALID) {
		if (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_STRING) {
			dbus_message_iter_get_basic(&iter, &string);
			printf("\n[%s] = ",
			string);
		}
		dbus_message_iter_next(&iter);
		if (dbus_message_iter_get_arg_type(&iter) !=
							DBUS_TYPE_INVALID) {
			dbus_message_iter_recurse(&iter, &array);
			if (dbus_message_iter_get_arg_type(&array) ==
							DBUS_TYPE_STRING) {
				dbus_message_iter_get_basic(&array, &value);
				printf("%s\n", value);
				continue;
			} else if (dbus_message_iter_get_arg_type(&array) ==
							DBUS_TYPE_BOOLEAN) {
				dbus_message_iter_get_basic(&array, &bvalue);
				printf("%s\n", bvalue == TRUE ?
							"True" : "False");
				continue;
			} else if (dbus_message_iter_get_arg_type(&array) ==
							DBUS_TYPE_ARRAY)
				dbus_message_iter_recurse(&array, &dict);
			if (dbus_message_iter_get_arg_type(&dict) ==
						DBUS_TYPE_DICT_ENTRY) {
				iterate_dict(&dict, value, key_int);
				printf("\n");
			} else {
				iterate_array(&array);
				printf("\n");
			}
			dbus_message_iter_next(&iter);
		}
	}
}

int monitor_connman(DBusConnection *connection, char *interface,
				char *signal_name)
{
	char *rule = g_strdup_printf("type='signal',interface='net.connman.%s',"
					"member='%s'", interface, signal_name);
	DBusError err;

	dbus_error_init(&err);
	g_dbus_setup_bus(DBUS_BUS_SYSTEM, NULL, &err);
	if (dbus_error_is_set(&err)) {
		fprintf(stderr, "Bus setup error:%s\n", err.message);
		return -1;
	}
	dbus_bus_add_match(connection, rule, &err);

	if (dbus_error_is_set(&err)) {
		fprintf(stderr, "Match Error: %s\n", err.message);
		return -1;
	}
	return 0;
}

static void monitor_clear(DBusConnection *connection, char *interface)
{
	char *rule = g_strdup_printf("type='signal',interface='net.connman.%s'",
			interface);

	dbus_bus_remove_match(connection, rule, NULL);
}

static int monitor_add(DBusConnection *connection, char *interface)
{
	char *rule = g_strdup_printf("type='signal',interface='net.connman.%s'",
			interface);
	DBusError err;

	dbus_error_init(&err);
	g_dbus_setup_bus(DBUS_BUS_SYSTEM, NULL, &err);
	if (dbus_error_is_set(&err)) {
		fprintf(stderr, "Bus setup error:%s\n", err.message);
		return -1;
	}
	dbus_bus_add_match(connection, rule, &err);

	if (dbus_error_is_set(&err)) {
		fprintf(stderr, "Match Error: %s\n", err.message);
		return -1;
	}
	return 0;
}

int monitor_connman_service(DBusConnection *connection)
{
	int err;

	err = monitor_add(connection, "Service");
	if (err < 0)
		return err;

	if (dbus_connection_add_filter(connection,
					service_property_changed,
					NULL, NULL) == FALSE) {
		monitor_clear(connection, "Service");
		return -ENXIO;
	}

	return 0;
}

int monitor_connman_technology(DBusConnection *connection)
{
	int err;

	err = monitor_add(connection, "Technology");
	if (err < 0)
		return err;

	if (dbus_connection_add_filter(connection,
					tech_property_changed,
					NULL, NULL) == FALSE) {
		monitor_clear(connection, "Technology");
		return -ENXIO;
	}

	return 0;
}

int monitor_connman_manager(DBusConnection *connection)
{
	int err;

	err = monitor_add(connection, "Manager");
	if (err < 0)
		return err;

	if (dbus_connection_add_filter(connection, manager_property_changed,
					NULL, NULL) == FALSE) {
		monitor_clear(connection, "Manager");
		return -ENXIO;
	}

	if (dbus_connection_add_filter(connection, manager_services_changed,
					NULL, NULL) == FALSE) {
		dbus_connection_remove_filter(connection,
				manager_property_changed, NULL);
		monitor_clear(connection, "Manager");
		return -ENXIO;
	}

	return 0;
}

DBusHandlerResult service_property_changed(DBusConnection *connection,
						DBusMessage *message,
						void *user_data)
{
	DBusMessage *service_message;
	struct service_data service;

	if (dbus_message_is_signal(message, "net.connman.Service",
					    "PropertyChanged")) {
		service_message = get_message(connection, "GetServices");
		if (service_message == NULL)
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

		service.name = get_service_name(service_message,
				(char *) dbus_message_get_path(message));
		printf("\n");
		g_message("Path = %s, Interface = %s\nService = %s",
				dbus_message_get_path(message),
				dbus_message_get_interface(message),
				service.name);
		extract_signal_args(message);

		dbus_message_unref(service_message);
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

DBusHandlerResult tech_property_changed(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	if (dbus_message_is_signal(message, "net.connman.Technology",
					    "PropertyChanged")) {
		printf("\n");
		g_message("Path = %s, Interface = %s",
				dbus_message_get_path(message),
				dbus_message_get_interface(message));
		extract_signal_args(message);
	}
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

DBusHandlerResult tech_added_removed(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	if (dbus_message_is_signal(message, "net.connman.Manager",
					    "TechnologyAdded")) {
		printf("\n");
		g_message("Path = %s, Interface = %s",
				dbus_message_get_path(message),
				dbus_message_get_interface(message));
		printf("New technology added:\n");
		extract_tech_signal(message);
	} else if (dbus_message_is_signal(message, "net.connman.Manager",
						   "TechnologyRemoved")) {
		printf("\n");
		g_message("Path = %s, Interface = %s",
				dbus_message_get_path(message),
				dbus_message_get_interface(message));
		printf("Technology was removed:\n");
		extract_tech_signal(message);
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

DBusHandlerResult manager_services_changed(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	if (dbus_message_is_signal(message, "net.connman.Manager",
						"ServicesChanged")) {
		printf("\n");
		g_message("Path = %s, Interface = %s",
				dbus_message_get_path(message),
				dbus_message_get_interface(message));
		printf("Services Changed, displaying updated "
							"list of services:\n");
		list_properties(connection, "GetServices", NULL);
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

DBusHandlerResult manager_property_changed(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	if (dbus_message_is_signal(message, "net.connman.Manager",
					    "PropertyChanged")) {
		printf("\n");
		g_message("Path = %s, Interface = %s",
				dbus_message_get_path(message),
				dbus_message_get_interface(message));
		extract_signal_args(message);
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}
