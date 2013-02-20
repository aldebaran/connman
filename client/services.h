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

#include <stdint.h>

#include <dbus/dbus.h>

struct service_data {
	const char *path;
	const char *name;
	dbus_bool_t autoconn;
	dbus_bool_t favorite;
	dbus_bool_t connected;
	dbus_bool_t online;
};

int parse_boolean(char *arg);
char *strip_service_path(char *service);
void extract_service_name(DBusMessageIter *dict, struct service_data *service);
int set_service_property(DBusConnection *connection, DBusMessage *message,
				char *name, char *property, char **keys,
				void *data, int num_args);
int remove_service(DBusConnection *connection, DBusMessage *message,
								char *name);
int set_proxy_manual(DBusConnection *connection, DBusMessage *message,
				char *name, char **servers, char **excludes,
				int num_servers, int num_excludes);

void extract_services(DBusMessage *message, char *service_name);
void get_services(DBusMessage *message);
void iterate_dict(DBusMessageIter *dict, char *string, uint16_t key_int);
int list_services(DBusConnection *connection, char *function);
int list_services_properties(DBusConnection *connection, char *function,
				char *service_name);
int listen_for_service_signal(DBusConnection *connection, char *signal_name,
			char *service_name);
void iterate_array(DBusMessageIter *iter);
