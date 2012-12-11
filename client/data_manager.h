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

#include <dbus/dbus.h>

#define SIGNAL_LISTEN_TIMEOUT 10

struct signal_args {
	DBusConnection *connection;
	const char *signal_name;
};

struct proxy_input {
	char *servers;
	char *excludes;
};

DBusMessage *get_message(DBusConnection *connection, char *function);
int store_proxy_input(DBusConnection *connection, DBusMessage *message,
				char *name, int num_args, char *argv[]);
int list_properties(DBusConnection *connection, char *function,
			char *service_name);
int connect_service(DBusConnection *connection, char *name);
int disconnect_service(DBusConnection *connection, char *name);
int set_manager(DBusConnection *connection, char *key, dbus_bool_t value);
void listen_for_manager_signal(void *args);
