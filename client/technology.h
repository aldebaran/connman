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

struct tech_data {
	char *path;
	char *name;
	dbus_bool_t powered;
	dbus_bool_t connected;
};

void extract_properties(DBusMessageIter *dict);
void match_tech_name(DBusMessage *message, char *tech_name,
			struct tech_data *tech);
void extract_tech(DBusMessage *message);
int list_tech(DBusConnection *connection, char *function);
int set_technology(DBusConnection *connection, DBusMessage *message, char *key,
						char *tech, dbus_bool_t value);
int scan_technology(DBusConnection *connection, DBusMessage *message,
						char *tech);
