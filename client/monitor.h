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

int monitor_connman(DBusConnection *connection, char *interface,
				char *signal_name);
int monitor_connman_service(DBusConnection *connection);
int monitor_connman_technology(DBusConnection *connection);
int monitor_connman_manager(DBusConnection *connection);

DBusHandlerResult service_property_changed(DBusConnection *connection,
				DBusMessage *message, void *user_data);

DBusHandlerResult tech_property_changed(DBusConnection *connection,
				DBusMessage *message, void *user_data);

DBusHandlerResult tech_added_removed(DBusConnection *connection,
				DBusMessage *message, void *user_data);

DBusHandlerResult manager_property_changed(DBusConnection *connection,
				DBusMessage *message, void *user_data);

DBusHandlerResult manager_services_changed(DBusConnection *connection,
				DBusMessage *message, void *user_data);
