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

extern DBusConnection *connection;

void show_interactive(DBusConnection *connection, GMainLoop *mainloop);
int commands(DBusConnection *connection, char *argv[], int argc);
int commands_no_options(DBusConnection *connection, char *argv[], int argc);
int commands_options(DBusConnection *connection, char *argv[], int argc);
int monitor_switch(int argc, char *argv[], int c, DBusConnection *conn);
int config_switch(int argc, char *argv[], int c, DBusConnection *conn);
int service_switch(int argc, char *argv[], int c, DBusConnection *conn,
						struct service_data *service);
