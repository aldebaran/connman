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

#include <dbus/dbus.h>

#define SUPPLICANT_SERVICE	"fi.w1.wpa_supplicant1"
#define SUPPLICANT_INTERFACE	"fi.w1.wpa_supplicant1"
#define SUPPLICANT_PATH		"/fi/w1/wpa_supplicant1"

typedef void (* supplicant_dbus_array_function) (DBusMessageIter *iter,
							void *user_data);

typedef void (* supplicant_dbus_property_function) (const char *key,
				DBusMessageIter *iter, void *user_data);

void supplicant_dbus_setup(DBusConnection *conn);

void supplicant_dbus_array_foreach(DBusMessageIter *iter,
				supplicant_dbus_array_function function,
							void *user_data);

void supplicant_dbus_property_foreach(DBusMessageIter *iter,
				supplicant_dbus_property_function function,
							void *user_data);

int supplicant_dbus_property_get_all(const char *path, const char *interface,
				supplicant_dbus_property_function function,
							void *user_data);
