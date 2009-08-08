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

#ifndef __CONNMAN_DBUS_H
#define __CONNMAN_DBUS_H

#include <dbus/dbus.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CONNMAN_SERVICE			"org.moblin.connman"

#define CONNMAN_DEBUG_INTERFACE		CONNMAN_SERVICE ".Debug"
#define CONNMAN_ERROR_INTERFACE		CONNMAN_SERVICE ".Error"
#define CONNMAN_AGENT_INTERFACE		CONNMAN_SERVICE ".Agent"

#define CONNMAN_MANAGER_INTERFACE	CONNMAN_SERVICE ".Manager"
#define CONNMAN_MANAGER_PATH		"/"

#define CONNMAN_TASK_INTERFACE		CONNMAN_SERVICE ".Task"
#define CONNMAN_PROFILE_INTERFACE	CONNMAN_SERVICE ".Profile"
#define CONNMAN_SERVICE_INTERFACE	CONNMAN_SERVICE ".Service"
#define CONNMAN_DEVICE_INTERFACE	CONNMAN_SERVICE ".Device"
#define CONNMAN_NETWORK_INTERFACE	CONNMAN_SERVICE ".Network"
#define CONNMAN_CONNECTION_INTERFACE	CONNMAN_SERVICE ".Connection"

DBusConnection *connman_dbus_get_connection(void);

void connman_dbus_property_append_variant(DBusMessageIter *property,
					const char *key, int type, void *val);

void connman_dbus_dict_append_array(DBusMessageIter *dict,
				const char *key, int type, void *val, int len);
void connman_dbus_dict_append_variant(DBusMessageIter *dict,
					const char *key, int type, void *val);

char *connman_dbus_encode_string(const char *value);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_DBUS_H */
