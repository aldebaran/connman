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

#ifndef __CONNMAN_DBUS_H
#define __CONNMAN_DBUS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <dbus/dbus.h>

#define CONNMAN_SERVICE  "org.moblin.connman"

#define CONNMAN_ERROR_INTERFACE    CONNMAN_SERVICE ".Error"

#define CONNMAN_AGENT_INTERFACE    CONNMAN_SERVICE ".Agent"

#define CONNMAN_ELEMENT_INTERFACE  CONNMAN_SERVICE ".Element"

#define CONNMAN_PROFILE_INTERFACE  CONNMAN_SERVICE ".Profile"

#define CONNMAN_MANAGER_INTERFACE  CONNMAN_SERVICE ".Manager"
#define CONNMAN_MANAGER_PATH       "/"

#define CONNMAN_IFACE_INTERFACE    CONNMAN_SERVICE ".Interface"
#define CONNMAN_IFACE_BASEPATH     "/interface"

#define CONNMAN_NETWORK_INTERFACE  CONNMAN_SERVICE ".Network"

extern void connman_dbus_dict_append_array(DBusMessageIter *dict,
				const char *key, int type, void *val, int len);
extern void connman_dbus_dict_append_variant(DBusMessageIter *dict,
					const char *key, int type, void *val);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_DBUS_H */
