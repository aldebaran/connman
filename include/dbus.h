/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2010  Intel Corporation. All rights reserved.
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
#define CONNMAN_PATH			"/org/moblin/connman"

#define CONNMAN_DEBUG_INTERFACE		CONNMAN_SERVICE ".Debug"
#define CONNMAN_ERROR_INTERFACE		CONNMAN_SERVICE ".Error"
#define CONNMAN_AGENT_INTERFACE		CONNMAN_SERVICE ".Agent"
#define CONNMAN_COUNTER_INTERFACE	CONNMAN_SERVICE ".Counter"

#define CONNMAN_MANAGER_INTERFACE	CONNMAN_SERVICE ".Manager"
#define CONNMAN_MANAGER_PATH		"/"

#define CONNMAN_TASK_INTERFACE		CONNMAN_SERVICE ".Task"
#define CONNMAN_PROFILE_INTERFACE	CONNMAN_SERVICE ".Profile"
#define CONNMAN_SERVICE_INTERFACE	CONNMAN_SERVICE ".Service"
#define CONNMAN_DEVICE_INTERFACE	CONNMAN_SERVICE ".Device"
#define CONNMAN_NETWORK_INTERFACE	CONNMAN_SERVICE ".Network"
#define CONNMAN_PROVIDER_INTERFACE	CONNMAN_SERVICE ".Provider"
#define CONNMAN_TECHNOLOGY_INTERFACE	CONNMAN_SERVICE ".Technology"

typedef void (* connman_dbus_append_cb_t) (DBusMessageIter *iter,
							void *user_data);

DBusConnection *connman_dbus_get_connection(void);

void connman_dbus_property_append_basic(DBusMessageIter *iter,
					const char *key, int type, void *val);
void connman_dbus_property_append_dict(DBusMessageIter *iter, const char *key,
			connman_dbus_append_cb_t function, void *user_data);
void connman_dbus_property_append_array(DBusMessageIter *iter,
						const char *key, int type,
			connman_dbus_append_cb_t function, void *user_data);
void connman_dbus_property_append_fixed_array(DBusMessageIter *iter,
				const char *key, int type, void *val, int len);

dbus_bool_t connman_dbus_property_changed_basic(const char *path,
				const char *interface, const char *key,
							int type, void *val);
dbus_bool_t connman_dbus_property_changed_dict(const char *path,
				const char *interface, const char *key,
			connman_dbus_append_cb_t function, void *user_data);
dbus_bool_t connman_dbus_property_changed_array(const char *path,
			const char *interface, const char *key, int type,
			connman_dbus_append_cb_t function, void *user_data);

static inline void connman_dbus_dict_open(DBusMessageIter *iter,
							DBusMessageIter *dict)
{
	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, dict);
}

static inline void connman_dbus_dict_close(DBusMessageIter *iter,
							DBusMessageIter *dict)
{
	dbus_message_iter_close_container(iter, dict);
}

static inline void connman_dbus_dict_append_basic(DBusMessageIter *dict,
					const char *key, int type, void *val)
{
	DBusMessageIter entry;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
								NULL, &entry);
	connman_dbus_property_append_basic(&entry, key, type, val);
	dbus_message_iter_close_container(dict, &entry);
}

static inline void connman_dbus_dict_append_dict(DBusMessageIter *dict,
			const char *key, connman_dbus_append_cb_t function,
							void *user_data)
{
	DBusMessageIter entry;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
								NULL, &entry);
	connman_dbus_property_append_dict(&entry, key, function, user_data);
	dbus_message_iter_close_container(dict, &entry);
}

static inline void connman_dbus_dict_append_array(DBusMessageIter *dict,
		const char *key, int type, connman_dbus_append_cb_t function,
							void *user_data)
{
	DBusMessageIter entry;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
								NULL, &entry);
	connman_dbus_property_append_array(&entry, key,
						type, function, user_data);
	dbus_message_iter_close_container(dict, &entry);
}

static inline void connman_dbus_dict_append_fixed_array(DBusMessageIter *dict,
				const char *key, int type, void *val, int len)
{
	DBusMessageIter entry;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
								NULL, &entry);
	connman_dbus_property_append_fixed_array(&entry, key, type, val, len);
	dbus_message_iter_close_container(dict, &entry);
}

dbus_bool_t connman_dbus_validate_ident(const char *ident);
char *connman_dbus_encode_string(const char *value);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_DBUS_H */
