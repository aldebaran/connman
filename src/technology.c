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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <gdbus.h>

#include "connman.h"

static DBusConnection *connection;

static GHashTable *device_table;
static GSList *technology_list = NULL;

enum connman_technology_state {
	CONNMAN_TECHNOLOGY_STATE_UNKNOWN   = 0,
	CONNMAN_TECHNOLOGY_STATE_OFFLINE   = 1,
	CONNMAN_TECHNOLOGY_STATE_AVAILABLE = 2,
	CONNMAN_TECHNOLOGY_STATE_ENABLED   = 3,
	CONNMAN_TECHNOLOGY_STATE_CONNECTED = 4,
};

struct connman_technology {
	gint refcount;
	enum connman_service_type type;
	enum connman_technology_state state;
	char *path;
	GSList *device_list;
};

void __connman_technology_list(DBusMessageIter *iter, void *user_data)
{
	GSList *list;

	for (list = technology_list; list; list = list->next) {
		struct connman_technology *technology = list->data;

		if (technology->path == NULL)
			continue;

		dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH,
							&technology->path);
	}
}

static void technologies_changed(void)
{
	connman_dbus_property_changed_array(CONNMAN_MANAGER_PATH,
			CONNMAN_MANAGER_INTERFACE, "Technologies",
			DBUS_TYPE_OBJECT_PATH, __connman_technology_list, NULL);
}

static void device_list(DBusMessageIter *iter, void *user_data)
{
	struct connman_technology *technology = user_data;
	GSList *list;

	for (list = technology->device_list; list; list = list->next) {
		struct connman_device *device = list->data;
		const char *path;

		path = connman_device_get_path(device);
		if (path == NULL)
			continue;

		dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH,
									&path);
	}
}

static void devices_changed(struct connman_technology *technology)
{
	connman_dbus_property_changed_array(technology->path,
			CONNMAN_TECHNOLOGY_INTERFACE, "Devices",
			DBUS_TYPE_OBJECT_PATH, device_list, technology);
}

static const char *state2string(enum connman_technology_state state)
{
	switch (state) {
	case CONNMAN_TECHNOLOGY_STATE_UNKNOWN:
		break;
	case CONNMAN_TECHNOLOGY_STATE_OFFLINE:
		return "offline";
	case CONNMAN_TECHNOLOGY_STATE_AVAILABLE:
		return "available";
	case CONNMAN_TECHNOLOGY_STATE_ENABLED:
		return "enabled";
	case CONNMAN_TECHNOLOGY_STATE_CONNECTED:
		return "connected";
	}

	return NULL;
}

static void state_changed(struct connman_technology *technology)
{
	const char *str;

	str = state2string(technology->state);
	if (str == NULL)
		return;

	connman_dbus_property_changed_basic(technology->path,
				CONNMAN_TECHNOLOGY_INTERFACE, "State",
						DBUS_TYPE_STRING, &str);
}

static const char *get_name(enum connman_service_type type)
{
	switch (type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_VPN:
		break;
	case CONNMAN_SERVICE_TYPE_ETHERNET:
		return "Wired";
	case CONNMAN_SERVICE_TYPE_WIFI:
		return "WiFi";
	case CONNMAN_SERVICE_TYPE_WIMAX:
		return "WiMAX";
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
		return "Bluetooth";
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		return "3G";
	}

	return NULL;
}

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *message, void *user_data)
{
	struct connman_technology *technology = user_data;
	DBusMessage *reply;
	DBusMessageIter array, dict;
	const char *str;

	reply = dbus_message_new_method_return(message);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &array);

	connman_dbus_dict_open(&array, &dict);

	str = state2string(technology->state);
	if (str != NULL)
		connman_dbus_dict_append_basic(&dict, "State",
						DBUS_TYPE_STRING, &str);

	str = get_name(technology->type);
	if (str != NULL)
		connman_dbus_dict_append_basic(&dict, "Name",
						DBUS_TYPE_STRING, &str);

	str = __connman_service_type2string(technology->type);
	if (str != NULL)
		connman_dbus_dict_append_basic(&dict, "Type",
						DBUS_TYPE_STRING, &str);

	connman_dbus_dict_append_array(&dict, "Devices",
			DBUS_TYPE_OBJECT_PATH, device_list, technology);

	connman_dbus_dict_close(&array, &dict);

	return reply;
}

static GDBusMethodTable technology_methods[] = {
	{ "GetProperties", "", "a{sv}", get_properties },
	{ },
};

static GDBusSignalTable technology_signals[] = {
	{ "PropertyChanged", "sv" },
	{ },
};

static struct connman_technology *technology_find(enum connman_service_type type)
{
	GSList *list;

	DBG("type %d", type);

	for (list = technology_list; list; list = list->next) {
		struct connman_technology *technology = list->data;

		if (technology->type == type)
			return technology;
	}

	return NULL;
}

static struct connman_technology *technology_get(enum connman_service_type type)
{
	struct connman_technology *technology;
	const char *str;

	DBG("type %d", type);

	technology = technology_find(type);
	if (technology != NULL) {
		g_atomic_int_inc(&technology->refcount);
		goto done;
	}

	str = __connman_service_type2string(type);
	if (str == NULL)
		return NULL;

	technology = g_try_new0(struct connman_technology, 1);
	if (technology == NULL)
		return NULL;

	technology->refcount = 1;

	technology->type = type;
	technology->path = g_strdup_printf("%s/technology/%s",
							CONNMAN_PATH, str);

	if (g_dbus_register_interface(connection, technology->path,
					CONNMAN_TECHNOLOGY_INTERFACE,
					technology_methods, technology_signals,
					NULL, technology, NULL) == FALSE) {
		connman_error("Failed to register %s", technology->path);
		g_free(technology);
		return NULL;
	}

	technology_list = g_slist_append(technology_list, technology);

	technologies_changed();

done:
	DBG("technology %p", technology);

	return technology;
}

static void technology_put(struct connman_technology *technology)
{
	DBG("technology %p", technology);

	if (g_atomic_int_dec_and_test(&technology->refcount) == FALSE)
		return;

	technology_list = g_slist_remove(technology_list, technology);

	technologies_changed();

	g_dbus_unregister_interface(connection, technology->path,
						CONNMAN_TECHNOLOGY_INTERFACE);

	g_free(technology->path);
	g_free(technology);
}

static void unregister_device(gpointer data)
{
	struct connman_technology *technology = data;

	DBG("technology %p", technology);

	technology_put(technology);
}

int __connman_technology_add_device(struct connman_device *device)
{
	struct connman_technology *technology;
	enum connman_service_type type;

	DBG("device %p", device);

	type = __connman_device_get_service_type(device);

	technology = technology_get(type);
	if (technology == NULL)
		return -ENXIO;

	g_hash_table_insert(device_table, device, technology);

	if (technology->device_list == NULL) {
		technology->state = CONNMAN_TECHNOLOGY_STATE_AVAILABLE;
		state_changed(technology);
	}

	technology->device_list = g_slist_append(technology->device_list,
								device);
	devices_changed(technology);

	return 0;
}

int __connman_technology_remove_device(struct connman_device *device)
{
	struct connman_technology *technology;

	DBG("device %p", device);

	technology = g_hash_table_lookup(device_table, device);
	if (technology == NULL)
		return -ENXIO;

	technology->device_list = g_slist_remove(technology->device_list,
								device);
	devices_changed(technology);

	if (technology->device_list == NULL) {
		technology->state = CONNMAN_TECHNOLOGY_STATE_OFFLINE;
		state_changed(technology);
	}

	g_hash_table_remove(device_table, device);

	return 0;
}

int __connman_technology_init(void)
{
	DBG("");

	connection = connman_dbus_get_connection();

	device_table = g_hash_table_new_full(g_direct_hash, g_direct_equal,
						NULL, unregister_device);

	return 0;
}

void __connman_technology_cleanup(void)
{
	DBG("");

	g_hash_table_destroy(device_table);

	dbus_connection_unref(connection);
}
