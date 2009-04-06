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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib.h>
#include <gdbus.h>

#include "connman.h"

#define PROFILE_DEFAULT  "/profile/default"

enum connman_service_type {
	CONNMAN_SERVICE_TYPE_UNKNOWN  = 0,
	CONNMAN_SERVICE_TYPE_ETHERNET = 1,
	CONNMAN_SERVICE_TYPE_WIFI     = 2,
	CONNMAN_SERVICE_TYPE_WIMAX    = 3,
};

enum connman_service_state {
	CONNMAN_SERVICE_STATE_UNKNOWN = 0,
	CONNMAN_SERVICE_STATE_IDLE    = 1,
};

struct connman_group {
	GSequenceIter *iter;
	char *id;
	char *path;
	char *name;
	char *mode;
	char *security;
	connman_uint8_t strength;
	connman_bool_t favorite;
	enum connman_service_type type;
	enum connman_service_state state;
	struct connman_network *network;
};

static GSequence *groups = NULL;

static DBusConnection *connection = NULL;

static const char *type2string(enum connman_service_type type)
{
	switch (type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
		break;
	case CONNMAN_SERVICE_TYPE_ETHERNET:
		return "ethernet";
	case CONNMAN_SERVICE_TYPE_WIFI:
		return "wifi";
	case CONNMAN_SERVICE_TYPE_WIMAX:
		return "wimax";
	}

	return NULL;
}

static const char *state2string(enum connman_service_state state)
{
	switch (state) {
	case CONNMAN_SERVICE_STATE_UNKNOWN:
		break;
	case CONNMAN_SERVICE_STATE_IDLE:
		return "idle";
	}

	return NULL;
}

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_group *group = data;
	DBusMessage *reply;
	DBusMessageIter array, dict;
	const char *str;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &array);

	dbus_message_iter_open_container(&array, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	str = type2string(group->type);
	if (str != NULL)
		connman_dbus_dict_append_variant(&dict, "Type",
						DBUS_TYPE_STRING, &str);

	str = state2string(group->state);
	if (str != NULL)
		connman_dbus_dict_append_variant(&dict, "State",
						DBUS_TYPE_STRING, &str);

	if (group->name != NULL)
		connman_dbus_dict_append_variant(&dict, "Name",
					DBUS_TYPE_STRING, &group->name);

	if (group->mode != NULL)
		connman_dbus_dict_append_variant(&dict, "Mode",
					DBUS_TYPE_STRING, &group->mode);

	if (group->security != NULL)
		connman_dbus_dict_append_variant(&dict, "Security",
					DBUS_TYPE_STRING, &group->security);

	if (group->strength > 0)
		connman_dbus_dict_append_variant(&dict, "Strength",
					DBUS_TYPE_BYTE, &group->strength);

	connman_dbus_dict_append_variant(&dict, "Favorite",
					DBUS_TYPE_BOOLEAN, &group->favorite);

	dbus_message_iter_close_container(&array, &dict);

	return reply;
}

static DBusMessage *connect_service(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_group *group = data;

	if (group->type == CONNMAN_SERVICE_TYPE_ETHERNET)
		return __connman_error_not_supported(msg);

	return __connman_error_not_implemented(msg);
}

static DBusMessage *disconnect_service(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_group *group = data;

	if (group->type == CONNMAN_SERVICE_TYPE_ETHERNET)
		return __connman_error_not_supported(msg);

	return __connman_error_not_implemented(msg);
}

static DBusMessage *remove_service(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_group *group = data;

	if (group->type == CONNMAN_SERVICE_TYPE_ETHERNET)
		return __connman_error_not_supported(msg);

	group->favorite = FALSE;

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *move_before(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_group *group = data;

	if (group->favorite == FALSE)
		return __connman_error_not_supported(msg);

	return __connman_error_not_implemented(msg);
}

static DBusMessage *move_after(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_group *group = data;

	if (group->favorite == FALSE)
		return __connman_error_not_supported(msg);

	return __connman_error_not_implemented(msg);
}

static GDBusMethodTable service_methods[] = {
	{ "GetProperties", "",  "a{sv}", get_properties     },
	{ "Connect",       "",  "",      connect_service    },
	{ "Disconnect",    "",  "",      disconnect_service },
	{ "Remove",        "",  "",      remove_service     },
	{ "MoveBefore",    "o", "",      move_before        },
	{ "MoveAfter",     "o", "",      move_after         },
	{ },
};

static GDBusSignalTable service_signals[] = {
	{ "PropertyChanged", "sv" },
	{ },
};

const char *__connman_profile_active(void)
{
	DBG("");

	return PROFILE_DEFAULT;
}

static void append_path(gpointer value, gpointer user_data)
{
	struct connman_group *group = value;
	DBusMessageIter *iter = user_data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH,
							&group->path);
}

void __connman_profile_list_services(DBusMessageIter *iter)
{
	DBG("");

	g_sequence_foreach(groups, append_path, iter);
}

static void append_services(DBusMessageIter *entry)
{
	DBusMessageIter value, iter;
	const char *key = "Services";

	dbus_message_iter_append_basic(entry, DBUS_TYPE_STRING, &key);

	dbus_message_iter_open_container(entry, DBUS_TYPE_VARIANT,
		DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_OBJECT_PATH_AS_STRING,
								&value);

	dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY,
				DBUS_TYPE_OBJECT_PATH_AS_STRING, &iter);
	__connman_profile_list_services(&iter);
	dbus_message_iter_close_container(&value, &iter);

	dbus_message_iter_close_container(entry, &value);
}

static void emit_services_signal(void)
{
	const char *path = __connman_profile_active();
	DBusMessage *signal;
	DBusMessageIter entry;

	signal = dbus_message_new_signal(path,
				CONNMAN_PROFILE_INTERFACE, "PropertyChanged");
	if (signal == NULL)
		return;

	dbus_message_iter_init_append(signal, &entry);
	append_services(&entry);
	g_dbus_send_message(connection, signal);

	signal = dbus_message_new_signal(CONNMAN_MANAGER_PATH,
				CONNMAN_MANAGER_INTERFACE, "PropertyChanged");
	if (signal == NULL)
		return;

	dbus_message_iter_init_append(signal, &entry);
	append_services(&entry);
	g_dbus_send_message(connection, signal);
}

static void free_group(gpointer data)
{
	struct connman_group *group = data;

	DBG("group %p", group);

	g_dbus_unregister_interface(connection, group->path,
						CONNMAN_SERVICE_INTERFACE);

	g_free(group->security);
	g_free(group->mode);
	g_free(group->name);
	g_free(group->path);
	g_free(group->id);
	g_free(group);
}

static gint compare_group(gconstpointer a, gconstpointer b, gpointer user_data)
{
	struct connman_group *group_a = (void *) a;
	struct connman_group *group_b = (void *) b;

	if (group_a->favorite == TRUE && group_b->favorite == FALSE)
		return -1;

	if (group_a->favorite == FALSE && group_b->favorite == TRUE)
		return 1;

	return (gint) group_b->strength - (gint) group_a->strength;
}

static struct connman_group *lookup_group(const char *name)
{
	GSequenceIter *iter;
	struct connman_group *group;

	DBG("name %s", name);

	if (name == NULL)
		return NULL;

	iter = g_sequence_get_begin_iter(groups);
	while (g_sequence_iter_is_end(iter) == FALSE) {
		group = g_sequence_get(iter);

		if (g_strcmp0(group->id, name) == 0)
			goto done;
	}

	group = g_try_new0(struct connman_group, 1);
	if (group == NULL)
		return NULL;

	group->id = g_strdup(name);

	group->type = CONNMAN_SERVICE_TYPE_UNKNOWN;
	group->path = g_strdup_printf("%s/%s", PROFILE_DEFAULT, name);

	group->favorite = FALSE;

	group->state = CONNMAN_SERVICE_STATE_IDLE;

	group->iter = g_sequence_insert_sorted(groups, group,
						compare_group, NULL);

	g_dbus_register_interface(connection, group->path,
					CONNMAN_SERVICE_INTERFACE,
					service_methods, service_signals,
							NULL, group, NULL);

done:
	DBG("group %p", group);

	return group;
}

static enum connman_service_type convert_device_type(struct connman_device *device)
{
	enum connman_device_type type = connman_device_get_type(device);

	switch (type) {
	case CONNMAN_DEVICE_TYPE_UNKNOWN:
	case CONNMAN_DEVICE_TYPE_VENDOR:
	case CONNMAN_DEVICE_TYPE_WIFI:
	case CONNMAN_DEVICE_TYPE_WIMAX:
	case CONNMAN_DEVICE_TYPE_BLUETOOTH:
	case CONNMAN_DEVICE_TYPE_GPS:
	case CONNMAN_DEVICE_TYPE_HSO:
	case CONNMAN_DEVICE_TYPE_NOZOMI:
	case CONNMAN_DEVICE_TYPE_HUAWEI:
	case CONNMAN_DEVICE_TYPE_NOVATEL:
		break;
	case CONNMAN_DEVICE_TYPE_ETHERNET:
		return CONNMAN_SERVICE_TYPE_ETHERNET;
	}

	return CONNMAN_SERVICE_TYPE_UNKNOWN;
}

int __connman_profile_add_device(struct connman_device *device)
{
	struct connman_group *group;
	char *name;

	DBG("device %p", device);

	name = g_strdup_printf("%s_%d", __connman_device_get_type(device),
					connman_device_get_index(device));
	group = lookup_group(name);
	g_free(name);

	if (group == NULL)
		return -EINVAL;

	group->type = convert_device_type(device);

	g_sequence_sort_changed(group->iter, compare_group, NULL);
	emit_services_signal();

	return 0;
}

int __connman_profile_remove_device(struct connman_device *device)
{
	struct connman_group *group;
	char *name;

	DBG("device %p", device);

	name = g_strdup_printf("%s_%d", __connman_device_get_type(device),
					connman_device_get_index(device));
	group = lookup_group(name);
	g_free(name);

	if (group == NULL)
		return -EINVAL;

	group->type = CONNMAN_SERVICE_TYPE_UNKNOWN;

	g_sequence_sort_changed(group->iter, compare_group, NULL);
	emit_services_signal();

	return 0;
}

int __connman_profile_set_carrier(struct connman_device *device,
						connman_bool_t carrier)
{
	struct connman_group *group;
	char *name;

	DBG("device %p carrier %d", device, carrier);

	name = g_strdup_printf("%s_%d", __connman_device_get_type(device),
					connman_device_get_index(device));
	group = lookup_group(name);
	g_free(name);

	if (group == NULL)
		return -EINVAL;

	if (group->favorite == carrier)
		return -EALREADY;

	group->favorite = carrier;

	g_sequence_sort_changed(group->iter, compare_group, NULL);
	emit_services_signal();

	return 0;
}

static enum connman_service_type convert_network_type(struct connman_network *network)
{
	enum connman_network_type type = connman_network_get_type(network);

	switch (type) {
	case CONNMAN_NETWORK_TYPE_UNKNOWN:
	case CONNMAN_NETWORK_TYPE_VENDOR:
	case CONNMAN_NETWORK_TYPE_BLUETOOTH_PAN:
	case CONNMAN_NETWORK_TYPE_BLUETOOTH_DUN:
	case CONNMAN_NETWORK_TYPE_HSO:
		break;
	case CONNMAN_NETWORK_TYPE_WIFI:
		return CONNMAN_SERVICE_TYPE_WIFI;
	case CONNMAN_NETWORK_TYPE_WIMAX:
		return CONNMAN_SERVICE_TYPE_WIMAX;
	}

	return CONNMAN_SERVICE_TYPE_UNKNOWN;
}

int __connman_profile_add_network(struct connman_network *network)
{
	struct connman_group *group;
	char *name;

	DBG("network %p", network);

	if (__connman_network_get_group(network) == NULL)
		return -EINVAL;

	name = g_strdup_printf("%s_%s", __connman_network_get_type(network),
					__connman_network_get_group(network));
	group = lookup_group(name);
	g_free(name);

	if (group == NULL)
		return -EINVAL;

	group->type = convert_network_type(network);

	g_free(group->name);
	group->name = g_strdup(connman_network_get_string(network, "Name"));

	group->strength = connman_network_get_uint8(network, "Strength");

	if (group->network == NULL) {
		group->network = network;

		group->mode = g_strdup(connman_network_get_string(network,
								"WiFi.Mode"));
		group->security = g_strdup(connman_network_get_string(network,
							"WiFi.Security"));
	}

	g_sequence_sort_changed(group->iter, compare_group, NULL);
	emit_services_signal();

	return 0;
}

int __connman_profile_remove_network(struct connman_network *network)
{
	struct connman_group *group;
	char *name;

	DBG("network %p", network);

	if (__connman_network_get_group(network) == NULL)
		return -EINVAL;

	name = g_strdup_printf("%s_%s", __connman_network_get_type(network),
					__connman_network_get_group(network));
	group = lookup_group(name);
	g_free(name);

	if (group == NULL)
		return -EINVAL;

	if (group->network == network) {
		g_free(group->security);
		group->security = NULL;

		g_free(group->mode);
		group->mode = NULL;

		group->network = NULL;
	}

	group->type = CONNMAN_SERVICE_TYPE_UNKNOWN;

	g_sequence_sort_changed(group->iter, compare_group, NULL);
	emit_services_signal();

	return 0;
}

void __connman_profile_list(DBusMessageIter *iter)
{
	const char *path = __connman_profile_active();

	DBG("");

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &path);
}

static DBusMessage *profile_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *name = "Default";
	DBusMessage *reply;
	DBusMessageIter array, dict, entry;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &array);

	dbus_message_iter_open_container(&array, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	connman_dbus_dict_append_variant(&dict, "Name",
						DBUS_TYPE_STRING, &name);

	dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY,
								NULL, &entry);
	append_services(&entry);
	dbus_message_iter_close_container(&dict, &entry);

	dbus_message_iter_close_container(&array, &dict);

	return reply;
}

static GDBusMethodTable profile_methods[] = {
	{ "GetProperties", "", "a{sv}", profile_properties },
	{ },
};

static GDBusSignalTable profile_signals[] = {
	{ "PropertyChanged", "sv" },
	{ },
};

int __connman_profile_init(DBusConnection *conn)
{
	DBG("conn %p", conn);

	connection = dbus_connection_ref(conn);
	if (connection == NULL)
		return -1;

	groups = g_sequence_new(free_group);

	g_dbus_register_interface(connection, PROFILE_DEFAULT,
					CONNMAN_PROFILE_INTERFACE,
					profile_methods, profile_signals,
							NULL, NULL, NULL);

	return 0;
}

void __connman_profile_cleanup(void)
{
	DBG("conn %p", connection);

	g_dbus_unregister_interface(connection, PROFILE_DEFAULT,
						CONNMAN_PROFILE_INTERFACE);

	g_sequence_free(groups);
	groups = NULL;

	if (connection == NULL)
		return;

	dbus_connection_unref(connection);
}
