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

struct connman_group {
	char *path;
	char *type;
	char *name;
	char *mode;
	char *security;
	connman_uint8_t strength;
	connman_bool_t favorite;
	struct connman_network *network;
};

static GHashTable *groups = NULL;

static DBusConnection *connection = NULL;

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_group *group = data;
	DBusMessage *reply;
	DBusMessageIter array, dict;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &array);

	dbus_message_iter_open_container(&array, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	if (group->type != NULL)
		connman_dbus_dict_append_variant(&dict, "Type",
					DBUS_TYPE_STRING, &group->type);

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

static GDBusMethodTable service_methods[] = {
	{ "GetProperties", "", "a{sv}", get_properties },
	{ },
};

static void free_group(gpointer data)
{
	struct connman_group *group = data;

	DBG("group %p", group);

	g_dbus_unregister_interface(connection, group->path,
						CONNMAN_SERVICE_INTERFACE);

	g_free(group->security);
	g_free(group->mode);
	g_free(group->name);
	g_free(group->type);
	g_free(group->path);
	g_free(group);
}

static struct connman_group *lookup_group(const char *name)
{
	struct connman_group *group;

	DBG("name %s", name);

	if (name == NULL)
		return NULL;

	group = g_hash_table_lookup(groups, name);
	if (group != NULL)
		goto done;

	group = g_try_new0(struct connman_group, 1);
	if (group == NULL)
		return NULL;

	group->type = CONNMAN_ELEMENT_TYPE_UNKNOWN;
	group->path = g_strdup_printf("%s/%s", PROFILE_DEFAULT, name);

	group->favorite = FALSE;

	g_hash_table_insert(groups, g_strdup(name), group);

	g_dbus_register_interface(connection, group->path,
						CONNMAN_SERVICE_INTERFACE,
						service_methods,
						NULL, NULL, group, NULL);

done:
	DBG("group %p", group);

	return group;
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

	group->type = g_strdup(__connman_device_get_type(device));
	group->name = g_strdup(connman_device_get_string(device, "Name"));

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

	return 0;
}

int __connman_profile_add_network(struct connman_network *network)
{
	struct connman_group *group;

	DBG("network %p", network);

	group = lookup_group(__connman_network_get_group(network));
	if (group == NULL)
		return -EINVAL;

	g_free(group->type);
	g_free(group->name);

	group->type = g_strdup(__connman_network_get_type(network));
	group->name = g_strdup(connman_network_get_string(network, "Name"));

	group->strength = connman_network_get_uint8(network, "Strength");

	if (group->network == NULL) {
		group->network = network;

		group->mode = g_strdup(connman_network_get_string(network,
								"WiFi.Mode"));
		group->security = g_strdup(connman_network_get_string(network,
							"WiFi.Security"));
	}

	return 0;
}

int __connman_profile_remove_network(struct connman_network *network)
{
	struct connman_group *group;

	DBG("network %p", network);

	group = lookup_group(__connman_network_get_group(network));
	if (group == NULL)
		return -EINVAL;

	if (group->network == network) {
		g_free(group->security);
		group->security = NULL;

		g_free(group->mode);
		group->mode = NULL;

		group->network = NULL;
	}

	return 0;
}

const char *__connman_profile_active(void)
{
	DBG("");

	return PROFILE_DEFAULT;
}

void __connman_profile_list(DBusMessageIter *iter)
{
	const char *path = __connman_profile_active();

	DBG("");

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &path);
}

static void append_path(gpointer key, gpointer value, gpointer user_data)
{
	struct connman_group *group = value;
	DBusMessageIter *iter = user_data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH,
							&group->path);
}

void __connman_profile_list_services(DBusMessageIter *iter)
{
	DBG("");

	g_hash_table_foreach(groups, append_path, iter);
}

static void append_services(DBusMessageIter *dict)
{
	DBusMessageIter entry, value, iter;
	const char *key = "Services";

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
								NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
		DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_OBJECT_PATH_AS_STRING,
								&value);

	dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY,
				DBUS_TYPE_OBJECT_PATH_AS_STRING, &iter);
	__connman_profile_list_services(&iter);
	dbus_message_iter_close_container(&value, &iter);

	dbus_message_iter_close_container(&entry, &value);

	dbus_message_iter_close_container(dict, &entry);
}

static DBusMessage *profile_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *name = "Default";
	DBusMessage *reply;
	DBusMessageIter array, dict;

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

	append_services(&dict);

	dbus_message_iter_close_container(&array, &dict);

	return reply;
}

static GDBusMethodTable profile_methods[] = {
	{ "GetProperties", "", "a{sv}", profile_properties },
	{ },
};

int __connman_profile_init(DBusConnection *conn)
{
	DBG("conn %p", conn);

	connection = dbus_connection_ref(conn);
	if (connection == NULL)
		return -1;

	groups = g_hash_table_new_full(g_str_hash, g_str_equal,
							g_free, free_group);

	g_dbus_register_interface(connection, PROFILE_DEFAULT,
						CONNMAN_PROFILE_INTERFACE,
						profile_methods,
						NULL, NULL, NULL, NULL);

	return 0;
}

void __connman_profile_cleanup(void)
{
	DBG("conn %p", connection);

	g_dbus_unregister_interface(connection, PROFILE_DEFAULT,
						CONNMAN_PROFILE_INTERFACE);

	g_hash_table_destroy(groups);
	groups = NULL;

	if (connection == NULL)
		return;

	dbus_connection_unref(connection);
}
