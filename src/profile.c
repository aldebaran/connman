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

#include <string.h>

#include <glib.h>
#include <gdbus.h>

#include "connman.h"

#define PROFILE_DEFAULT_IDENT  "default"

struct connman_profile {
	char *ident;
	char *path;
	char *name;
	connman_bool_t offlinemode;
};

static GHashTable *profile_hash = NULL;
static struct connman_profile *default_profile = NULL;

static DBusConnection *connection = NULL;

static void append_path(gpointer key, gpointer value, gpointer user_data)
{
	struct connman_profile *profile = value;
	DBusMessageIter *iter = user_data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH,
							&profile->path);
}

void __connman_profile_list(DBusMessageIter *iter, void *user_data)
{
	g_hash_table_foreach(profile_hash, append_path, iter);
}

static void profiles_changed(void)
{
	connman_dbus_property_changed_array(CONNMAN_MANAGER_PATH,
			CONNMAN_MANAGER_INTERFACE, "Profiles",
			DBUS_TYPE_OBJECT_PATH, __connman_profile_list, NULL);
}

static void name_changed(struct connman_profile *profile)
{
	connman_dbus_property_changed_basic(profile->path,
				CONNMAN_PROFILE_INTERFACE, "Name",
					DBUS_TYPE_STRING, &profile->name);
}

static void offlinemode_changed(struct connman_profile *profile)
{
	connman_dbus_property_changed_basic(profile->path,
				CONNMAN_PROFILE_INTERFACE, "OfflineMode",
				DBUS_TYPE_BOOLEAN, &profile->offlinemode);

	if (profile != default_profile)
		return;

	connman_dbus_property_changed_basic(CONNMAN_MANAGER_PATH,
				CONNMAN_MANAGER_INTERFACE, "OfflineMode",
				DBUS_TYPE_BOOLEAN, &profile->offlinemode);
}

connman_bool_t __connman_profile_get_offlinemode(void)
{
	if (default_profile == NULL)
		return FALSE;

	DBG("offlinemode %d", default_profile->offlinemode);

	return default_profile->offlinemode;
}

int __connman_profile_set_offlinemode(connman_bool_t offlinemode,
					connman_bool_t all_devices)
{
	DBG("offlinemode %d", offlinemode);

	if (default_profile == NULL)
		return -EINVAL;

	if (default_profile->offlinemode == offlinemode)
		return -EALREADY;

	default_profile->offlinemode = offlinemode;
	offlinemode_changed(default_profile);

	if (all_devices)
		__connman_device_set_offlinemode(offlinemode);

	return 0;
}

int __connman_profile_save_default(void)
{
	DBG("");

	if (default_profile != NULL)
		__connman_storage_save_profile(default_profile);

	return 0;
}

const char *__connman_profile_active_ident(void)
{
	DBG("");

	return PROFILE_DEFAULT_IDENT;
}

const char *__connman_profile_active_path(void)
{
	DBG("");

	if (default_profile == NULL)
		return NULL;

	return default_profile->path;
}

static guint changed_timeout = 0;

static gboolean services_changed(gpointer user_data)
{
	struct connman_profile *profile = default_profile;
	connman_dbus_append_cb_t function = NULL;

	changed_timeout = 0;

	if (profile == NULL)
		return FALSE;

	if (g_strcmp0(profile->ident, PROFILE_DEFAULT_IDENT) == 0) {
		function = __connman_service_list;

		connman_dbus_property_changed_array(CONNMAN_MANAGER_PATH,
				CONNMAN_MANAGER_INTERFACE, "Services",
				DBUS_TYPE_OBJECT_PATH, function, NULL);
	}

	connman_dbus_property_changed_array(profile->path,
				CONNMAN_PROFILE_INTERFACE, "Services",
				DBUS_TYPE_OBJECT_PATH, function, NULL);

	return FALSE;
}

void __connman_profile_changed(gboolean delayed)
{
	DBG("");

	if (changed_timeout > 0) {
		g_source_remove(changed_timeout);
		changed_timeout = 0;
	}

	if (__connman_connection_update_gateway() == TRUE) {
		services_changed(NULL);
		return;
	}

	if (delayed == FALSE) {
		services_changed(NULL);
		return;
	}

	changed_timeout = g_timeout_add_seconds(1, services_changed, NULL);
}

int __connman_profile_add_network(struct connman_network *network)
{
	struct connman_service *service;

	DBG("network %p", network);

	service = __connman_service_create_from_network(network);
	if (service == NULL)
		return -EINVAL;

	return 0;
}

int __connman_profile_update_network(struct connman_network *network)
{
	DBG("network %p", network);

	__connman_service_update_from_network(network);

	return 0;
}

int __connman_profile_remove_network(struct connman_network *network)
{
	DBG("network %p", network);

	__connman_service_remove_from_network(network);

	return 0;
}

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_profile *profile = data;
	DBusMessage *reply;
	DBusMessageIter array, dict;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &array);

	connman_dbus_dict_open(&array, &dict);

	if (profile->name != NULL)
		connman_dbus_dict_append_basic(&dict, "Name",
					DBUS_TYPE_STRING, &profile->name);

	connman_dbus_dict_append_basic(&dict, "OfflineMode",
				DBUS_TYPE_BOOLEAN, &profile->offlinemode);

	connman_dbus_dict_append_array(&dict, "Services",
			DBUS_TYPE_OBJECT_PATH, __connman_service_list, NULL);

	connman_dbus_dict_close(&array, &dict);

	return reply;
}

static DBusMessage *set_property(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_profile *profile = data;
	DBusMessageIter iter, value;
	const char *name;
	int type;

	DBG("conn %p", conn);

	if (dbus_message_iter_init(msg, &iter) == FALSE)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &name);
	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &value);

	type = dbus_message_iter_get_arg_type(&value);

	if (g_str_equal(name, "Name") == TRUE) {
		const char *name;

		if (type != DBUS_TYPE_STRING)
			return __connman_error_invalid_arguments(msg);

		dbus_message_iter_get_basic(&value, &name);

		g_free(profile->name);
		profile->name = g_strdup(name);

		if (profile->name != NULL)
			name_changed(profile);

		__connman_storage_save_profile(profile);
	} else if (g_str_equal(name, "OfflineMode") == TRUE) {
		connman_bool_t offlinemode;

		if (type != DBUS_TYPE_BOOLEAN)
			return __connman_error_invalid_arguments(msg);

		dbus_message_iter_get_basic(&value, &offlinemode);

		if (profile->offlinemode == offlinemode)
			return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);

		profile->offlinemode = offlinemode;
		offlinemode_changed(profile);

		__connman_storage_save_profile(profile);
	} else
		return __connman_error_invalid_property(msg);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static GDBusMethodTable profile_methods[] = {
	{ "GetProperties", "",   "a{sv}", get_properties },
	{ "SetProperty",   "sv", "",      set_property   },
	{ },
};

static GDBusSignalTable profile_signals[] = {
	{ "PropertyChanged", "sv" },
	{ },
};

static void free_profile(struct connman_profile *profile)
{
	g_free(profile->name);
	g_free(profile->path);
	g_free(profile->ident);
	g_free(profile);
}

static void unregister_profile(gpointer data)
{
	struct connman_profile *profile = data;

	DBG("profile %p", profile);

	connman_info("Removing profile %s", profile->ident);

	g_dbus_unregister_interface(connection, profile->path,
						CONNMAN_PROFILE_INTERFACE);

	if (g_strcmp0(profile->ident, PROFILE_DEFAULT_IDENT) == 0)
		default_profile = NULL;

	free_profile(profile);
}

static int create_profile(const char *ident, const char *name,
							const char **path)
{
	struct connman_profile *profile;

	DBG("ident %s name %s", ident, name);

	profile = g_try_new0(struct connman_profile, 1);
	if (profile == NULL)
		return -ENOMEM;

	profile->ident = g_strdup(ident);
	profile->path = g_strdup_printf("/profile/%s", ident);

	if (profile->ident == NULL || profile->path == NULL) {
		free_profile(profile);
		return -ENOMEM;
	}

	if (g_hash_table_lookup(profile_hash, profile->path) != NULL) {
		free_profile(profile);
		return -EEXIST;
	}

	profile->name = g_strdup(name);

	__connman_storage_load_profile(profile);

	g_hash_table_insert(profile_hash, g_strdup(profile->path), profile);

	connman_info("Adding profile %s", ident);

	if (g_strcmp0(ident, PROFILE_DEFAULT_IDENT) == 0)
		default_profile = profile;

	g_dbus_register_interface(connection, profile->path,
					CONNMAN_PROFILE_INTERFACE,
					profile_methods, profile_signals,
							NULL, profile, NULL);

	if (path != NULL)
		*path = profile->path;

	DBG("profile %p path %s", profile, profile->path);

	return 0;
}

int __connman_profile_create(const char *name, const char **path)
{
	struct connman_profile *profile;
	int err;

	DBG("name %s", name);

	if (connman_dbus_validate_ident(name) == FALSE)
		return -EINVAL;

	err = create_profile(name, NULL, path);
	if (err < 0)
		return err;

	profile = g_hash_table_lookup(profile_hash, *path);
	if (profile == NULL)
		return -EIO;

	__connman_storage_save_profile(profile);

	profiles_changed();

	return 0;
}

int __connman_profile_remove(const char *path)
{
	struct connman_profile *profile;

	DBG("path %s", path);

	if (default_profile != NULL &&
				g_strcmp0(path, default_profile->path) == 0)
		return -EINVAL;

	profile = g_hash_table_lookup(profile_hash, path);
	if (profile == NULL)
		return -ENXIO;

	__connman_storage_delete_profile(profile->ident);

	g_hash_table_remove(profile_hash, path);

	profiles_changed();

	return 0;
}

static int profile_init(void)
{
	GDir *dir;
	const gchar *file;

	DBG("");

	dir = g_dir_open(STORAGEDIR, 0, NULL);
	if (dir != NULL) {
		while ((file = g_dir_read_name(dir)) != NULL) {
			GString *str;
			gchar *ident;

			if (g_str_has_suffix(file, ".profile") == FALSE)
				continue;

			ident = g_strrstr(file, ".profile");
			if (ident == NULL)
				continue;

			str = g_string_new_len(file, ident - file);
			if (str == NULL)
				continue;

			ident = g_string_free(str, FALSE);

			if (connman_dbus_validate_ident(ident) == TRUE)
				create_profile(ident, NULL, NULL);

			g_free(ident);
		}

		g_dir_close(dir);
	}

	if (default_profile == NULL)
		create_profile(PROFILE_DEFAULT_IDENT, "Default", NULL);

	profiles_changed();

	return 0;
}

static int profile_load(struct connman_profile *profile)
{
	GKeyFile *keyfile;
	GError *error = NULL;
	connman_bool_t offlinemode;
	char *name;

	DBG("profile %p", profile);

	keyfile = __connman_storage_open_profile(profile->ident);
	if (keyfile == NULL)
		return -EIO;

	name = g_key_file_get_string(keyfile, "global", "Name", NULL);
	if (name != NULL) {
		g_free(profile->name);
		profile->name = name;
	}

	offlinemode = g_key_file_get_boolean(keyfile, "global",
						"OfflineMode", &error);
	if (error == NULL)
		profile->offlinemode = offlinemode;
	g_clear_error(&error);

	__connman_storage_close_profile(profile->ident, keyfile, FALSE);

	return 0;
}

static int profile_save(struct connman_profile *profile)
{
	GKeyFile *keyfile;

	DBG("profile %p", profile);

	keyfile = __connman_storage_open_profile(profile->ident);
	if (keyfile == NULL)
		return -EIO;

	if (profile->name != NULL)
		g_key_file_set_string(keyfile, "global",
						"Name", profile->name);

	g_key_file_set_boolean(keyfile, "global",
					"OfflineMode", profile->offlinemode);

	__connman_storage_close_profile(profile->ident, keyfile, TRUE);

	return 0;
}

static struct connman_storage profile_storage = {
	.name		= "profile",
	.priority	= CONNMAN_STORAGE_PRIORITY_LOW,
	.profile_init	= profile_init,
	.profile_load	= profile_load,
	.profile_save	= profile_save,
};

int __connman_profile_init(void)
{
	DBG("");

	connection = connman_dbus_get_connection();
	if (connection == NULL)
		return -1;

	if (connman_storage_register(&profile_storage) < 0)
		connman_error("Failed to register profile storage");

	profile_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						g_free, unregister_profile);

	return 0;
}

void __connman_profile_cleanup(void)
{
	DBG("");

	if (connection == NULL)
		return;

	g_hash_table_destroy(profile_hash);
	profile_hash = NULL;

	connman_storage_unregister(&profile_storage);

	dbus_connection_unref(connection);
}
