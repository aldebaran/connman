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

#include <errno.h>
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

static struct connman_profile *default_profile = NULL;

static DBusConnection *connection = NULL;

connman_bool_t __connman_profile_get_offlinemode(void)
{
	if (default_profile == NULL)
		return FALSE;

	DBG("offlinemode %d", default_profile->offlinemode);

	return default_profile->offlinemode;
}

int __connman_profile_set_offlinemode(connman_bool_t offlinemode)
{
	DBG("offlinemode %d", offlinemode);

	if (default_profile == NULL)
		return -EINVAL;

	if (default_profile->offlinemode == offlinemode)
		return -EALREADY;

	default_profile->offlinemode = offlinemode;
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
	changed_timeout = 0;

	if (default_profile == NULL)
		return FALSE;

	connman_dbus_property_changed_array(CONNMAN_MANAGER_PATH,
				CONNMAN_MANAGER_INTERFACE, "Services",
				DBUS_TYPE_OBJECT_PATH, __connman_service_list,
				NULL);

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

static void free_profile(struct connman_profile *profile)
{
	g_free(profile->name);
	g_free(profile->path);
	g_free(profile->ident);
	g_free(profile);
}

static int profile_init(void)
{
	DBG("");

	default_profile = g_try_new0(struct connman_profile, 1);
	if (default_profile == NULL)
		return -ENOMEM;

	default_profile->ident = g_strdup(PROFILE_DEFAULT_IDENT);
	default_profile->path = g_strdup_printf("/profile/%s",
					PROFILE_DEFAULT_IDENT);

	if (default_profile->ident == NULL || default_profile->path == NULL) {
		free_profile(default_profile);
		return -ENOMEM;
	}

	default_profile->name = g_strdup("Default");

	__connman_storage_load_profile(default_profile);

	connman_info("Adding default profile");

	DBG("profile %p path %s", default_profile, default_profile->path);

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

	return 0;
}

void __connman_profile_cleanup(void)
{
	DBG("");

	if (connection == NULL)
		return;

	connman_storage_unregister(&profile_storage);

	dbus_connection_unref(connection);
}
