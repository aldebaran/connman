/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2012  Intel Corporation. All rights reserved.
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
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>

#include <connman/storage.h>

#include "connman.h"

#define SETTINGS	"settings"
#define DEFAULT		"default.profile"

#define MODE		(S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | \
			S_IXGRP | S_IROTH | S_IXOTH)

static GKeyFile *storage_load(const char *pathname)
{
	GKeyFile *keyfile = NULL;
	GError *error = NULL;

	DBG("Loading %s", pathname);

	keyfile = g_key_file_new();

	if (!g_key_file_load_from_file(keyfile, pathname, 0, &error)) {
		DBG("Unable to load %s: %s", pathname, error->message);
		g_clear_error(&error);

		g_key_file_free(keyfile);
		keyfile = NULL;
	}

	return keyfile;
}

static int storage_save(GKeyFile *keyfile, char *pathname)
{
	gchar *data = NULL;
	gsize length = 0;
	GError *error = NULL;
	int ret = 0;

	data = g_key_file_to_data(keyfile, &length, NULL);

	if (!g_file_set_contents(pathname, data, length, &error)) {
		DBG("Failed to store information: %s", error->message);
		g_error_free(error);
		ret = -EIO;
	}

	g_free(data);

	return ret;
}

static void storage_delete(const char *pathname)
{
	DBG("file path %s", pathname);

	if (unlink(pathname) < 0)
		connman_error("Failed to remove %s", pathname);
}

GKeyFile *__connman_storage_load_global()
{
	gchar *pathname;
	GKeyFile *keyfile = NULL;

	pathname = g_strdup_printf("%s/%s", STORAGEDIR, SETTINGS);
	if(pathname == NULL)
		return NULL;

	keyfile = storage_load(pathname);

	g_free(pathname);

	return keyfile;
}

int __connman_storage_save_global(GKeyFile *keyfile)
{
	gchar *pathname;
	int ret;

	pathname = g_strdup_printf("%s/%s", STORAGEDIR, SETTINGS);
	if(pathname == NULL)
		return -ENOMEM;

	ret = storage_save(keyfile, pathname);

	g_free(pathname);

	return ret;
}

void __connman_storage_delete_global()
{
	gchar *pathname;

	pathname = g_strdup_printf("%s/%s", STORAGEDIR, SETTINGS);
	if(pathname == NULL)
		return;

	storage_delete(pathname);

	g_free(pathname);
}

GKeyFile *__connman_storage_load_config(const char *ident)
{
	gchar *pathname;
	GKeyFile *keyfile = NULL;

	pathname = g_strdup_printf("%s/%s.config", STORAGEDIR, ident);
	if(pathname == NULL)
		return NULL;

	keyfile = storage_load(pathname);

	g_free(pathname);

	return keyfile;
}

GKeyFile *__connman_storage_open_service(const char *service_id)
{
	gchar *pathname;
	GKeyFile *keyfile = NULL;

	pathname = g_strdup_printf("%s/%s/%s", STORAGEDIR, service_id, SETTINGS);
	if(pathname == NULL)
		return NULL;

	keyfile =  storage_load(pathname);
	if (keyfile) {
		g_free(pathname);
		return keyfile;
	}

	g_free(pathname);

	keyfile = g_key_file_new();

	return keyfile;
}

gchar **connman_storage_get_services()
{
	struct dirent *d;
	gchar *str;
	DIR *dir;
	GString *result;
	gchar **services = NULL;
	struct stat buf;
	int ret;

	dir = opendir(STORAGEDIR);
	if (dir == NULL)
		return NULL;

	result = g_string_new(NULL);

	while ((d = readdir(dir))) {
		if (strcmp(d->d_name, ".") == 0 ||
				strcmp(d->d_name, "..") == 0 ||
				strncmp(d->d_name, "provider_", 9) == 0)
			continue;

		switch (d->d_type) {
		case DT_DIR:
			/*
			 * If the settings file is not found, then
			 * assume this directory is not a services dir.
			 */
			str = g_strdup_printf("%s/%s/settings", STORAGEDIR,
								d->d_name);
			ret = stat(str, &buf);
			g_free(str);
			if (ret < 0)
				continue;

			g_string_append_printf(result, "%s/", d->d_name);
			break;
		}
	}

	closedir(dir);

	str = g_string_free(result, FALSE);
	if (str) {
		str[strlen(str) - 1] = '\0';
		services = g_strsplit(str, "/", -1);
	}
	g_free(str);

	return services;
}

GKeyFile *connman_storage_load_service(const char *service_id)
{
	gchar *pathname;
	GKeyFile *keyfile = NULL;

	pathname = g_strdup_printf("%s/%s/%s", STORAGEDIR, service_id, SETTINGS);
	if(pathname == NULL)
		return NULL;

	keyfile =  storage_load(pathname);
	g_free(pathname);

	return keyfile;
}

int __connman_storage_save_service(GKeyFile *keyfile, const char *service_id)
{
	int ret = 0;
	gchar *pathname, *dirname;

	dirname = g_strdup_printf("%s/%s", STORAGEDIR, service_id);
	if(dirname == NULL)
		return -ENOMEM;

	/* If the dir doesn't exist, create it */
	if (!g_file_test(dirname, G_FILE_TEST_IS_DIR)) {
		if(mkdir(dirname, MODE) < 0) {
			if (errno != EEXIST) {
				g_free(dirname);
				return -errno;
			}
		}
	}

	pathname = g_strdup_printf("%s/%s", dirname, SETTINGS);

	g_free(dirname);

	ret = storage_save(keyfile, pathname);

	g_free(pathname);

	return ret;
}

static gboolean remove_file(const char *service_id, const char *file)
{
	gchar *pathname;
	gboolean ret = FALSE;

	pathname = g_strdup_printf("%s/%s/%s", STORAGEDIR, service_id, file);
	if(pathname == NULL)
		return FALSE;

	if (g_file_test(pathname, G_FILE_TEST_EXISTS) == FALSE) {
		ret = TRUE;
	} else if (g_file_test(pathname, G_FILE_TEST_IS_REGULAR) == TRUE) {
		unlink(pathname);
		ret = TRUE;
	}

	g_free(pathname);
	return ret;
}

static gboolean remove_dir(const char *service_id)
{
	gchar *pathname;
	gboolean ret = FALSE;

	pathname = g_strdup_printf("%s/%s", STORAGEDIR, service_id);
	if(pathname == NULL)
		return FALSE;

	if (g_file_test(pathname, G_FILE_TEST_EXISTS) == FALSE) {
		ret = TRUE;
	} else if (g_file_test(pathname, G_FILE_TEST_IS_DIR) == TRUE) {
		rmdir(pathname);
		ret = TRUE;
	}

	g_free(pathname);
	return ret;
}

gboolean __connman_storage_remove_service(const char *service_id)
{
	gboolean removed;

	/* Remove service configuration file */
	removed = remove_file(service_id, SETTINGS);
	if (removed == FALSE)
		return FALSE;

	/* Remove the statistics file also */
	removed = remove_file(service_id, "data");
	if (removed == FALSE)
		return FALSE;

	removed = remove_dir(service_id);
	if (removed == FALSE)
		return FALSE;

	DBG("Removed service dir %s/%s", STORAGEDIR, service_id);

	return TRUE;
}

GKeyFile *__connman_storage_load_provider(const char *identifier)
{
	gchar *pathname;
	GKeyFile *keyfile;

	pathname = g_strdup_printf("%s/%s_%s/%s", STORAGEDIR, "provider",
			identifier, SETTINGS);
	if (pathname == NULL)
		return NULL;

	keyfile = storage_load(pathname);
	g_free(pathname);

	return keyfile;
}

void __connman_storage_save_provider(GKeyFile *keyfile, const char *identifier)
{
	gchar *pathname, *dirname;

	dirname = g_strdup_printf("%s/%s_%s", STORAGEDIR,
			"provider", identifier);
	if (dirname == NULL)
		return;

	if (g_file_test(dirname, G_FILE_TEST_IS_DIR) == FALSE &&
			mkdir(dirname, MODE) < 0) {
		g_free(dirname);
		return;
	}

	pathname = g_strdup_printf("%s/%s", dirname, SETTINGS);
	g_free(dirname);

	storage_save(keyfile, pathname);
	g_free(pathname);
}

gchar **__connman_storage_get_providers(void)
{
	GSList *list = NULL;
	int num = 0, i = 0;
	struct dirent *d;
	gchar *str;
	DIR *dir;
	struct stat buf;
	int ret;
	char **providers;
	GSList *iter;

	dir = opendir(STORAGEDIR);
	if (dir == NULL)
		return NULL;

	while ((d = readdir(dir))) {
		if (strcmp(d->d_name, ".") == 0 ||
				strcmp(d->d_name, "..") == 0 ||
				strncmp(d->d_name, "provider_", 9) != 0)
			continue;

		if (d->d_type == DT_DIR) {
			str = g_strdup_printf("%s/%s/settings", STORAGEDIR,
					d->d_name);
			ret = stat(str, &buf);
			g_free(str);
			if (ret < 0)
				continue;
			list = g_slist_prepend(list, g_strdup(d->d_name));
			num += 1;
		}
	}

	closedir(dir);

	providers = g_try_new0(char *, num + 1);
	for (iter = list; iter != NULL; iter = g_slist_next(iter)) {
		if (providers != NULL)
			providers[i] = iter->data;
		else
			g_free(iter->data);
		i += 1;
	}
	g_slist_free(list);

	return providers;
}

/*
 * This function migrates keys from default.profile to settings file.
 * This can be removed once the migration is over.
*/
void __connman_storage_migrate()
{
	gchar *pathname;
	GKeyFile *keyfile_def = NULL;
	GKeyFile *keyfile = NULL;
	GError *error = NULL;
	connman_bool_t delete_old_config = TRUE;
	char **services, **keys, *value;
	int i, k, err;
	connman_bool_t val;

	pathname = g_strdup_printf("%s/%s", STORAGEDIR, DEFAULT);
	if (pathname == NULL)
		return;

	/* If setting file exists, migration has been done. */
	keyfile = __connman_storage_load_global();
	if (keyfile) {
		g_key_file_free(keyfile);
		unlink(pathname);
		g_free(pathname);
		return;
	}

	/* If default.profile exists, create new settings file */
	keyfile_def = storage_load(pathname);
	if (keyfile_def == NULL)
		goto done;

	services = g_key_file_get_groups(keyfile_def, NULL);
	for (i = 0; services != NULL && services[i] != NULL; i++) {
		if (strncmp(services[i], "wifi_", 5) != 0 &&
				strncmp(services[i], "ethernet_", 9) != 0 &&
				strncmp(services[i], "cellular_", 9) != 0 &&
				strncmp(services[i], "bluetooth_", 10) != 0 &&
				strncmp(services[i], "wimax_", 6) != 0 &&
				strncmp(services[i], "vpn_", 4) != 0)
			continue;

		keyfile = connman_storage_load_service(services[i]);
		if (keyfile != NULL) {
			g_key_file_free(keyfile);
			DBG("already exists %s", services[i]);
			continue;
		}

		keyfile = g_key_file_new();
		if (keyfile == NULL) {
			connman_warn("Migrating %s failed", services[i]);
			delete_old_config = FALSE;
			continue;
		}

		keys = g_key_file_get_keys(keyfile_def, services[i],
				NULL, NULL);

		for (k = 0; keys != NULL && keys[k] != NULL; k++) {
			value = g_key_file_get_value(keyfile_def, services[i],
					keys[k], NULL);
			g_key_file_set_value(keyfile, services[i],
					keys[k], value);
			g_free(value);
		}

		if (keys != NULL && keys[0] != NULL) {
			err = __connman_storage_save_service(keyfile,
					services[i]);
			if (err >= 0)
				DBG("migrated %s", services[i]);
			else {
				connman_warn("Migrating %s failed %s",
						services[i], strerror(-err));
				delete_old_config = FALSE;
			}
		} else
			DBG("no keys in %s", services[i]);

		g_strfreev(keys);
		g_key_file_free(keyfile);
	}
	g_strfreev(services);

	/* Copy global settings from default.profile to settings. */
	keyfile = g_key_file_new();

	val = g_key_file_get_boolean(keyfile_def, "global",
					"OfflineMode", &error);
	if (error != NULL) {
		g_clear_error(&error);
		val = FALSE;
	}

	g_key_file_set_boolean(keyfile, "global",
					"OfflineMode", val);

	/* Migrate Powered/Enable state key/value pairs from legacy
	 * settings
	 */

	val = g_key_file_get_boolean(keyfile_def, "WiFi",
					"Enable", &error);
	if (error != NULL) {
		g_clear_error(&error);
		val = g_key_file_get_boolean(keyfile_def, "device_Wireless", "Powered", &error);
		if (error != NULL) {
			g_clear_error(&error);
			val = FALSE;
		}
	}

	g_key_file_set_boolean(keyfile, "WiFi",
					"Enable", val);

	val = g_key_file_get_boolean(keyfile_def, "Bluetooth",
					"Enable", &error);
	if (error != NULL) {
		g_clear_error(&error);
		val = g_key_file_get_boolean(keyfile_def, "device_Bluetooth", "Powered", &error);
		if (error != NULL) {
			g_clear_error(&error);
			val = FALSE;
		}
	}

	g_key_file_set_boolean(keyfile, "Bluetooth",
					"Enable", val);

	val = g_key_file_get_boolean(keyfile_def, "Wired",
					"Enable", &error);
	if (error != NULL) {
		g_clear_error(&error);
		val = g_key_file_get_boolean(keyfile_def, "device_Ethernet", "Powered", &error);
		if (error != NULL) {
			g_clear_error(&error);
			val = FALSE;
		}
	}

	g_key_file_set_boolean(keyfile, "Wired",
					"Enable", val);

	val = g_key_file_get_boolean(keyfile_def, "Cellular",
					"Enable", &error);
	if (error != NULL) {
		g_clear_error(&error);
		val = g_key_file_get_boolean(keyfile_def, "device_Cellular", "Powered", &error);
		if (error != NULL) {
			g_clear_error(&error);
			val = FALSE;
		}
	}

	g_key_file_set_boolean(keyfile, "Cellular",
					"Enable", val);

	val = g_key_file_get_boolean(keyfile_def, "WiMAX",
					"Enable", &error);
	if (error != NULL) {
		g_clear_error(&error);
		val = g_key_file_get_boolean(keyfile_def, "device_WiMAX", "Powered", &error);
		if (error != NULL) {
			g_clear_error(&error);
			val = FALSE;
		}
	}

	g_key_file_set_boolean(keyfile, "WiMAX",
					"Enable", val);

	if (__connman_storage_save_global(keyfile) < 0) {
		connman_warn("Migrating global config failed");
		delete_old_config = FALSE;
	}

	g_key_file_free(keyfile);

	g_key_file_free(keyfile_def);

	if (delete_old_config == TRUE) {
		DBG("migration done for %s", pathname);
		unlink(pathname);
	}
done:
	g_free(pathname);
}
