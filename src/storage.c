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

static void storage_save(GKeyFile *keyfile, char *pathname)
{
	gchar *data = NULL;
	gsize length = 0;
	GError *error = NULL;

	data = g_key_file_to_data(keyfile, &length, NULL);

	if (!g_file_set_contents(pathname, data, length, &error)) {
		DBG("Failed to store information: %s", error->message);
		g_free(error);
	}

	g_free(data);
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

void __connman_storage_save_global(GKeyFile *keyfile)
{
	gchar *pathname;

	pathname = g_strdup_printf("%s/%s", STORAGEDIR, SETTINGS);
	if(pathname == NULL)
		return;

	storage_save(keyfile, pathname);

	g_free(pathname);
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

void __connman_storage_save_config(GKeyFile *keyfile, const char *ident)
{
	gchar *pathname;

	pathname = g_strdup_printf("%s/%s.config", STORAGEDIR, ident);
	if(pathname == NULL)
		return;

	storage_save(keyfile, pathname);
}

void __connman_storage_delete_config(const char *ident)
{
	gchar *pathname;

	pathname = g_strdup_printf("%s/%s.config", STORAGEDIR, ident);
	if(pathname == NULL)
		return;

	storage_delete(pathname);

	g_free(pathname);
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
	if (keyfile) {
		g_free(pathname);
		return keyfile;
	}

	g_free(pathname);

	pathname = g_strdup_printf("%s/%s", STORAGEDIR, DEFAULT);
	if(pathname == NULL)
		return NULL;

	keyfile =  storage_load(pathname);

	g_free(pathname);

	return keyfile;
}

void __connman_storage_save_service(GKeyFile *keyfile, const char *service_id)
{
	gchar *pathname, *dirname;

	dirname = g_strdup_printf("%s/%s", STORAGEDIR, service_id);
	if(dirname == NULL)
		return;

	/* If the dir doesn't exist, create it */
	if (!g_file_test(dirname, G_FILE_TEST_IS_DIR)) {
		if(mkdir(dirname, MODE) < 0) {
			if (errno != EEXIST) {
				g_free(dirname);
				return;
			}
		}
	}

	pathname = g_strdup_printf("%s/%s", dirname, SETTINGS);

	g_free(dirname);

	storage_save(keyfile, pathname);

	g_free(pathname);
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
	connman_bool_t val;

	/* If setting file exists, migration has been done. */
	keyfile = __connman_storage_load_global();
	if (keyfile) {
		g_key_file_free(keyfile);
		return;
	}

	pathname = g_strdup_printf("%s/%s", STORAGEDIR, DEFAULT);
	if(pathname == NULL)
		return;

	/* If default.profile doesn't exists, no need to migrate. */
	keyfile_def = storage_load(pathname);
	if (keyfile_def == NULL) {
		g_free(pathname);
		return;
	}

	/* Copy global settings from default.profile to settings. */
	keyfile = g_key_file_new();

	/* offline mode */
	val = g_key_file_get_boolean(keyfile_def, "global",
					"OfflineMode", &error);
	if (error != NULL)
		g_clear_error(&error);
	else
		g_key_file_set_boolean(keyfile, "global",
					"OfflineMode", val);

	/* wifi */
	val = g_key_file_get_boolean(keyfile_def, "WiFi",
					"Enable", &error);
	if (error != NULL)
		g_clear_error(&error);
	else
		g_key_file_set_boolean(keyfile, "WiFi",
					"Enable", val);

	/* bluetooth */
	val = g_key_file_get_boolean(keyfile_def, "Bluetooth",
					"Enable", &error);
	if (error != NULL)
		g_clear_error(&error);
	else
		g_key_file_set_boolean(keyfile, "Bluetooth",
					"Enable", val);

	/* wired */
	val = g_key_file_get_boolean(keyfile_def, "Wired",
					"Enable", &error);
	if (error != NULL)
		g_clear_error(&error);
	else
		g_key_file_set_boolean(keyfile, "Wired",
					"Enable", val);

	/* 3G */
	val = g_key_file_get_boolean(keyfile_def, "3G",
					"Enable", &error);
	if (error != NULL)
		g_clear_error(&error);
	else
		g_key_file_set_boolean(keyfile, "3G",
					"Enable", val);

	/* WiMAX */
	val = g_key_file_get_boolean(keyfile_def, "WiMAX",
					"Enable", &error);
	if (error != NULL)
		g_clear_error(&error);
	else
		g_key_file_set_boolean(keyfile, "WiMAX",
					"Enable", val);

	__connman_storage_save_global(keyfile);

	g_key_file_free(keyfile);
	g_key_file_free(keyfile_def);
	g_free(pathname);
}
