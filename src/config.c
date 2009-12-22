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

#include "connman.h"

struct connman_config {
	char *ident;
	char *name;
	char *description;
};

static GHashTable *config_hash = NULL;

static int load_config(struct connman_config *config)
{
	GKeyFile *keyfile;
	char *str;

	DBG("config %p", config);

	keyfile = __connman_storage_open_config(config->ident);
	if (keyfile == NULL)
		return -EIO;

	str = g_key_file_get_string(keyfile, "global", "Name", NULL);
	if (str != NULL) {
		g_free(config->name);
		config->name = str;
	}

	str = g_key_file_get_string(keyfile, "global", "Description", NULL);
	if (str != NULL) {
		g_free(config->description);
		config->description = str;
	}

	__connman_storage_close_config(config->ident, keyfile, FALSE);

	return 0;
}

static void free_config(struct connman_config *config)
{
	g_free(config->description);
	g_free(config->name);
	g_free(config->ident);
	g_free(config);
}

static void unregister_config(gpointer data)
{
	struct connman_config *config = data;

	connman_info("Removing configuration %s", config->ident);

	free_config(config);
}

static int create_config(const char *ident)
{
	struct connman_config *config;

	DBG("ident %s", ident);

	config = g_try_new0(struct connman_config, 1);
	if (config == NULL)
		return -ENOMEM;

	config->ident = g_strdup(ident);

	if (config->ident == NULL) {
		free_config(config);
		return -ENOMEM;
	}

	if (g_hash_table_lookup(config_hash, config->ident) != NULL) {
		free_config(config);
		return -EEXIST;
	}

	g_hash_table_insert(config_hash, g_strdup(config->ident), config);

	connman_info("Adding configuration %s", config->ident);

	load_config(config);

	return 0;
}

static int config_init(void)
{
	GDir *dir;
	const gchar *file;

	DBG("");

	dir = g_dir_open(STORAGEDIR, 0, NULL);
	if (dir != NULL) {
		while ((file = g_dir_read_name(dir)) != NULL) {
			GString *str;
			gchar *ident;

			if (g_str_has_suffix(file, ".config") == FALSE)
				continue;

			ident = g_strrstr(file, ".config");
			if (ident == NULL)
				continue;

			str = g_string_new_len(file, ident - file);
			if (str == NULL)
				continue;

			ident = g_string_free(str, FALSE);

			if (connman_dbus_validate_ident(ident) == TRUE)
				create_config(ident);

			g_free(ident);
		}

		g_dir_close(dir);
	}

	return 0;
}

int __connman_config_init(void)
{
	DBG("");

	config_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						g_free, unregister_config);

	return config_init();
}

void __connman_config_cleanup(void)
{
	DBG("");

	g_hash_table_destroy(config_hash);
	config_hash = NULL;
}

int __connman_config_provision_service(struct connman_service *service)
{
	DBG("service %p", service);

	return 0;
}
