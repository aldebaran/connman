/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
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
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/vfs.h>
#include <sys/inotify.h>
#include <glib.h>

#include <connman/log.h>
#include "../src/connman.h"

#include "vpn.h"

enum what {
	REMOVE = 1,
	ADD = 2,
};

struct vpn_config_provider {
	char *provider_identifier;
	char *ident;
	char *name;
	char *type;
	char *host;
	char *domain;
	char *networks;
	GHashTable *setting_strings;

	char *config_ident; /* file prefix */
	char *config_entry; /* entry name */
};

struct vpn_config {
	char *ident;
	char *name;
	char *description;
	connman_bool_t protected;
	GHashTable *provider_table;
};

static GHashTable *config_table = NULL;
static GSList *protected_providers = NULL;

static connman_bool_t cleanup = FALSE;

/* Definition of possible strings in the .config files */
#define CONFIG_KEY_NAME                "Name"
#define CONFIG_KEY_DESC                "Description"
#define CONFIG_KEY_PROT                "Protected"

static const char *config_possible_keys[] = {
	CONFIG_KEY_NAME,
	CONFIG_KEY_DESC,
	CONFIG_KEY_PROT,
	NULL,
};

static void unregister_config(gpointer data)
{
	struct vpn_config *config = data;

	connman_info("Removing configuration %s", config->ident);

	g_hash_table_destroy(config->provider_table);

	g_free(config->description);
	g_free(config->name);
	g_free(config->ident);
	g_free(config);
}

static void unregister_provider(gpointer data)
{
	struct vpn_config_provider *config_provider = data;
	struct vpn_provider *provider;
	char *provider_id;

	if (cleanup == TRUE)
		goto free_only;

	provider_id = config_provider->provider_identifier;

	connman_info("Removing provider configuration %s provider %s",
				config_provider->ident, provider_id);

	protected_providers = g_slist_remove(protected_providers,
						config_provider);

	provider = __vpn_provider_lookup(provider_id);
	if (provider != NULL)
		__vpn_provider_delete(provider);
	else {
		if (__connman_storage_remove_provider(provider_id) == FALSE)
			DBG("Could not remove all files for provider %s",
								provider_id);
	}

free_only:
	g_free(config_provider->ident);
	g_free(config_provider->type);
	g_free(config_provider->name);
	g_free(config_provider->host);
	g_free(config_provider->domain);
	g_free(config_provider->networks);
	g_hash_table_destroy(config_provider->setting_strings);
	g_free(config_provider->provider_identifier);
	g_free(config_provider->config_ident);
	g_free(config_provider->config_entry);
	g_free(config_provider);
}

static connman_bool_t check_type(const char *type)
{
	if (g_strcmp0(type, "OpenConnect") == 0)
		return TRUE;
	if (g_strcmp0(type, "OpenVPN") == 0)
		return TRUE;
	if (g_strcmp0(type, "VPNC") == 0)
		return TRUE;
	if (g_strcmp0(type, "L2TP") == 0)
		return TRUE;
	if (g_strcmp0(type, "PPTP") == 0)
		return TRUE;

	return FALSE;
}

static connman_bool_t
is_protected_provider(struct vpn_config_provider *config_provider)
{
	GSList *list;

	DBG("ident %s", config_provider->ident);

	for (list = protected_providers; list; list = list->next) {
		struct vpn_config_provider *p = list->data;

		if (g_strcmp0(p->type, config_provider->type) != 0)
			continue;

		if (check_type(config_provider->type) == TRUE)
			return TRUE;
	}

	return FALSE;
}

static int set_string(struct vpn_config_provider *config_provider,
					const char *key, const char *value)
{
	DBG("provider %p key %s value %s", config_provider, key, value);

	if (g_str_equal(key, "Type") == TRUE) {
		g_free(config_provider->type);
		config_provider->type = g_strdup(value);
	} else if (g_str_equal(key, "Name") == TRUE) {
		g_free(config_provider->name);
		config_provider->name = g_strdup(value);
	} else if (g_str_equal(key, "Host") == TRUE) {
		g_free(config_provider->host);
		config_provider->host = g_strdup(value);
	} else if (g_str_equal(key, "Domain") == TRUE) {
		g_free(config_provider->domain);
		config_provider->domain = g_strdup(value);
	} else if (g_str_equal(key, "Networks") == TRUE) {
		g_free(config_provider->networks);
		config_provider->networks = g_strdup(value);
	}

	g_hash_table_replace(config_provider->setting_strings,
					g_strdup(key), g_strdup(value));
	return 0;
}

static const char *get_string(struct vpn_config_provider *config_provider,
							const char *key)
{
	DBG("provider %p key %s", config_provider, key);

	if (g_str_equal(key, "Type") == TRUE)
		return config_provider->type;
	else if (g_str_equal(key, "Name") == TRUE)
		return config_provider->name;
	else if (g_str_equal(key, "Host") == TRUE)
		return config_provider->host;
	else if (g_str_equal(key, "Domain") == TRUE)
		return config_provider->domain;
	else if (g_str_equal(key, "Networks") == TRUE)
		return config_provider->networks;

	return g_hash_table_lookup(config_provider->setting_strings, key);
}

static void add_keys(struct vpn_config_provider *config_provider,
			GKeyFile *keyfile, const char *group)
{
	char **avail_keys;
	gsize nb_avail_keys, i;

	avail_keys = g_key_file_get_keys(keyfile, group, &nb_avail_keys, NULL);
	if (avail_keys == NULL)
		return;

	for (i = 0 ; i < nb_avail_keys; i++) {
		char *value = g_key_file_get_value(keyfile, group,
						avail_keys[i], NULL);
		if (value == NULL) {
			connman_warn("Cannot find value for %s",
							avail_keys[i]);
			continue;
		}

		set_string(config_provider, avail_keys[i], value);
		g_free(value);
	}

	g_strfreev(avail_keys);
}

static int load_provider(GKeyFile *keyfile, const char *group,
				struct vpn_config *config, enum what action)
{
	struct vpn_config_provider *config_provider;
	const char *ident, *host, *domain;
	int err;

	/* Strip off "provider_" prefix */
	ident = group + 9;

	if (strlen(ident) < 1)
		return -EINVAL;

	config_provider = g_hash_table_lookup(config->provider_table, ident);
	if (config_provider != NULL)
		return -EALREADY;

	config_provider = g_try_new0(struct vpn_config_provider, 1);
	if (config_provider == NULL)
		return -ENOMEM;

	config_provider->ident = g_strdup(ident);

	config_provider->setting_strings = g_hash_table_new_full(g_str_hash,
						g_str_equal, g_free, g_free);

	add_keys(config_provider, keyfile, group);

	host = get_string(config_provider, "Host");
	domain = get_string(config_provider, "Domain");
	if (host != NULL && domain != NULL) {
		char *id = __vpn_provider_create_identifier(host, domain);

		struct vpn_provider *provider;
		provider = __vpn_provider_lookup(id);
		if (provider != NULL) {
			if (action == REMOVE)
				__vpn_provider_delete(provider);

			g_free(id);
			err = -EALREADY;
			goto err;
		}

		config_provider->provider_identifier = id;

		DBG("provider identifier %s", id);
	} else {
		DBG("invalid values host %s domain %s", host, domain);
		err = -EINVAL;
		goto err;
	}

	if (is_protected_provider(config_provider) == TRUE) {
		connman_error("Trying to provision a protected service");
		err = -EACCES;
		goto err;
	}

	config_provider->config_ident = g_strdup(config->ident);
	config_provider->config_entry = g_strdup_printf("provider_%s",
						config_provider->ident);

	g_hash_table_insert(config->provider_table,
				config_provider->ident,	config_provider);

	if (config->protected == TRUE)
		protected_providers =
			g_slist_prepend(protected_providers, config_provider);

	err = __vpn_provider_create_from_config(
					config_provider->setting_strings,
					config_provider->config_ident,
					config_provider->config_entry);
	if (err != 0) {
		DBG("Cannot create provider from config file (%d/%s)",
			-err, strerror(-err));
		goto err;
	}

	connman_info("Added provider configuration %s",
						config_provider->ident);
	return 0;

err:
	g_free(config_provider->ident);
	g_free(config_provider->type);
	g_free(config_provider->name);
	g_free(config_provider->host);
	g_free(config_provider->domain);
	g_free(config_provider->networks);
	g_hash_table_destroy(config_provider->setting_strings);
	g_free(config_provider);

	return err;
}

static void check_keys(GKeyFile *keyfile, const char *group,
			const char **possible_keys)
{
	char **avail_keys;
	gsize nb_avail_keys, i, j;

	avail_keys = g_key_file_get_keys(keyfile, group, &nb_avail_keys, NULL);
	if (avail_keys == NULL)
		return;

	for (i = 0 ; i < nb_avail_keys; i++) {
		for (j = 0; possible_keys[j] ; j++)
			if (g_strcmp0(avail_keys[i], possible_keys[j]) == 0)
				break;

		if (possible_keys[j] == NULL)
			connman_warn("Unknown configuration key %s in [%s]",
					avail_keys[i], group);
	}

	g_strfreev(avail_keys);
}

static int load_config(struct vpn_config *config, char *path, enum what action)
{
	GKeyFile *keyfile;
	GError *error = NULL;
	gsize length;
	char **groups;
	char *str;
	gboolean protected, found = FALSE;
	int i;

	DBG("config %p", config);

	keyfile = __connman_storage_load_provider_config(config->ident);
	if (keyfile == NULL)
		return -EIO;

	/* Verify keys validity of the global section */
	check_keys(keyfile, "global", config_possible_keys);

	str = g_key_file_get_string(keyfile, "global", CONFIG_KEY_NAME, NULL);
	if (str != NULL) {
		g_free(config->name);
		config->name = str;
	}

	str = g_key_file_get_string(keyfile, "global", CONFIG_KEY_DESC, NULL);
	if (str != NULL) {
		g_free(config->description);
		config->description = str;
	}

	protected = g_key_file_get_boolean(keyfile, "global",
					CONFIG_KEY_PROT, &error);
	if (error == NULL)
		config->protected = protected;
	else
		config->protected = TRUE;
	g_clear_error(&error);

	groups = g_key_file_get_groups(keyfile, &length);

	for (i = 0; groups[i] != NULL; i++) {
		if (g_str_has_prefix(groups[i], "provider_") == TRUE) {
			int ret = load_provider(keyfile, groups[i], config,
						action);
			if (ret == 0 || ret == -EALREADY)
				found = TRUE;
		}
	}

	if (found == FALSE)
		connman_warn("Config file %s/%s.config does not contain any "
			"configuration that can be provisioned!",
			path, config->ident);

	g_strfreev(groups);

	g_key_file_free(keyfile);

	return 0;
}

static struct vpn_config *create_config(const char *ident)
{
	struct vpn_config *config;

	DBG("ident %s", ident);

	if (g_hash_table_lookup(config_table, ident) != NULL)
		return NULL;

	config = g_try_new0(struct vpn_config, 1);
	if (config == NULL)
		return NULL;

	config->ident = g_strdup(ident);

	config->provider_table = g_hash_table_new_full(g_str_hash, g_str_equal,
						NULL, unregister_provider);

	g_hash_table_insert(config_table, config->ident, config);

	connman_info("Adding configuration %s", config->ident);

	return config;
}

static connman_bool_t validate_ident(const char *ident)
{
	unsigned int i;

	if (ident == NULL)
		return FALSE;

	for (i = 0; i < strlen(ident); i++)
		if (g_ascii_isprint(ident[i]) == FALSE)
			return FALSE;

	return TRUE;
}

static char *get_dir()
{
	return g_strdup_printf("%s", VPN_STORAGEDIR);
}

static int read_configs(void)
{
	GDir *dir;
	char *path = get_dir();

	DBG("path %s", path);

	dir = g_dir_open(path, 0, NULL);
	if (dir != NULL) {
		const gchar *file;

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

			if (validate_ident(ident) == TRUE) {
				struct vpn_config *config;

				config = create_config(ident);
				if (config != NULL)
					load_config(config, path, ADD);
			} else {
				connman_error("Invalid config ident %s", ident);
			}
			g_free(ident);
		}

		g_dir_close(dir);
	}

	g_free(path);

	return 0;
}

static void config_notify_handler(struct inotify_event *event,
                                        const char *ident)
{
	char *ext;

	if (ident == NULL)
		return;

	if (g_str_has_suffix(ident, ".config") == FALSE)
		return;

	ext = g_strrstr(ident, ".config");
	if (ext == NULL)
		return;

	*ext = '\0';

	if (validate_ident(ident) == FALSE) {
		connman_error("Invalid config ident %s", ident);
		return;
	}

	if (event->mask & IN_CREATE)
		create_config(ident);

	if (event->mask & IN_MODIFY) {
		struct vpn_config *config;

		config = g_hash_table_lookup(config_table, ident);
		if (config != NULL) {
			char *path = get_dir();

			g_hash_table_remove_all(config->provider_table);
			load_config(config, path, REMOVE);

			/* Re-scan the config file for any changes */
			g_hash_table_remove_all(config->provider_table);
			load_config(config, path, ADD);

			g_free(path);
		}
	}

	if (event->mask & IN_DELETE)
		g_hash_table_remove(config_table, ident);
}

int __vpn_config_init(void)
{
	char *dir = get_dir();

	DBG("");

	config_table = g_hash_table_new_full(g_str_hash, g_str_equal,
						NULL, unregister_config);

	connman_inotify_register(dir, config_notify_handler);

	g_free(dir);

	return read_configs();
}

void __vpn_config_cleanup(void)
{
	char *dir = get_dir();

	DBG("");

	cleanup = TRUE;

	connman_inotify_unregister(dir, config_notify_handler);

	g_free(dir);

	g_hash_table_destroy(config_table);
	config_table = NULL;

	cleanup = FALSE;
}
