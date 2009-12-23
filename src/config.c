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

#include <stdio.h>
#include <string.h>
#include <glib.h>

#include "connman.h"

struct connman_config_service {
	char *type;
	void *ssid;
	unsigned int ssid_len;
	char *eap;
	char *identity;
	char *ca_cert_file;
	char *client_cert_file;
	char *private_key_file;
	char *private_key_passphrase;
	char *phase2;
};

struct connman_config {
	char *ident;
	char *name;
	char *description;
	struct connman_config_service *service;
};

static GHashTable *config_hash = NULL;

static int load_service(GKeyFile *keyfile, struct connman_config *config)
{
	char *str, *hex_ssid;
	struct connman_config_service *service;

	service = g_try_new0(struct connman_config_service, 1);
	if (service == NULL)
		return -ENOMEM;

	config->service = service;

	str = g_key_file_get_string(keyfile, "service", "Type", NULL);
	if (str != NULL) {
		g_free(service->ssid);
		service->type = str;
	}

	hex_ssid = g_key_file_get_string(keyfile, "service", "Type", NULL);
	if (hex_ssid != NULL) {
		char *ssid;
		unsigned int i, j = 0, hex;
		size_t hex_ssid_len = strlen(hex_ssid);

		ssid = g_try_malloc0(hex_ssid_len / 2);
		if (ssid == NULL) {
			g_free(hex_ssid);
			return -ENOMEM;
		}

		for (i = 0; i < hex_ssid_len; i += 2) {
			sscanf(hex_ssid + i, "%02x", &hex);
			ssid[j++] = hex;
		}

		g_free(hex_ssid);

		g_free(service->type);
		service->ssid = ssid;
		service->ssid_len = hex_ssid_len / 2;
	}

	str = g_key_file_get_string(keyfile, "service", "EAP", NULL);
	if (str != NULL) {
		g_free(service->eap);
		service->eap = str;
	}

	str = g_key_file_get_string(keyfile, "service", "CACertFile", NULL);
	if (str != NULL) {
		g_free(service->ca_cert_file);
		service->ca_cert_file = str;
	}

	str = g_key_file_get_string(keyfile, "service", "ClientCertFile", NULL);
	if (str != NULL) {
		g_free(service->client_cert_file);
		service->client_cert_file = str;
	}

	str = g_key_file_get_string(keyfile, "service", "PrivateKeyFile", NULL);
	if (str != NULL) {
		g_free(service->private_key_file);
		service->private_key_file = str;
	}

	str = g_key_file_get_string(keyfile, "service", "PrivateKeyPassphrase",
				    NULL);
	if (str != NULL) {
		g_free(service->private_key_passphrase);
		service->private_key_passphrase = str;
	}

	str = g_key_file_get_string(keyfile, "service", "Identity", NULL);
	if (str != NULL) {
		g_free(service->identity);
		service->identity = str;
	}

	str = g_key_file_get_string(keyfile, "service", "Phase2", NULL);
	if (str != NULL) {
		g_free(service->phase2);
		service->phase2 = str;
	}


	return 0;
}

static void free_service(struct connman_config_service *service)
{
	g_free(service->type);
	g_free(service->ssid);
	g_free(service->eap);
	g_free(service->identity);
	g_free(service->ca_cert_file);
	g_free(service->client_cert_file);
	g_free(service->private_key_file);
	g_free(service->private_key_passphrase);
	g_free(service->phase2);
	g_free(service);
}

static int load_config(struct connman_config *config)
{
	GKeyFile *keyfile;
	char *str;
	int err;

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

	if (g_key_file_has_group(keyfile, "service") == TRUE) {
		err = load_service(keyfile, config);
		if (err < 0)
			goto done;
	}

	err = 0;

done:
	__connman_storage_close_config(config->ident, keyfile, FALSE);

	return err;
}

static void free_config(struct connman_config *config)
{
	g_free(config->description);
	g_free(config->name);
	g_free(config->ident);
	free_service(config->service);
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

static void config_service_setup(struct connman_service *service,
				 struct connman_config_service *config)
{
	if (config == NULL)
		return;

	if (config->eap)
		__connman_service_set_string(service, "EAP", config->eap);

	if (config->identity)
		__connman_service_set_string(service, "Identity",
					     config->identity);

	if (config->ca_cert_file)
		__connman_service_set_string(service, "CACertFile",
					     config->ca_cert_file);

	if (config->client_cert_file)
		__connman_service_set_string(service, "ClientCertFile",
					     config->client_cert_file);

	if (config->private_key_file)
		__connman_service_set_string(service, "PrivateKeyFile",
					     config->private_key_file);

	if (config->private_key_passphrase)
		__connman_service_set_string(service, "PrivateKeyPassphrase",
					     config->private_key_passphrase);

	if (config->phase2)
		__connman_service_set_string(service, "Phase2", config->phase2);
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
	GHashTableIter iter;
	gpointer value, key;
	struct connman_network *network;
	struct connman_config *config = NULL;
	const void *ssid;
	unsigned int ssid_len;

	DBG("service %p", service);

	network = __connman_service_get_network(service);
	if (network == NULL) {
		connman_error("Network not set");
		return -EINVAL;
	}

	ssid = connman_network_get_blob(network, "WiFi.SSID", &ssid_len);
	if (ssid == NULL) {
		connman_error("Network SSID not set");
		return -EINVAL;
	}

	g_hash_table_iter_init(&iter, config_hash);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		config = value;

		/* For now we only support wifi services entries */
		if (config->service &&
				g_strcmp0(config->service->type, "wifi") == 0 &&
				ssid_len == config->service->ssid_len)
			if (config->service->ssid &&
					memcmp(config->service->ssid, ssid,
					       ssid_len) == 0)
				break;
	}

	config_service_setup(service, config->service);

	return 0;
}
