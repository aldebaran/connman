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

#include <stdio.h>
#include <string.h>
#include <sys/vfs.h>
#include <glib.h>

#include "connman.h"

struct connman_config_service {
	char *ident;
	char *name;
	char *type;
	void *ssid;
	unsigned int ssid_len;
	char *eap;
	char *identity;
	char *ca_cert_file;
	char *client_cert_file;
	char *private_key_file;
	char *private_key_passphrase;
	char *private_key_passphrase_type;
	char *phase2;
};

struct connman_config {
	char *ident;
	char *name;
	char *description;
	GHashTable *service_table;
};

static GHashTable *config_table = NULL;

static void unregister_config(gpointer data)
{
	struct connman_config *config = data;

	connman_info("Removing configuration %s", config->ident);

	g_hash_table_destroy(config->service_table);

	g_free(config->description);
	g_free(config->name);
	g_free(config->ident);
	g_free(config);
}

static void unregister_service(gpointer data)
{
	struct connman_config_service *service = data;

	connman_info("Removing service configuration %s", service->ident);

	g_free(service->ident);
	g_free(service->type);
	g_free(service->name);
	g_free(service->ssid);
	g_free(service->eap);
	g_free(service->identity);
	g_free(service->ca_cert_file);
	g_free(service->client_cert_file);
	g_free(service->private_key_file);
	g_free(service->private_key_passphrase);
	g_free(service->private_key_passphrase_type);
	g_free(service->phase2);
	g_free(service);
}

static int load_service(GKeyFile *keyfile, const char *group,
						struct connman_config *config)
{
	struct connman_config_service *service;
	const char *ident;
	char *str, *hex_ssid;

	/* Strip off "service_" prefix */
	ident = group + 8;

	if (strlen(ident) < 1)
		return -EINVAL;

	service = g_hash_table_lookup(config->service_table, ident);
	if (service == NULL) {
		service = g_try_new0(struct connman_config_service, 1);
		if (service == NULL)
			return -ENOMEM;

		service->ident = g_strdup(ident);
	}

	str = g_key_file_get_string(keyfile, group, "Type", NULL);
	if (str != NULL) {
		g_free(service->type);
		service->type = str;
	}

	str = g_key_file_get_string(keyfile, group, "Name", NULL);
	if (str != NULL) {
		g_free(service->type);
		service->name = str;
	}

	hex_ssid = g_key_file_get_string(keyfile, group, "SSID", NULL);
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

		g_free(service->ssid);
		service->ssid = ssid;
		service->ssid_len = hex_ssid_len / 2;
	} else if (service->name != NULL) {
		char *ssid;
		unsigned int ssid_len;

		ssid_len = strlen(service->name);
		ssid = g_try_malloc0(ssid_len);
		if (ssid == NULL)
			return -ENOMEM;

		memcpy(ssid, service->name, ssid_len);
		g_free(service->ssid);
		service->ssid = ssid;
		service->ssid_len = ssid_len;
	}

	str = g_key_file_get_string(keyfile, group, "EAP", NULL);
	if (str != NULL) {
		g_free(service->eap);
		service->eap = str;
	}

	str = g_key_file_get_string(keyfile, group, "CACertFile", NULL);
	if (str != NULL) {
		g_free(service->ca_cert_file);
		service->ca_cert_file = str;
	}

	str = g_key_file_get_string(keyfile, group, "ClientCertFile", NULL);
	if (str != NULL) {
		g_free(service->client_cert_file);
		service->client_cert_file = str;
	}

	str = g_key_file_get_string(keyfile, group, "PrivateKeyFile", NULL);
	if (str != NULL) {
		g_free(service->private_key_file);
		service->private_key_file = str;
	}

	str = g_key_file_get_string(keyfile, group,
						"PrivateKeyPassphrase", NULL);
	if (str != NULL) {
		g_free(service->private_key_passphrase);
		service->private_key_passphrase = str;
	}

	str = g_key_file_get_string(keyfile, group,
					"PrivateKeyPassphraseType", NULL);
	if (str != NULL) {
		g_free(service->private_key_passphrase_type);
		service->private_key_passphrase_type = str;
	}

	str = g_key_file_get_string(keyfile, group, "Identity", NULL);
	if (str != NULL) {
		g_free(service->identity);
		service->identity = str;
	}

	str = g_key_file_get_string(keyfile, group, "Phase2", NULL);
	if (str != NULL) {
		g_free(service->phase2);
		service->phase2 = str;
	}

	g_hash_table_replace(config->service_table, service->ident, service);

	connman_info("Adding service configuration %s", service->ident);

	return 0;
}

static int load_config(struct connman_config *config)
{
	GKeyFile *keyfile;
	gsize length;
	char **groups;
	char *str;
	int i;

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

	groups = g_key_file_get_groups(keyfile, &length);

	for (i = 0; groups[i] != NULL; i++) {
		if (g_str_has_prefix(groups[i], "service_") == TRUE)
			load_service(keyfile, groups[i], config);
	}

	g_strfreev(groups);

	__connman_storage_close_config(config->ident, keyfile, FALSE);

	return 0;
}

static int create_config(const char *ident)
{
	struct connman_config *config;

	DBG("ident %s", ident);

	if (g_hash_table_lookup(config_table, ident) != NULL)
		return -EEXIST;

	config = g_try_new0(struct connman_config, 1);
	if (config == NULL)
		return -ENOMEM;

	config->ident = g_strdup(ident);

	config->service_table = g_hash_table_new_full(g_str_hash, g_str_equal,
						NULL, unregister_service);

	g_hash_table_insert(config_table, config->ident, config);

	connman_info("Adding configuration %s", config->ident);

	load_config(config);

	return 0;
}

static int read_configs(void)
{
	GDir *dir;

	DBG("");

	dir = g_dir_open(STORAGEDIR, 0, NULL);
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

	config_table = g_hash_table_new_full(g_str_hash, g_str_equal,
						NULL, unregister_config);

	return read_configs();
}

void __connman_config_cleanup(void)
{
	DBG("");

	g_hash_table_destroy(config_table);
	config_table = NULL;
}

static char *config_pem_fsid(const char *pem_file)
{
	struct statfs buf;
	unsigned *fsid = (unsigned *) &buf.f_fsid;
	unsigned long long fsid64;

	if (pem_file == NULL)
		return NULL;

	if (statfs(pem_file, &buf) < 0) {
		connman_error("statfs error %s for %s",
						strerror(errno), pem_file);
		return NULL;
	}

	fsid64 = ((unsigned long long) fsid[0] << 32) | fsid[1];

	return g_strdup_printf("%llx", fsid64);
}

static void provision_service(gpointer key, gpointer value, gpointer user_data)
{
	struct connman_service *service = user_data;
	struct connman_config_service *config = value;
	struct connman_network *network;
	const void *ssid;
	unsigned int ssid_len;

	/* For now only WiFi service entries are supported */
	if (g_strcmp0(config->type, "wifi") != 0)
		return;

	network = __connman_service_get_network(service);
	if (network == NULL) {
		connman_error("Service has no network set");
		return;
	}

	ssid = connman_network_get_blob(network, "WiFi.SSID", &ssid_len);
	if (ssid == NULL) {
		connman_error("Network SSID not set");
		return;
	}

	if (config->ssid == NULL || ssid_len != config->ssid_len)
		return;

	if (memcmp(config->ssid, ssid, ssid_len) != 0)
		return;

	__connman_service_set_immutable(service, TRUE);
	__connman_service_set_favorite(service, TRUE);

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

	if (g_strcmp0(config->private_key_passphrase_type, "fsid") == 0 &&
						config->private_key_file) {
		char *fsid;

		fsid = config_pem_fsid(config->private_key_file);
		if (fsid == NULL)
			return;

		g_free(config->private_key_passphrase);
		config->private_key_passphrase = fsid;
	}

	if (config->private_key_passphrase) {
		__connman_service_set_string(service, "PrivateKeyPassphrase",
						config->private_key_passphrase);
		/*
		 * TODO: Support for PEAP with both identity and key passwd.
		 * In that case, we should check if both of them are found
		 * from the config file. If not, we should not set the
		 * service passphrase in order for the UI to request for an
		 * additional passphrase.
		 */
		__connman_service_set_string(service, "Passphrase",
						config->private_key_passphrase);
	}

	if (config->phase2)
		__connman_service_set_string(service, "Phase2", config->phase2);
}

int __connman_config_provision_service(struct connman_service *service)
{
	enum connman_service_type type;
	GHashTableIter iter;
	gpointer value, key;

	DBG("service %p", service);

	/* For now only WiFi services are supported */
	type = connman_service_get_type(service);
	if (type != CONNMAN_SERVICE_TYPE_WIFI)
		return -ENOSYS;

	g_hash_table_iter_init(&iter, config_table);

	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		struct connman_config *config = value;

		g_hash_table_foreach(config->service_table,
						provision_service, service);
	}

	return 0;
}
