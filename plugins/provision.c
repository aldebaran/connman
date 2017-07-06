/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2017  SoftBank Robotics. All rights reserved.
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
 * This plugin implement an interface to create provision config used for WPA
 * enterprise.
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <gdbus.h>
#include <glib.h>
#include <string.h>
#include <unistd.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/dbus.h>
#include <connman/storage.h>

#define CONNMAN_PROVISION_INTERFACE "net.connman.Provision"

const char *keys[] = {"Name", "EAP", "CACertFile", "ClientCertFile",
		      "Phase2", "Passphrase", "Identity", 0};

static DBusMessage *error_invalid_arguments(DBusMessage *msg)
{
	return g_dbus_create_error(msg, "net.connman.provision.Error"
					".InvalidArguments", "Invalid arguments");
}

static char *get_path(const char *ident)
{
	return g_strdup_printf("%s/service_%s.config", STORAGEDIR, ident);
}

static DBusMessage *provision_get(DBusConnection *conn,
				  DBusMessage *msg, void *user_data)
{
	const char *ident, *key;
	char *path, *category = 0, *str;
	GKeyFile *file = 0;
	GError *error = 0;
	DBusMessage *reply = 0;
	DBusMessageIter array, dict;
	int i;

	DBG("");
	dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &ident,
			      DBUS_TYPE_INVALID);

	DBG("%s", ident);
	file = g_key_file_new();
	path = get_path(ident);
	if (!g_key_file_load_from_file(file, path, G_KEY_FILE_NONE, &error)) {
		connman_error("Fail to load config %s", path);
		goto fail;
	};
	category = g_strdup_printf("service_%s", ident);
	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &array);
	connman_dbus_dict_open(&array, &dict);
	connman_dbus_dict_append_basic(&dict, "Name",
				       DBUS_TYPE_STRING, &ident);
	for (i = 0; keys[i] != 0; i++) {
		key = keys[i];
		/* Filter out Passphrase for privacy */
		if (!g_strcmp0(key, "Passphrase"))
			continue;
		str = g_key_file_get_string(file, category, key, &error);
		if (error != 0) {
			g_clear_error(&error);
			continue;
		}
		connman_dbus_dict_append_basic(&dict, key,
					       DBUS_TYPE_STRING, &str);
	}
	connman_dbus_dict_close(&array, &dict);

fail:
	g_free(path);
	g_free(category);
	g_key_file_free(file);
	if (!reply)
		reply = g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
	return reply;
}

struct wpa_entreprise_creds {
	char *name;
	char *eap;
	char *phase2;
	char *cacertfile;
	char *clientcertfile;
	char *identity;
	char *passphrase;
};

static int eap_is_valid(const char *eap)
{
	return (!g_strcmp0(eap, "tls") || !g_strcmp0(eap, "ttls")
		|| !g_strcmp0(eap, "peap"));
}

static int creds_is_valid(struct wpa_entreprise_creds *creds)
{
	return (creds->name && eap_is_valid(creds->eap)
		&& creds->identity && creds ->passphrase);
}

/* TODO: see why compiler isn't happy when using bool as type */
static int parse_provision_creds(struct wpa_entreprise_creds *creds,
				 DBusMessageIter *iter)
{
	DBusMessageIter subiter, dictiter, variantiter;
	dbus_message_iter_recurse(iter, &subiter);
	do {
		char *key;
		char *value;

		int type = dbus_message_iter_get_arg_type(&subiter);
		if (type == DBUS_TYPE_INVALID)
			break;
		dbus_message_iter_recurse(&subiter, &dictiter);
		/*Parse key */
		dbus_message_iter_get_basic(&dictiter, &key);
		if (!dbus_message_iter_next(&dictiter))
			return -1;
		if (dbus_message_iter_get_arg_type(&dictiter) !=
		    DBUS_TYPE_VARIANT)
			return -1;
		dbus_message_iter_recurse(&dictiter, &variantiter);
		dbus_message_iter_get_basic(&variantiter, &value);

		if (!g_strcmp0(key, "Name"))
			creds->name = value;
		else if (!g_strcmp0(key, "EAP"))
			creds->eap = value;
		else if (!g_strcmp0(key, "Phase2"))
			creds->phase2 = value;
		else if (!g_strcmp0(key, "CACertFile"))
			creds->cacertfile = value;
		else if(!g_strcmp0(key, "ClientCertFile"))
			creds->clientcertfile = value;
		else if(!g_strcmp0(key, "Passphrase"))
			creds->passphrase = value;
		else if(!g_strcmp0(key, "Identity"))
			creds->identity = value;
		else {
			connman_error("Invalid property: %s", key);
			return -1;
		}
		dbus_message_iter_next(&subiter);
	} while (1);
	return 0;
}

static DBusMessage *provision_set(DBusConnection *conn,
				  DBusMessage *msg, void *user_data)
{
	DBusMessageIter iter;
	GError *error = 0;
	char *category = 0, *path = 0;
	GKeyFile *keyfile;
	struct wpa_entreprise_creds creds;

	memset(&creds, 0, sizeof(struct wpa_entreprise_creds));

	dbus_message_iter_init(msg, &iter);
	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
	    dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_DICT_ENTRY)
		return error_invalid_arguments(msg);
	if (parse_provision_creds(&creds, &iter))
		return error_invalid_arguments(msg);
	if (!creds_is_valid(&creds))
		return error_invalid_arguments(msg);

	keyfile = g_key_file_new();

	g_key_file_set_string(keyfile, "global", "Name", creds.name);
	g_key_file_set_string(keyfile, "global", "Description",
			      "auto generated do not edit.");

	category = g_strdup_printf("service_%s", creds.name);
	g_key_file_set_string(keyfile, category, "Name", creds.name);
	g_key_file_set_string(keyfile, category, "Type", "wifi");
	g_key_file_set_string(keyfile, category, "EAP", creds.eap);
	g_key_file_set_string(keyfile, category, "Phase2", creds.phase2);
	g_key_file_set_string(keyfile, category, "Identity", creds.identity);
	g_key_file_set_string(keyfile, category, "Passphrase", creds.passphrase);
	if (creds.cacertfile)
		g_key_file_set_string(keyfile, category,
				      "CACertFile", creds.cacertfile);
	if (creds.clientcertfile)
		g_key_file_set_string(keyfile, category,
				      "ClientCertFile", creds.clientcertfile);
	path = get_path(creds.name);
	g_key_file_save_to_file(keyfile, path, &error);
	if (error) {
		connman_error("Fail to save file: %s error: %s", path, error->message);
		g_clear_error(&error);
	}

	g_free(path);
	g_key_file_free(keyfile);
	g_free(category);
	return dbus_message_new_method_return(msg);
}

static DBusMessage *provision_list(DBusConnection *conn,
				   DBusMessage *msg, void *user_data)
{
	DBusMessageIter list, entry;
	DBusMessage *reply = 0;

	struct dirent *d;
	DIR *dir;
	unsigned int prelen, sulen;

	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &list);

	dbus_message_iter_open_container(&list, DBUS_TYPE_ARRAY,
					 DBUS_TYPE_STRING_AS_STRING, &entry);

	prelen = strlen("service_");
	sulen = strlen(".config");

	dir = opendir(STORAGEDIR);
	while ((d = readdir(dir))) {
		char *name;
		/* only look for regular file */
		if (d->d_type != DT_REG)
			continue;
		/* only look at */
		if (g_str_has_prefix(d->d_name, "service_") == FALSE ||
		    g_str_has_suffix(d->d_name, ".config") == FALSE)
			continue;
		/* cut .config sufix */
		d->d_name[strlen(d->d_name) - sulen] = '\0';
		/* skip prefix */
		name = d->d_name + prelen;
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING,
					       &name);
	}

	dbus_message_iter_close_container(&list, &entry);
	return reply;
}

static DBusMessage *provision_del(DBusConnection *conn,
				  DBusMessage *msg, void *user_data)
{
	const char *name;
	char *path;
	DBusMessage *reply = 0;

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &name,
				  DBUS_TYPE_INVALID) == FALSE)
		return error_invalid_arguments(msg);

	path = get_path(name);
	if (unlink(path))
		reply = g_dbus_create_error(msg, "net.connman.provision.Error"
						 ".EIO", "Fail to delete file");
	g_free(path);
	if (!reply)
		reply = dbus_message_new_method_return(msg);
	return reply;
}

static const GDBusMethodTable service_methods[] = {
	{ GDBUS_METHOD("Get",
	  GDBUS_ARGS({ "name", "s" }),
	  GDBUS_ARGS({ "properties", "a{sv}" }),
	  provision_get) },
	{ GDBUS_METHOD("Set",
	  GDBUS_ARGS({ "value", "a{sv}" }),
	  NULL, provision_set) },
	{ GDBUS_METHOD("List",
	  NULL,
	  GDBUS_ARGS({ "value", "as" }),
	  provision_list) },
	{ GDBUS_METHOD("Del",
	  GDBUS_ARGS({ "name", "s" }),
	  NULL, provision_del) },
	{ },
};

static const GDBusSignalTable service_signals[] = {
	{ },
};

static int provision_init(void)
{
	DBusConnection *connection;

	DBG("Provision system");
	connman_info("Provision System API");

	connection = connman_dbus_get_connection();
	g_dbus_register_interface(connection, "/",
				  CONNMAN_PROVISION_INTERFACE,
				  service_methods, service_signals,
				  NULL, NULL, NULL);
	return 0;
}

static void provision_exit(void)
{
	DBusConnection *connection;

	connection = connman_dbus_get_connection();
	g_dbus_unregister_interface(connection, "/",
				    CONNMAN_PROVISION_INTERFACE);
}

CONNMAN_PLUGIN_DEFINE(provision, "Provision API for SBR product", VERSION,
		      CONNMAN_PLUGIN_PRIORITY_DEFAULT, provision_init, provision_exit)
