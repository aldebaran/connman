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
#include <gdbus.h>

#include "connman.h"

static DBusConnection *connection = NULL;

static GHashTable *provider_hash = NULL;

static GSList *driver_list = NULL;

struct connman_provider {
	struct connman_element element;
	struct connman_service *vpn_service;
	char *identifier;
	char *name;
	char *type;
	char *dns;
	char *domain;
	struct connman_provider_driver *driver;
	void *driver_data;
};

void __connman_provider_append_properties(struct connman_provider *provider,
							DBusMessageIter *iter)
{
	dbus_bool_t required;

	if (provider->name != NULL)
		connman_dbus_dict_append_basic(iter, "Name",
					DBUS_TYPE_STRING, &provider->name);

	if (provider->type != NULL)
		connman_dbus_dict_append_basic(iter, "Type", DBUS_TYPE_STRING,
						 &provider->type);

	required = TRUE;
	connman_dbus_dict_append_basic(iter, "PassphraseRequired",
					 DBUS_TYPE_BOOLEAN, &required);
}

static void append_path(gpointer key, gpointer value, gpointer user_data)
{
	struct connman_provider *provider = value;
	DBusMessageIter *iter = user_data;
	const char *service_path;

	service_path = __connman_service_get_path(provider->vpn_service);
	if (service_path == NULL)
		return;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH,
							&service_path);
}

void __connman_provider_list(DBusMessageIter *iter, void *user_data)
{
	g_hash_table_foreach(provider_hash, append_path, iter);
}

static struct connman_provider *connman_provider_lookup(const char *identifier)
{
	struct connman_provider *provider = NULL;

	provider = g_hash_table_lookup(provider_hash, identifier);

	return provider;
}

static void connman_provider_setup_vpn_ipv4(struct connman_provider *provider,
						struct connman_element *element)
{
	if (element == NULL || provider == NULL)
		return;

	DBG("set vpn type %d", element->type);

	if (provider == NULL)
		return;

	g_free(element->ipv4.address);
	element->ipv4.address = g_strdup(provider->element.ipv4.address);

	g_free(element->ipv4.netmask);
	element->ipv4.netmask = g_strdup(provider->element.ipv4.netmask);

	g_free(element->ipv4.gateway);
	element->ipv4.gateway = g_strdup(provider->element.ipv4.gateway);

	g_free(element->ipv4.broadcast);
	element->ipv4.broadcast = g_strdup(provider->element.ipv4.broadcast);

	g_free(element->ipv4.pac);
	element->ipv4.pac = g_strdup(provider->element.ipv4.pac);

	DBG("VPN exist");
}

struct connman_provider *connman_provider_ref(struct connman_provider *provider)
{
	DBG("provider %p", provider);

	if (connman_element_ref(&provider->element) == NULL)
		return NULL;

	return provider;
}

void connman_provider_unref(struct connman_provider *provider)
{
	DBG("provider %p", provider);

	connman_element_unref(&provider->element);
}

static gboolean match_driver(struct connman_provider *provider,
				struct connman_provider_driver *driver)
{
	if (g_strcmp0(driver->name, provider->type) == 0)
		return TRUE;

	return FALSE;
}

static int provider_probe(struct connman_provider *provider)
{
	GSList *list;

	DBG("provider %p name %s", provider, provider->name);

	if (provider->driver != NULL)
		return -EALREADY;

	for (list = driver_list; list; list = list->next) {
		struct connman_provider_driver *driver = list->data;

		if (match_driver(provider, driver) == FALSE)
			continue;

		DBG("driver %p name %s", driver, driver->name);

		if (driver->probe != NULL && driver->probe(provider) == 0) {
			provider->driver = driver;
			break;
		}
	}

	if (provider->driver == NULL)
		return -ENODEV;

	return 0;
}

int __connman_provider_disconnect(struct connman_provider *provider)
{
	int err;

	DBG("provider %p", provider);

	if (provider->driver != NULL && provider->driver->disconnect != NULL)
		err = provider->driver->disconnect(provider);
	else
		return -EOPNOTSUPP;

	__connman_service_indicate_state(provider->vpn_service,
					CONNMAN_SERVICE_STATE_DISCONNECT);
	if (err < 0) {
		if (err != -EINPROGRESS)
			return err;

		return -EINPROGRESS;
	}

	return 0;
}

int __connman_provider_connect(struct connman_provider *provider)
{
	int err;

	DBG("provider %p", provider);

	g_free(provider->element.ipv4.address);
	g_free(provider->element.ipv4.netmask);
	g_free(provider->element.ipv4.gateway);
	g_free(provider->element.ipv4.broadcast);
	g_free(provider->element.ipv4.pac);

	provider->element.ipv4.address = NULL;
	provider->element.ipv4.netmask = NULL;
	provider->element.ipv4.gateway = NULL;
	provider->element.ipv4.broadcast = NULL;
	provider->element.ipv4.pac = NULL;

	if (provider->driver != NULL && provider->driver->connect != NULL)
		err = provider->driver->connect(provider);
	else
		return -EOPNOTSUPP;

	if (err < 0) {
		if (err != -EINPROGRESS)
			return err;

		__connman_service_indicate_state(provider->vpn_service,
					CONNMAN_SERVICE_STATE_ASSOCIATION);
		return -EINPROGRESS;
	}

	return 0;
}

int __connman_provider_remove(const char *path)
{
	struct connman_provider *provider;

	DBG("path %s", path);

	provider = g_hash_table_lookup(provider_hash, path);
	if (provider == NULL) {
		DBG("patch %s not found", path);
		return -ENXIO;
	}

	g_hash_table_remove(provider_hash, path);

	return 0;
}

int connman_provider_set_connected(struct connman_provider *provider,
						connman_bool_t connected)
{
	if (connected == TRUE) {
		enum connman_element_type type = CONNMAN_ELEMENT_TYPE_UNKNOWN;
		struct connman_element *element;

		type = CONNMAN_ELEMENT_TYPE_IPV4;

		element = connman_element_create(NULL);
		if (element != NULL) {
			element->type  = type;
			element->index = provider->element.index;

			connman_provider_setup_vpn_ipv4(provider, element);

			if (connman_element_register(element,
					&provider->element) < 0)
				connman_element_unref(element);
			else {
				char *nameservers = NULL;
				const char *value;
				char *name = NULL;

				DBG("set dns");
				nameservers = g_strdup(provider->dns);
				value = nameservers;
				name = connman_inet_ifname(
						provider->element.index);
				while (value) {
					char *next = strchr(value, ' ');
					if (next)
						*(next++) = 0;

					connman_resolver_append(name,
							provider->domain,
							value);
					value = next;
				}
				DBG("free extra");
				g_free(nameservers);
				g_free(name);
			}

		}
		__connman_service_indicate_state(provider->vpn_service,
						CONNMAN_SERVICE_STATE_READY);
	} else {
		connman_element_unregister_children(&provider->element);
		__connman_service_indicate_state(provider->vpn_service,
						CONNMAN_SERVICE_STATE_IDLE);
	}

	return 0;
}

static void provider_free(gpointer user_data)
{
	struct connman_provider *provider = user_data;

	DBG("provider %p", provider);

	g_free(provider->name);
	g_free(provider->type);
	g_free(provider->domain);
	g_free(provider->identifier);
	g_free(provider->dns);
	__connman_service_put(provider->vpn_service);
}

static void unregister_provider(gpointer data)
{
	struct connman_provider *provider = data;

	DBG("provider %p", provider);

	__connman_provider_disconnect(provider);

	connman_element_unregister(&provider->element);
	connman_provider_unref(provider);
}

static void provider_destruct(struct connman_element *element)
{
	struct connman_provider *provider = element->private;

	DBG("provider %p", provider);

	provider_free(provider);
}

static void __connman_provider_initialize(struct connman_provider *provider)
{
	DBG("provider %p", provider);

	__connman_element_initialize(&provider->element);

	provider->element.private = provider;
	provider->element.destruct = provider_destruct;

	provider->element.ipv4.address = NULL;
	provider->element.ipv4.netmask = NULL;
	provider->element.ipv4.gateway = NULL;
	provider->element.ipv4.broadcast = NULL;
	provider->element.ipv4.pac = NULL;

	provider->name = NULL;
	provider->type = NULL;
	provider->dns = NULL;
	provider->domain = NULL;
	provider->identifier = NULL;
}

static struct connman_provider *connman_provider_new(void)
{
	struct connman_provider *provider;

	provider = g_try_new0(struct connman_provider, 1);
	if (provider == NULL)
		return NULL;

	DBG("provider %p", provider);
	__connman_provider_initialize(provider);

	return provider;
}

static int provider_register(struct connman_provider *provider)
{
	DBG("provider %p", provider);

	return 0;
}

static struct connman_provider *connman_provider_get(const char *identifier)
{
	struct connman_provider *provider;

	provider = g_hash_table_lookup(provider_hash, identifier);
	if (provider != NULL)
		return provider;

	provider = connman_provider_new();
	if (provider == NULL)
		return NULL;

	DBG("provider %p", provider);

	provider->identifier = g_strdup(identifier);

	g_hash_table_insert(provider_hash, provider->identifier, provider);

	provider->element.name = g_strdup(identifier);
	connman_element_register(&provider->element, NULL);

	return provider;
}

static struct connman_provider *connman_provider_create(const char *name)
{
	struct connman_provider *provider;

	provider = connman_provider_get(name);

	if (provider == NULL)
		return NULL;

	provider_register(provider);

	return provider;
}

int __connman_provider_create_and_connect(DBusMessage *msg)
{
	struct connman_provider *provider;
	DBusMessageIter iter, array;
	const char *type = NULL, *name = NULL, *service_path = NULL;
	char *ident;
	gboolean created = FALSE;
	int err;

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_recurse(&iter, &array);

	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;

		dbus_message_iter_recurse(&array, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		switch (dbus_message_iter_get_arg_type(&value)) {
		case DBUS_TYPE_STRING:
			if (g_str_equal(key, "Type") == TRUE)
				dbus_message_iter_get_basic(&value, &type);
			else if (g_str_equal(key, "Name") == TRUE)
				dbus_message_iter_get_basic(&value, &name);
			break;
		}

		if (type != NULL && name != NULL)
			break;

		dbus_message_iter_next(&array);
	}

	DBG("Type %s name %s", type, name);

	if (type == NULL || name == NULL) {
		err = -EOPNOTSUPP;
		goto failed;
	}

	ident = g_strdup_printf("%s_%s", type, name);

	provider = connman_provider_lookup(ident);

	if (provider == NULL) {
		created = TRUE;
		provider = connman_provider_create(ident);
		if (provider) {
			provider->name = g_strdup(name);
			provider->type = g_strdup(type);
		}
	}

	if (provider == NULL) {
		DBG("can not create provider");
		err = -EOPNOTSUPP;
		goto failed;
	}
	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_recurse(&iter, &array);

	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key, *str;

		dbus_message_iter_recurse(&array, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		switch (dbus_message_iter_get_arg_type(&value)) {
		case DBUS_TYPE_STRING:
			dbus_message_iter_get_basic(&value, &str);
			connman_provider_set_string(provider, key, str);
			break;
		}

		dbus_message_iter_next(&array);
	}

	g_free(ident);

	if (provider == NULL) {
		err = -EOPNOTSUPP;
		goto failed;
	}

	if (created == TRUE)
		provider_probe(provider);

	provider->vpn_service =
			__connman_service_create_from_provider(provider);
	if (provider->vpn_service == NULL) {
		err = -EOPNOTSUPP;
		goto failed;
	}

	err = __connman_service_connect(provider->vpn_service);
	if (err < 0 && err != -EINPROGRESS)
		goto failed;

	service_path = __connman_service_get_path(provider->vpn_service);
	g_dbus_send_reply(connection, msg,
				DBUS_TYPE_OBJECT_PATH, &service_path,
							DBUS_TYPE_INVALID);
	return 0;

failed:
	if (provider != NULL && created == TRUE) {
		DBG("can not connect delete provider");
		connman_provider_unref(provider);

		if (provider->vpn_service != NULL)
			__connman_service_put(provider->vpn_service);
	}

	return err;
}

const char * __connman_provider_get_ident(struct connman_provider *provider)
{
	if (provider == NULL)
		return NULL;

	return provider->identifier;
}

int connman_provider_set_string(struct connman_provider *provider,
					const char *key, const char *value)
{
	DBG("provider %p key %s value %s", provider, key, value);

	if (g_str_equal(key, "Type") == TRUE) {
		g_free(provider->type);
		provider->type = g_strdup(value);
	} else if (g_str_equal(key, "Name") == TRUE) {
		g_free(provider->name);
		provider->name = g_strdup(value);
	} else if (g_str_equal(key, "Gateway") == TRUE) {
		g_free(provider->element.ipv4.gateway);
		provider->element.ipv4.gateway = g_strdup(value);
	} else if (g_str_equal(key, "Address") == TRUE) {
		g_free(provider->element.ipv4.address);
		provider->element.ipv4.address = g_strdup(value);
	} else if (g_str_equal(key, "Netmask") == TRUE) {
		g_free(provider->element.ipv4.netmask);
		provider->element.ipv4.netmask = g_strdup(value);
	} else if (g_str_equal(key, "PAC") == TRUE) {
		g_free(provider->element.ipv4.pac);
		provider->element.ipv4.pac = g_strdup(value);
	} else if (g_str_equal(key, "DNS") == TRUE) {
		g_free(provider->dns);
		provider->dns = g_strdup(value);
	} else if (g_str_equal(key, "Domain") == TRUE) {
		g_free(provider->domain);
		provider->domain = g_strdup(value);
	}

	return connman_element_set_string(&provider->element, key, value);
}

const char *connman_provider_get_string(struct connman_provider *provider,
							const char *key)
{
	DBG("provider %p key %s", provider, key);

	if (g_str_equal(key, "Type") == TRUE)
		return provider->type;
	else if (g_str_equal(key, "Name") == TRUE)
		return provider->name;

	return connman_element_get_string(&provider->element, key);
}

void *connman_provider_get_data(struct connman_provider *provider)
{
	return provider->driver_data;
}

void connman_provider_set_data(struct connman_provider *provider, void *data)
{
	provider->driver_data = data;
}

void connman_provider_set_index(struct connman_provider *provider, int index)
{
	provider->element.index = index;
}

int connman_provider_get_index(struct connman_provider *provider)
{
	return provider->element.index;
}

static gint compare_priority(gconstpointer a, gconstpointer b)
{
	return 0;
}

static void clean_provider(gpointer key, gpointer value, gpointer user_data)
{
	struct connman_provider *provider = value;

	if (provider->driver != NULL && provider->driver->remove)
		provider->driver->remove(provider);
}

int connman_provider_driver_register(struct connman_provider_driver *driver)
{
	DBG("driver %p name %s", driver, driver->name);

	driver_list = g_slist_insert_sorted(driver_list, driver,
							compare_priority);
	return 0;
}

void connman_provider_driver_unregister(struct connman_provider_driver *driver)
{
	DBG("driver %p name %s", driver, driver->name);

	driver_list = g_slist_remove(driver_list, driver);
}

int __connman_provider_init(void)
{
	DBG("");

	connection = connman_dbus_get_connection();

	provider_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						NULL, unregister_provider);
	return 0;
}

void __connman_provider_cleanup(void)
{
	DBG("");

	g_hash_table_foreach(provider_hash, clean_provider, NULL);

	g_hash_table_destroy(provider_hash);
	provider_hash = NULL;

	dbus_connection_unref(connection);
}
