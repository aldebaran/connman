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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gdbus.h>

#include "connman.h"

static DBusConnection *connection = NULL;

static GHashTable *provider_hash = NULL;

static GSList *driver_list = NULL;

struct connman_route {
	int family;
	char *host;
	char *netmask;
	char *gateway;
};

struct connman_provider {
	int refcount;
	struct connman_service *vpn_service;
	int index;
	char *identifier;
	char *name;
	char *type;
	char *host;
	char *domain;
	int family;
	GHashTable *routes;
	struct connman_provider_driver *driver;
	void *driver_data;
	GHashTable *setting_strings;
};

void __connman_provider_append_properties(struct connman_provider *provider,
							DBusMessageIter *iter)
{
	if (provider->host != NULL)
		connman_dbus_dict_append_basic(iter, "Host",
					DBUS_TYPE_STRING, &provider->host);

	if (provider->domain != NULL)
		connman_dbus_dict_append_basic(iter, "Domain",
					DBUS_TYPE_STRING, &provider->domain);

	if (provider->type != NULL)
		connman_dbus_dict_append_basic(iter, "Type", DBUS_TYPE_STRING,
						 &provider->type);
}

static int provider_load_from_keyfile(struct connman_provider *provider,
		GKeyFile *keyfile)
{
	gsize idx = 0;
	gchar **settings;
	gchar *key, *value;
	gsize length;

	settings = g_key_file_get_keys(keyfile, provider->identifier, &length,
				NULL);
	if (settings == NULL) {
		g_key_file_free(keyfile);
		return -ENOENT;
	}

	while (idx < length) {
		key = settings[idx];
		if (key != NULL) {
			value = g_key_file_get_string(keyfile,
						provider->identifier,
						key, NULL);
			connman_provider_set_string(provider, key, value);
			g_free(value);
		}
		idx += 1;
	}
	g_strfreev(settings);

	return 0;
}

static int connman_provider_load(struct connman_provider *provider)
{
	GKeyFile *keyfile;

	DBG("provider %p", provider);

	keyfile = __connman_storage_load_provider(provider->identifier);
	if (keyfile == NULL)
		return -ENOENT;

	provider_load_from_keyfile(provider, keyfile);

	g_key_file_free(keyfile);
	return 0;
}

static int connman_provider_save(struct connman_provider *provider)
{
	GKeyFile *keyfile;

	DBG("provider %p", provider);

	keyfile = g_key_file_new();
	if (keyfile == NULL)
		return -ENOMEM;

	g_key_file_set_string(keyfile, provider->identifier,
			"Name", provider->name);
	g_key_file_set_string(keyfile, provider->identifier,
			"Type", provider->type);
	g_key_file_set_string(keyfile, provider->identifier,
			"Host", provider->host);
	g_key_file_set_string(keyfile, provider->identifier,
			"VPN.Domain", provider->domain);

	if (provider->driver != NULL && provider->driver->save != NULL)
		provider->driver->save(provider, keyfile);

	__connman_storage_save_provider(keyfile, provider->identifier);
        g_key_file_free(keyfile);

	return 0;
}

static struct connman_provider *connman_provider_lookup(const char *identifier)
{
	struct connman_provider *provider = NULL;

	provider = g_hash_table_lookup(provider_hash, identifier);

	return provider;
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

static void provider_remove(struct connman_provider *provider)
{
	if (provider->driver != NULL) {
		provider->driver->remove(provider);
		provider->driver = NULL;
	}
}

static int provider_register(struct connman_provider *provider)
{
	connman_provider_load(provider);
	return provider_probe(provider);
}

static void provider_unregister(struct connman_provider *provider)
{
	provider_remove(provider);
}

struct connman_provider *
connman_provider_ref_debug(struct connman_provider *provider,
			const char *file, int line, const char *caller)
{
	DBG("%p ref %d by %s:%d:%s()", provider, provider->refcount + 1,
		file, line, caller);

	__sync_fetch_and_add(&provider->refcount, 1);

	return provider;
}

static void provider_destruct(struct connman_provider *provider)
{
	DBG("provider %p", provider);

	g_free(provider->name);
	g_free(provider->type);
	g_free(provider->host);
	g_free(provider->domain);
	g_free(provider->identifier);
	g_hash_table_destroy(provider->routes);
	g_hash_table_destroy(provider->setting_strings);
}

void connman_provider_unref_debug(struct connman_provider *provider,
				const char *file, int line, const char *caller)
{
	DBG("%p ref %d by %s:%d:%s()", provider, provider->refcount - 1,
		file, line, caller);

	if (__sync_fetch_and_sub(&provider->refcount, 1) != 1)
		return;

	provider_remove(provider);

	provider_destruct(provider);
}

static int provider_indicate_state(struct connman_provider *provider,
					enum connman_service_state state)
{
	DBG("state %d", state);

	__connman_service_ipconfig_indicate_state(provider->vpn_service, state,
					CONNMAN_IPCONFIG_TYPE_IPV4);

	return __connman_service_ipconfig_indicate_state(provider->vpn_service,
					state, CONNMAN_IPCONFIG_TYPE_IPV6);
}

int __connman_provider_disconnect(struct connman_provider *provider)
{
	int err;

	DBG("provider %p", provider);

	if (provider->driver != NULL && provider->driver->disconnect != NULL)
		err = provider->driver->disconnect(provider);
	else
		return -EOPNOTSUPP;

	if (provider->vpn_service != NULL)
		provider_indicate_state(provider,
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

	if (provider->driver != NULL && provider->driver->connect != NULL)
		err = provider->driver->connect(provider);
	else
		return -EOPNOTSUPP;

	if (err < 0) {
		if (err != -EINPROGRESS)
			return err;

		provider_indicate_state(provider,
					CONNMAN_SERVICE_STATE_ASSOCIATION);

		return -EINPROGRESS;
	}

	return 0;
}

int __connman_provider_remove(const char *path)
{
	struct connman_provider *provider;
	GHashTableIter iter;
	gpointer value, key;

	DBG("path %s", path);

	g_hash_table_iter_init(&iter, provider_hash);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		const char *srv_path;
		provider = value;

		if (provider->vpn_service == NULL)
			continue;

		srv_path = __connman_service_get_path(provider->vpn_service);

		if (g_strcmp0(srv_path, path) == 0) {
			DBG("Removing VPN %s", provider->identifier);

			provider_unregister(provider);
			g_hash_table_remove(provider_hash,
						provider->identifier);
			return 0;
		}
	}

	return -ENXIO;
}

static void provider_append_routes(gpointer key, gpointer value,
					gpointer user_data)
{
	struct connman_route *route = value;
	struct connman_provider *provider = user_data;
	int index = provider->index;

	if (route->family == AF_INET6) {
		unsigned char prefix_len = atoi(route->netmask);

		connman_inet_add_ipv6_network_route(index, route->host,
							route->gateway,
							prefix_len);
	} else {
		connman_inet_add_network_route(index, route->host,
						route->gateway,
						route->netmask);
	}
}

static int set_connected(struct connman_provider *provider,
					connman_bool_t connected)
{
	struct connman_service *service = provider->vpn_service;
	struct connman_ipconfig *ipconfig;

	if (service == NULL)
		return -ENODEV;

	ipconfig = __connman_service_get_ipconfig(service, provider->family);

	if (connected == TRUE) {
		if (ipconfig == NULL) {
			provider_indicate_state(provider,
						CONNMAN_SERVICE_STATE_FAILURE);
			return -EIO;
		}

		__connman_ipconfig_address_add(ipconfig);
		__connman_ipconfig_gateway_add(ipconfig);

		provider_indicate_state(provider,
					CONNMAN_SERVICE_STATE_READY);

		g_hash_table_foreach(provider->routes, provider_append_routes,
					provider);

	} else {
		if (ipconfig != NULL) {
			provider_indicate_state(provider,
					CONNMAN_SERVICE_STATE_DISCONNECT);
			__connman_ipconfig_gateway_remove(ipconfig);
		}

		provider_indicate_state(provider,
					CONNMAN_SERVICE_STATE_IDLE);
	}

	return 0;
}

int connman_provider_set_state(struct connman_provider *provider,
					enum connman_provider_state state)
{
	if (provider == NULL || provider->vpn_service == NULL)
		return -EINVAL;

	switch (state) {
	case CONNMAN_PROVIDER_STATE_UNKNOWN:
		return -EINVAL;
	case CONNMAN_PROVIDER_STATE_IDLE:
		return set_connected(provider, FALSE);
	case CONNMAN_PROVIDER_STATE_CONNECT:
		return provider_indicate_state(provider,
					CONNMAN_SERVICE_STATE_ASSOCIATION);
	case CONNMAN_PROVIDER_STATE_READY:
		return set_connected(provider, TRUE);
	case CONNMAN_PROVIDER_STATE_DISCONNECT:
		return provider_indicate_state(provider,
					CONNMAN_SERVICE_STATE_DISCONNECT);
	case CONNMAN_PROVIDER_STATE_FAILURE:
		return provider_indicate_state(provider,
					CONNMAN_SERVICE_STATE_FAILURE);
	}

	return -EINVAL;
}

int connman_provider_indicate_error(struct connman_provider *provider,
					enum connman_provider_error error)
{
	enum connman_service_error service_error;
	const char *path;
	int ret;

	switch (error) {
	case CONNMAN_PROVIDER_ERROR_LOGIN_FAILED:
		service_error = CONNMAN_SERVICE_ERROR_LOGIN_FAILED;
		break;
	case CONNMAN_PROVIDER_ERROR_AUTH_FAILED:
		service_error = CONNMAN_SERVICE_ERROR_AUTH_FAILED;
		break;
	case CONNMAN_PROVIDER_ERROR_CONNECT_FAILED:
		service_error = CONNMAN_SERVICE_ERROR_CONNECT_FAILED;
		break;
	default:
		service_error = CONNMAN_SERVICE_ERROR_UNKNOWN;
		break;
	}

	ret = __connman_service_indicate_error(provider->vpn_service,
							service_error);
	path = __connman_service_get_path(provider->vpn_service);
	__connman_provider_remove(path);

	return ret;
}

static void unregister_provider(gpointer data)
{
	struct connman_provider *provider = data;

	DBG("provider %p service %p", provider, provider->vpn_service);

	if (provider->vpn_service != NULL) {
		connman_service_unref(provider->vpn_service);
		provider->vpn_service = NULL;
	}

	connman_provider_unref(provider);
}

static void destroy_route(gpointer user_data)
{
	struct connman_route *route = user_data;

	g_free(route->host);
	g_free(route->netmask);
	g_free(route->gateway);
	g_free(route);
}

static void provider_initialize(struct connman_provider *provider)
{
	DBG("provider %p", provider);

	provider->index = 0;
	provider->name = NULL;
	provider->type = NULL;
	provider->domain = NULL;
	provider->identifier = NULL;
	provider->routes = g_hash_table_new_full(g_direct_hash, g_direct_equal,
					NULL, destroy_route);
	provider->setting_strings = g_hash_table_new_full(g_str_hash, g_str_equal,
							g_free, g_free);
}

static struct connman_provider *connman_provider_new(void)
{
	struct connman_provider *provider;

	provider = g_try_new0(struct connman_provider, 1);
	if (provider == NULL)
		return NULL;

	provider->refcount = 1;

	DBG("provider %p", provider);
	provider_initialize(provider);

	return provider;
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

	return provider;
}

static void provider_dbus_ident(char *ident)
{
	int i, len = strlen(ident);

	for (i = 0; i < len; i++) {
		if (ident[i] >= '0' && ident[i] <= '9')
			continue;
		if (ident[i] >= 'a' && ident[i] <= 'z')
			continue;
		if (ident[i] >= 'A' && ident[i] <= 'Z')
			continue;
		ident[i] = '_';
	}
}

int __connman_provider_create_and_connect(DBusMessage *msg)
{
	struct connman_provider *provider;
	DBusMessageIter iter, array;
	const char *type = NULL, *name = NULL, *service_path;
	const char *host = NULL, *domain = NULL;
	char *ident;
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
			else if (g_str_equal(key, "Host") == TRUE)
				dbus_message_iter_get_basic(&value, &host);
			else if (g_str_equal(key, "VPN.Domain") == TRUE)
				dbus_message_iter_get_basic(&value, &domain);
			break;
		}

		dbus_message_iter_next(&array);
	}

	if (host == NULL || domain == NULL)
		return -EINVAL;

	DBG("Type %s name %s", type, name);

	if (type == NULL || name == NULL)
		return -EOPNOTSUPP;

	ident = g_strdup_printf("%s_%s", host, domain);
	provider_dbus_ident(ident);

	DBG("ident %s", ident);

	provider = connman_provider_lookup(ident);
	if (provider == NULL) {
		provider = connman_provider_get(ident);
		if (provider == NULL) {
			DBG("can not create provider");
			g_free(ident);
			return -EOPNOTSUPP;
		}

		provider->host = g_strdup(host);
		provider->domain = g_strdup(domain);
		provider->name = g_strdup(name);
		provider->type = g_strdup(type);

		provider_register(provider);
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

	if (provider->vpn_service == NULL) {
		provider->vpn_service =
			__connman_service_create_from_provider(provider);
		if (provider->vpn_service == NULL) {
			err = -EOPNOTSUPP;
			goto unref;
		}

		err = __connman_service_connect(provider->vpn_service);
		if (err < 0 && err != -EINPROGRESS)
			goto failed;
	} else
		DBG("provider already connected");

	connman_provider_save(provider);
	service_path = __connman_service_get_path(provider->vpn_service);
	g_dbus_send_reply(connection, msg,
				DBUS_TYPE_OBJECT_PATH, &service_path,
							DBUS_TYPE_INVALID);
	return 0;

failed:
	connman_service_unref(provider->vpn_service);
	provider->vpn_service = NULL;

unref:
	DBG("can not connect, delete provider");

	g_hash_table_remove(provider_hash, provider->identifier);

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
	} else if (g_str_equal(key, "Host") == TRUE) {
		g_free(provider->host);
		provider->host = g_strdup(value);
	} else if (g_str_equal(key, "VPN.Domain") == TRUE) {
		g_free(provider->domain);
		provider->domain = g_strdup(value);
	} else
		g_hash_table_replace(provider->setting_strings,
				g_strdup(key), g_strdup(value));
	return 0;
}

const char *connman_provider_get_string(struct connman_provider *provider,
							const char *key)
{
	DBG("provider %p key %s", provider, key);

	if (g_str_equal(key, "Type") == TRUE)
		return provider->type;
	else if (g_str_equal(key, "Name") == TRUE)
		return provider->name;
	else if (g_str_equal(key, "Host") == TRUE)
		return provider->host;
	else if (g_str_equal(key, "VPN.Domain") == TRUE)
		return provider->domain;

	return g_hash_table_lookup(provider->setting_strings, key);
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
	struct connman_service *service = provider->vpn_service;
	struct connman_ipconfig *ipconfig;

	DBG("");

	if (service == NULL)
		return;

	ipconfig = __connman_service_get_ip4config(service);

	if (ipconfig == NULL) {
		__connman_service_create_ip4config(service, index);

		ipconfig = __connman_service_get_ip4config(service);
		if (ipconfig == NULL) {
			DBG("Couldnt create ipconfig");
			goto done;
		}
	}

	__connman_ipconfig_set_method(ipconfig, CONNMAN_IPCONFIG_METHOD_FIXED);
	__connman_ipconfig_set_index(ipconfig, index);


	ipconfig = __connman_service_get_ip6config(service);

	if (ipconfig == NULL) {
		__connman_service_create_ip6config(service, index);

		ipconfig = __connman_service_get_ip6config(service);
		if (ipconfig == NULL) {
			DBG("Couldnt create ipconfig for IPv6");
			goto done;
		}
	}

	__connman_ipconfig_set_method(ipconfig, CONNMAN_IPCONFIG_METHOD_OFF);
	__connman_ipconfig_set_index(ipconfig, index);

done:
	provider->index = index;
}

int connman_provider_get_index(struct connman_provider *provider)
{
	return provider->index;
}

int connman_provider_set_ipaddress(struct connman_provider *provider,
					struct connman_ipaddress *ipaddress)
{
	struct connman_ipconfig *ipconfig = NULL;

	ipconfig = __connman_service_get_ipconfig(provider->vpn_service,
							ipaddress->family);
	if (ipconfig == NULL)
		return -EINVAL;

	provider->family = ipaddress->family;

	__connman_ipconfig_set_local(ipconfig, ipaddress->local);
	__connman_ipconfig_set_peer(ipconfig, ipaddress->peer);
	__connman_ipconfig_set_broadcast(ipconfig, ipaddress->broadcast);
	__connman_ipconfig_set_gateway(ipconfig, ipaddress->gateway);
	__connman_ipconfig_set_prefixlen(ipconfig, ipaddress->prefixlen);

	return 0;
}

int connman_provider_set_pac(struct connman_provider *provider, const char *pac)
{
	DBG("provider %p pac %s", provider, pac);

	__connman_service_set_pac(provider->vpn_service, pac);

	return 0;
}


int connman_provider_set_domain(struct connman_provider *provider,
					const char *domain)
{
	DBG("provider %p domain %s", provider, domain);

	g_free(provider->domain);
	provider->domain = g_strdup(domain);

	__connman_service_set_domainname(provider->vpn_service, domain);

	return 0;
}

int connman_provider_set_nameservers(struct connman_provider *provider,
					const char *nameservers)
{
	int i;
	char **nameservers_array = NULL;

	DBG("provider %p nameservers %s", provider, nameservers);

	__connman_service_nameserver_clear(provider->vpn_service);

	if (nameservers == NULL)
		return 0;

	nameservers_array = g_strsplit(nameservers, " ", 0);

	for (i = 0; nameservers_array[i] != NULL; i++) {
		__connman_service_nameserver_append(provider->vpn_service,
						nameservers_array[i], FALSE);
	}

	g_strfreev(nameservers_array);

	return 0;
}

enum provider_route_type {
	PROVIDER_ROUTE_TYPE_NONE = 0,
	PROVIDER_ROUTE_TYPE_MASK = 1,
	PROVIDER_ROUTE_TYPE_ADDR = 2,
	PROVIDER_ROUTE_TYPE_GW   = 3,
};

static int route_env_parse(struct connman_provider *provider, const char *key,
				int *family, unsigned long *idx,
				enum provider_route_type *type)
{
	char *end;
	const char *start;

	DBG("name %s", provider->name);

	if (!strcmp(provider->type, "openvpn")) {
		if (g_str_has_prefix(key, "route_network_") == TRUE) {
			start = key + strlen("route_network_");
			*type = PROVIDER_ROUTE_TYPE_ADDR;
		} else if (g_str_has_prefix(key, "route_netmask_") == TRUE) {
			start = key + strlen("route_netmask_");
			*type = PROVIDER_ROUTE_TYPE_MASK;
		} else if (g_str_has_prefix(key, "route_gateway_") == TRUE) {
			start = key + strlen("route_gateway_");
			*type = PROVIDER_ROUTE_TYPE_GW;
		} else
			return -EINVAL;

		*family = AF_INET;
		*idx = g_ascii_strtoull(start, &end, 10);

	} else if (!strcmp(provider->type, "openconnect")) {
		if (g_str_has_prefix(key, "CISCO_SPLIT_INC_") == TRUE) {
			*family = AF_INET;
			start = key + strlen("CISCO_SPLIT_INC_");
		} else if (g_str_has_prefix(key, "CISCO_IPV6_SPLIT_INC_") == TRUE) {
			*family = AF_INET6;
			start = key + strlen("CISCO_IPV6_SPLIT_INC_");
		} else
			return -EINVAL;

		*idx = g_ascii_strtoull(start, &end, 10);

		if (strncmp(end, "_ADDR", 5) == 0)
			*type = PROVIDER_ROUTE_TYPE_ADDR;
		else if (strncmp(end, "_MASK", 5) == 0)
			*type = PROVIDER_ROUTE_TYPE_MASK;
		else if (strncmp(end, "_MASKLEN", 8) == 0 &&
				*family == AF_INET6) {
			*type = PROVIDER_ROUTE_TYPE_MASK;
		} else
			return -EINVAL;
	}

	return 0;
}

int connman_provider_append_route(struct connman_provider *provider,
					const char *key, const char *value)
{
	struct connman_route *route;
	int ret, family = 0;
	unsigned long idx = 0;
	enum provider_route_type type = PROVIDER_ROUTE_TYPE_NONE;

	DBG("key %s value %s", key, value);

	ret = route_env_parse(provider, key, &family, &idx, &type);
	if (ret < 0)
		return ret;

	DBG("idx %lu family %d type %d", idx, family, type);

	route = g_hash_table_lookup(provider->routes, GINT_TO_POINTER(idx));
	if (route == NULL) {
		route = g_try_new0(struct connman_route, 1);
		if (route == NULL) {
			connman_error("out of memory");
			return -ENOMEM;
		}

		route->family = family;

		g_hash_table_replace(provider->routes, GINT_TO_POINTER(idx),
						route);
	}

	switch (type) {
	case PROVIDER_ROUTE_TYPE_NONE:
		break;
	case PROVIDER_ROUTE_TYPE_MASK:
		route->netmask = g_strdup(value);
		break;
	case PROVIDER_ROUTE_TYPE_ADDR:
		route->host = g_strdup(value);
		break;
	case PROVIDER_ROUTE_TYPE_GW:
		route->gateway = g_strdup(value);
		break;
	}

	return 0;
}

const char *connman_provider_get_driver_name(struct connman_provider *provider)
{
	if (provider->driver == NULL)
		return NULL;

	return provider->driver->name;
}

const char *connman_provider_get_save_group(struct connman_provider *provider)
{
	return provider->identifier;
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

static void provider_remove_all(gpointer key, gpointer value,
						gpointer user_data)
{
	struct connman_provider *provider = value;

	__connman_provider_remove(provider->identifier);
}

static void provider_offline_mode(connman_bool_t enabled)
{
	DBG("enabled %d", enabled);

	if (enabled == TRUE)
		g_hash_table_foreach(provider_hash, provider_remove_all, NULL);

}

static struct connman_notifier provider_notifier = {
	.name			= "provider",
	.offline_mode		= provider_offline_mode,
};

int __connman_provider_init(void)
{
	int err;

	DBG("");

	connection = connman_dbus_get_connection();

	provider_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						NULL, unregister_provider);

	err = connman_notifier_register(&provider_notifier);
	if (err < 0) {
		g_hash_table_destroy(provider_hash);
		dbus_connection_unref(connection);
	}

	return err;
}

void __connman_provider_cleanup(void)
{
	DBG("");

	connman_notifier_unregister(&provider_notifier);

	g_hash_table_foreach(provider_hash, clean_provider, NULL);

	g_hash_table_destroy(provider_hash);
	provider_hash = NULL;

	dbus_connection_unref(connection);
}
