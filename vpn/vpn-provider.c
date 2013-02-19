/*
 *
 *  ConnMan VPN daemon
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
#include <string.h>
#include <stdlib.h>
#include <gdbus.h>
#include <connman/log.h>
#include <gweb/gresolv.h>
#include <netdb.h>

#include "../src/connman.h"
#include "connman/agent.h"
#include "connman/vpn-dbus.h"
#include "vpn-provider.h"
#include "vpn.h"

static DBusConnection *connection;
static GHashTable *provider_hash;
static GSList *driver_list;
static int configuration_count;
static gboolean handle_routes;

struct vpn_route {
	int family;
	char *network;
	char *netmask;
	char *gateway;
};

struct vpn_setting {
	gboolean hide_value;
	char *value;
};

struct vpn_provider {
	int refcount;
	int index;
	int fd;
	enum vpn_provider_state state;
	char *path;
	char *identifier;
	char *name;
	char *type;
	char *host;
	char *domain;
	int family;
	GHashTable *routes;
	struct vpn_provider_driver *driver;
	void *driver_data;
	GHashTable *setting_strings;
	GHashTable *user_routes;
	GSList *user_networks;
	GResolv *resolv;
	char **host_ip;
	struct vpn_ipconfig *ipconfig_ipv4;
	struct vpn_ipconfig *ipconfig_ipv6;
	char **nameservers;
	guint notify_id;
	char *config_file;
	char *config_entry;
};

static void append_properties(DBusMessageIter *iter,
				struct vpn_provider *provider);

static void free_route(gpointer data)
{
	struct vpn_route *route = data;

	g_free(route->network);
	g_free(route->netmask);
	g_free(route->gateway);

	g_free(route);
}

static void free_setting(gpointer data)
{
	struct vpn_setting *setting = data;

	g_free(setting->value);
	g_free(setting);
}

static void append_route(DBusMessageIter *iter, void *user_data)
{
	struct vpn_route *route = user_data;
	DBusMessageIter item;
	int family = 0;

	connman_dbus_dict_open(iter, &item);

	if (route == NULL)
		goto empty_dict;

	if (route->family == AF_INET)
		family = 4;
	else if (route->family == AF_INET6)
		family = 6;

	if (family != 0)
		connman_dbus_dict_append_basic(&item, "ProtocolFamily",
					DBUS_TYPE_INT32, &family);

	if (route->network != NULL)
		connman_dbus_dict_append_basic(&item, "Network",
					DBUS_TYPE_STRING, &route->network);

	if (route->netmask != NULL)
		connman_dbus_dict_append_basic(&item, "Netmask",
					DBUS_TYPE_STRING, &route->netmask);

	if (route->gateway != NULL)
		connman_dbus_dict_append_basic(&item, "Gateway",
					DBUS_TYPE_STRING, &route->gateway);

empty_dict:
	connman_dbus_dict_close(iter, &item);
}

static void append_routes(DBusMessageIter *iter, void *user_data)
{
	GHashTable *routes = user_data;
	GHashTableIter hash;
	gpointer value, key;

	if (routes == NULL) {
		append_route(iter, NULL);
		return;
	}

	g_hash_table_iter_init(&hash, routes);

	while (g_hash_table_iter_next(&hash, &key, &value) == TRUE) {
		DBusMessageIter dict;

		dbus_message_iter_open_container(iter, DBUS_TYPE_STRUCT, NULL,
						&dict);
		append_route(&dict, value);
		dbus_message_iter_close_container(iter, &dict);
	}
}

static void send_routes(struct vpn_provider *provider, GHashTable *routes,
			const char *name)
{
	connman_dbus_property_changed_array(provider->path,
					VPN_CONNECTION_INTERFACE,
					name,
					DBUS_TYPE_DICT_ENTRY,
					append_routes,
					routes);
}

static int provider_routes_changed(struct vpn_provider *provider)
{
	DBG("provider %p", provider);

	send_routes(provider, provider->routes, "ServerRoutes");

	return 0;
}

static GSList *read_route_dict(GSList *routes, DBusMessageIter *dicts)
{
	DBusMessageIter dict, value, entry;
	const char *network, *netmask, *gateway;
	struct vpn_route *route;
	int family, type;
	const char *key;

	dbus_message_iter_recurse(dicts, &entry);

	network = netmask = gateway = NULL;
	family = PF_UNSPEC;

	while (dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_DICT_ENTRY) {

		dbus_message_iter_recurse(&entry, &dict);
		dbus_message_iter_get_basic(&dict, &key);

		dbus_message_iter_next(&dict);
		dbus_message_iter_recurse(&dict, &value);

		type = dbus_message_iter_get_arg_type(&value);

		switch (type) {
		case DBUS_TYPE_STRING:
			if (g_str_equal(key, "ProtocolFamily") == TRUE)
				dbus_message_iter_get_basic(&value, &family);
			else if (g_str_equal(key, "Network") == TRUE)
				dbus_message_iter_get_basic(&value, &network);
			else if (g_str_equal(key, "Netmask") == TRUE)
				dbus_message_iter_get_basic(&value, &netmask);
			else if (g_str_equal(key, "Gateway") == TRUE)
				dbus_message_iter_get_basic(&value, &gateway);
			break;
		}

		dbus_message_iter_next(&entry);
	}

	DBG("family %d network %s netmask %s gateway %s", family,
		network, netmask, gateway);

	if (network == NULL || netmask == NULL) {
		DBG("Ignoring route as network/netmask is missing");
		return routes;
	}

	route = g_try_new(struct vpn_route, 1);
	if (route == NULL) {
		g_slist_free_full(routes, free_route);
		return NULL;
	}

	if (family == PF_UNSPEC) {
		family = connman_inet_check_ipaddress(network);
		if (family < 0) {
			DBG("Cannot get address family of %s (%d/%s)", network,
				family, gai_strerror(family));

			g_free(route);
			return routes;
		}
	} else {
		switch (family) {
		case '4':
			family = AF_INET;
			break;
		case '6':
			family = AF_INET6;
			break;
		default:
			family = PF_UNSPEC;
			break;
		}
	}

	route->family = family;
	route->network = g_strdup(network);
	route->netmask = g_strdup(netmask);
	route->gateway = g_strdup(gateway);

	routes = g_slist_prepend(routes, route);
	return routes;
}

static GSList *get_user_networks(DBusMessageIter *array)
{
	DBusMessageIter entry;
	GSList *list = NULL;

	while (dbus_message_iter_get_arg_type(array) == DBUS_TYPE_ARRAY) {

		dbus_message_iter_recurse(array, &entry);

		while (dbus_message_iter_get_arg_type(&entry) ==
							DBUS_TYPE_STRUCT) {
			DBusMessageIter dicts;

			dbus_message_iter_recurse(&entry, &dicts);

			while (dbus_message_iter_get_arg_type(&dicts) ==
							DBUS_TYPE_ARRAY) {

				list = read_route_dict(list, &dicts);
				dbus_message_iter_next(&dicts);
			}

			dbus_message_iter_next(&entry);
		}

		dbus_message_iter_next(array);
	}

	return list;
}

static void set_user_networks(struct vpn_provider *provider, GSList *networks)
{
	GSList *list;

	for (list = networks; list != NULL; list = g_slist_next(list)) {
		struct vpn_route *route = list->data;

		if (__vpn_provider_append_user_route(provider,
					route->family, route->network,
					route->netmask, route->gateway) != 0)
			break;
	}
}

static void del_routes(struct vpn_provider *provider)
{
	GHashTableIter hash;
	gpointer value, key;

	g_hash_table_iter_init(&hash, provider->user_routes);
	while (handle_routes == TRUE && g_hash_table_iter_next(&hash,
						&key, &value) == TRUE) {
		struct vpn_route *route = value;
		if (route->family == AF_INET6) {
			unsigned char prefixlen = atoi(route->netmask);
			connman_inet_del_ipv6_network_route(provider->index,
							route->network,
							prefixlen);
		} else
			connman_inet_del_host_route(provider->index,
						route->network);
	}

	g_hash_table_remove_all(provider->user_routes);
	g_slist_free_full(provider->user_networks, free_route);
	provider->user_networks = NULL;
}

static void send_value(const char *path, const char *key, const char *value)
{
	const char *empty = "";
	const char *str;

	if (value != NULL)
		str = value;
	else
		str = empty;

	connman_dbus_property_changed_basic(path,
					VPN_CONNECTION_INTERFACE,
					key,
					DBUS_TYPE_STRING,
					&str);
}

static gboolean provider_send_changed(gpointer data)
{
	struct vpn_provider *provider = data;

	provider_routes_changed(provider);

	provider->notify_id = 0;

	return FALSE;
}

static void provider_schedule_changed(struct vpn_provider *provider)
{
	if (provider->notify_id != 0)
		g_source_remove(provider->notify_id);

	provider->notify_id = g_timeout_add(100, provider_send_changed,
								provider);
}

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct vpn_provider *provider = data;
	DBusMessage *reply;
	DBusMessageIter array;

	DBG("provider %p", provider);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &array);

	append_properties(&array, provider);

	return reply;
}

static DBusMessage *set_property(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct vpn_provider *provider = data;
	DBusMessageIter iter, value;
	const char *name;
	int type;

	DBG("conn %p", conn);

	if (dbus_message_iter_init(msg, &iter) == FALSE)
		return __connman_error_invalid_arguments(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &name);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_recurse(&iter, &value);

	type = dbus_message_iter_get_arg_type(&value);

	if (g_str_equal(name, "UserRoutes") == TRUE) {
		GSList *networks;

		if (type != DBUS_TYPE_ARRAY)
			return __connman_error_invalid_arguments(msg);

		networks = get_user_networks(&value);
		if (networks != NULL) {
			del_routes(provider);
			provider->user_networks = networks;
			set_user_networks(provider, provider->user_networks);

			if (handle_routes == FALSE)
				send_routes(provider, provider->user_routes,
								"UserRoutes");
		}
	} else {
		const char *str;

		dbus_message_iter_get_basic(&value, &str);
		vpn_provider_set_string(provider, name, str);
	}

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *clear_property(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct vpn_provider *provider = data;
	const char *name;

	DBG("conn %p", conn);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &name,
							DBUS_TYPE_INVALID);

	if (g_str_equal(name, "UserRoutes") == TRUE) {
		del_routes(provider);

		if (handle_routes == FALSE)
			send_routes(provider, provider->user_routes, name);
	} else if (vpn_provider_get_string(provider, name) != NULL) {
		vpn_provider_set_string(provider, name, NULL);
	} else {
		return __connman_error_invalid_property(msg);
	}

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *do_connect(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct vpn_provider *provider = data;
	int err;

	DBG("conn %p provider %p", conn, provider);

	err = __vpn_provider_connect(provider, msg);
	if (err < 0)
		return __connman_error_failed(msg, -err);

	return NULL;
}

static DBusMessage *do_disconnect(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct vpn_provider *provider = data;
	int err;

	DBG("conn %p provider %p", conn, provider);

	err = __vpn_provider_disconnect(provider);
	if (err < 0 && err != -EINPROGRESS)
		return __connman_error_failed(msg, -err);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static const GDBusMethodTable connection_methods[] = {
	{ GDBUS_METHOD("GetProperties",
			NULL, GDBUS_ARGS({ "properties", "a{sv}" }),
			get_properties) },
	{ GDBUS_METHOD("SetProperty",
			GDBUS_ARGS({ "name", "s" }, { "value", "v" }),
			NULL, set_property) },
	{ GDBUS_METHOD("ClearProperty",
			GDBUS_ARGS({ "name", "s" }), NULL,
			clear_property) },
	{ GDBUS_ASYNC_METHOD("Connect", NULL, NULL, do_connect) },
	{ GDBUS_METHOD("Disconnect", NULL, NULL, do_disconnect) },
	{ },
};

static const GDBusSignalTable connection_signals[] = {
	{ GDBUS_SIGNAL("PropertyChanged",
			GDBUS_ARGS({ "name", "s" }, { "value", "v" })) },
	{ },
};

static void resolv_result(GResolvResultStatus status,
					char **results, gpointer user_data)
{
	struct vpn_provider *provider = user_data;

	DBG("status %d", status);

	if (status == G_RESOLV_RESULT_STATUS_SUCCESS && results != NULL &&
						g_strv_length(results) > 0)
		provider->host_ip = g_strdupv(results);

	vpn_provider_unref(provider);
}

static void provider_resolv_host_addr(struct vpn_provider *provider)
{
	if (provider->host == NULL)
		return;

	if (connman_inet_check_ipaddress(provider->host) > 0)
		return;

	if (provider->host_ip != NULL)
		return;

	/*
	 * If the hostname is not numeric, try to resolv it. We do not wait
	 * the result as it might take some time. We will get the result
	 * before VPN will feed routes to us because VPN client will need
	 * the IP address also before VPN connection can be established.
	 */
	provider->resolv = g_resolv_new(0);
	if (provider->resolv == NULL) {
		DBG("Cannot resolv %s", provider->host);
		return;
	}

	DBG("Trying to resolv %s", provider->host);

	vpn_provider_ref(provider);

	g_resolv_lookup_hostname(provider->resolv, provider->host,
				resolv_result, provider);
}

void __vpn_provider_append_properties(struct vpn_provider *provider,
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

int __vpn_provider_append_user_route(struct vpn_provider *provider,
				int family, const char *network,
				const char *netmask, const char *gateway)
{
	struct vpn_route *route;
	char *key = g_strdup_printf("%d/%s/%s/%s", family, network,
				netmask, gateway != NULL ? gateway : "");

	DBG("family %d network %s netmask %s gw %s", family, network,
							netmask, gateway);

	route = g_hash_table_lookup(provider->user_routes, key);
	if (route == NULL) {
		route = g_try_new0(struct vpn_route, 1);
		if (route == NULL) {
			connman_error("out of memory");
			return -ENOMEM;
		}

		route->family = family;
		route->network = g_strdup(network);
		route->netmask = g_strdup(netmask);
		route->gateway = g_strdup(gateway);

		g_hash_table_replace(provider->user_routes, key, route);
	} else
		g_free(key);

	return 0;
}

static struct vpn_route *get_route(char *route_str)
{
	char **elems = g_strsplit(route_str, "/", 0);
	char *network, *netmask, *gateway, *family_str;
	int family = PF_UNSPEC;
	struct vpn_route *route = NULL;

	if (elems == NULL)
		return NULL;

	family_str = elems[0];

	network = elems[1];
	if (network == NULL || network[0] == '\0')
		goto out;

	netmask = elems[2];
	if (netmask == NULL || netmask[0] == '\0')
		goto out;

	gateway = elems[3];

	route = g_try_new0(struct vpn_route, 1);
	if (route == NULL)
		goto out;

	if (family_str[0] == '\0' || atoi(family_str) == 0) {
		family = PF_UNSPEC;
	} else {
		switch (family_str[0]) {
		case '4':
			family = AF_INET;
			break;
		case '6':
			family = AF_INET6;
			break;
		}
	}

	if (g_strrstr(network, ":") != NULL) {
		if (family != PF_UNSPEC && family != AF_INET6)
			DBG("You have IPv6 address but you have non IPv6 route");
	} else if (g_strrstr(network, ".") != NULL) {
		if (family != PF_UNSPEC && family != AF_INET)
			DBG("You have IPv4 address but you have non IPv4 route");

		if (g_strrstr(netmask, ".") == NULL) {
			/* We have netmask length */
			in_addr_t addr;
			struct in_addr netmask_in;
			unsigned char prefix_len = 32;

			if (netmask != NULL) {
				char *ptr;
				long int value = strtol(netmask, &ptr, 10);
				if (ptr != netmask && *ptr == '\0' &&
								value <= 32)
					prefix_len = value;
			}

			addr = 0xffffffff << (32 - prefix_len);
			netmask_in.s_addr = htonl(addr);
			netmask = inet_ntoa(netmask_in);

			DBG("network %s netmask %s", network, netmask);
		}
	}

	if (family == PF_UNSPEC) {
		family = connman_inet_check_ipaddress(network);
		if (family < 0 || family == PF_UNSPEC)
			goto out;
	}

	route->family = family;
	route->network = g_strdup(network);
	route->netmask = g_strdup(netmask);
	route->gateway = g_strdup(gateway);

out:
	g_strfreev(elems);
	return route;
}

static GSList *get_routes(gchar **networks)
{
	struct vpn_route *route;
	GSList *routes = NULL;
	int i;

	for (i = 0; networks[i] != NULL; i++) {
		route = get_route(networks[i]);
		if (route != NULL)
			routes = g_slist_prepend(routes, route);
	}

	return routes;
}

static int provider_load_from_keyfile(struct vpn_provider *provider,
		GKeyFile *keyfile)
{
	gsize idx = 0;
	gchar **settings;
	gchar *key, *value;
	gsize length, num_user_networks;
	gchar **networks = NULL;

	settings = g_key_file_get_keys(keyfile, provider->identifier, &length,
				NULL);
	if (settings == NULL) {
		g_key_file_free(keyfile);
		return -ENOENT;
	}

	while (idx < length) {
		key = settings[idx];
		if (key != NULL) {
			if (g_str_equal(key, "Networks") == TRUE) {
				networks = g_key_file_get_string_list(keyfile,
						provider->identifier,
						key,
						&num_user_networks,
						NULL);
				provider->user_networks = get_routes(networks);

			} else {
				value = g_key_file_get_string(keyfile,
							provider->identifier,
							key, NULL);
				vpn_provider_set_string(provider, key,
							value);
				g_free(value);
			}
		}
		idx += 1;
	}
	g_strfreev(settings);
	g_strfreev(networks);

	if (provider->user_networks != NULL)
		set_user_networks(provider, provider->user_networks);

	return 0;
}


static int vpn_provider_load(struct vpn_provider *provider)
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

static gchar **create_network_list(GSList *networks, gsize *count)
{
	GSList *list;
	gchar **result = NULL;
	unsigned int num_elems = 0;

	for (list = networks; list != NULL; list = g_slist_next(list)) {
		struct vpn_route *route = list->data;
		int family;

		result = g_try_realloc(result,
				(num_elems + 1) * sizeof(gchar *));
		if (result == NULL)
			return NULL;

		switch (route->family) {
		case AF_INET:
			family = 4;
			break;
		case AF_INET6:
			family = 6;
			break;
		default:
			family = 0;
			break;
		}

		result[num_elems] = g_strdup_printf("%d/%s/%s/%s",
				family, route->network, route->netmask,
				route->gateway == NULL ? "" : route->gateway);

		num_elems++;
	}

	result = g_try_realloc(result, (num_elems + 1) * sizeof(gchar *));
	if (result == NULL)
		return NULL;

	result[num_elems] = NULL;
	*count = num_elems;
	return result;
}

static int vpn_provider_save(struct vpn_provider *provider)
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
	if (provider->user_networks != NULL) {
		gchar **networks;
		gsize network_count;

		networks = create_network_list(provider->user_networks,
							&network_count);
		if (networks != NULL) {
			g_key_file_set_string_list(keyfile,
						provider->identifier,
						"Networks",
						(const gchar ** const)networks,
						network_count);
			g_strfreev(networks);
		}
	}

	if (provider->config_file != NULL && strlen(provider->config_file) > 0)
		g_key_file_set_string(keyfile, provider->identifier,
				"Config.file", provider->config_file);

	if (provider->config_entry != NULL &&
					strlen(provider->config_entry) > 0)
		g_key_file_set_string(keyfile, provider->identifier,
				"Config.ident", provider->config_entry);

	if (provider->driver != NULL && provider->driver->save != NULL)
		provider->driver->save(provider, keyfile);

	__connman_storage_save_provider(keyfile, provider->identifier);
        g_key_file_free(keyfile);

	return 0;
}

struct vpn_provider *__vpn_provider_lookup(const char *identifier)
{
	struct vpn_provider *provider = NULL;

	provider = g_hash_table_lookup(provider_hash, identifier);

	return provider;
}

static gboolean match_driver(struct vpn_provider *provider,
				struct vpn_provider_driver *driver)
{
	if (g_strcmp0(driver->name, provider->type) == 0)
		return TRUE;

	return FALSE;
}

static int provider_probe(struct vpn_provider *provider)
{
	GSList *list;

	DBG("provider %p driver %p name %s", provider, provider->driver,
						provider->name);

	if (provider->driver != NULL)
		return -EALREADY;

	for (list = driver_list; list; list = list->next) {
		struct vpn_provider_driver *driver = list->data;

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

static void provider_remove(struct vpn_provider *provider)
{
	if (provider->driver != NULL) {
		provider->driver->remove(provider);
		provider->driver = NULL;
	}
}

static int provider_register(struct vpn_provider *provider)
{
	return provider_probe(provider);
}

static void provider_unregister(struct vpn_provider *provider)
{
	provider_remove(provider);
}

struct vpn_provider *
vpn_provider_ref_debug(struct vpn_provider *provider,
			const char *file, int line, const char *caller)
{
	DBG("%p ref %d by %s:%d:%s()", provider, provider->refcount + 1,
		file, line, caller);

	__sync_fetch_and_add(&provider->refcount, 1);

	return provider;
}

static void provider_destruct(struct vpn_provider *provider)
{
	DBG("provider %p", provider);

	if (provider->notify_id != 0)
		g_source_remove(provider->notify_id);

	g_free(provider->name);
	g_free(provider->type);
	g_free(provider->host);
	g_free(provider->domain);
	g_free(provider->identifier);
	g_free(provider->path);
	g_slist_free_full(provider->user_networks, free_route);
	g_strfreev(provider->nameservers);
	g_hash_table_destroy(provider->routes);
	g_hash_table_destroy(provider->user_routes);
	g_hash_table_destroy(provider->setting_strings);
	if (provider->resolv != NULL) {
		g_resolv_unref(provider->resolv);
		provider->resolv = NULL;
	}
	__vpn_ipconfig_unref(provider->ipconfig_ipv4);
	__vpn_ipconfig_unref(provider->ipconfig_ipv6);

	g_strfreev(provider->host_ip);
	g_free(provider->config_file);
	g_free(provider->config_entry);
	g_free(provider);
}

void vpn_provider_unref_debug(struct vpn_provider *provider,
				const char *file, int line, const char *caller)
{
	DBG("%p ref %d by %s:%d:%s()", provider, provider->refcount - 1,
		file, line, caller);

	if (__sync_fetch_and_sub(&provider->refcount, 1) != 1)
		return;

	provider_remove(provider);

	provider_destruct(provider);
}

static void configuration_count_add(void)
{
	DBG("count %d", configuration_count + 1);

	__sync_fetch_and_add(&configuration_count, 1);
}

static void configuration_count_del(void)
{
	DBG("count %d", configuration_count - 1);

	if (__sync_fetch_and_sub(&configuration_count, 1) != 1)
		return;

	raise(SIGTERM);
}

int __vpn_provider_disconnect(struct vpn_provider *provider)
{
	int err;

	DBG("provider %p", provider);

	if (provider->driver != NULL && provider->driver->disconnect != NULL)
		err = provider->driver->disconnect(provider);
	else
		return -EOPNOTSUPP;

	if (err == -EINPROGRESS)
		vpn_provider_set_state(provider, VPN_PROVIDER_STATE_CONNECT);

	return err;
}

static void connect_cb(struct vpn_provider *provider, void *user_data,
								int error)
{
	DBusMessage *pending = user_data;

	DBG("provider %p user %p error %d", provider, user_data, error);

	if (error != 0) {
		DBusMessage *reply = __connman_error_failed(pending, error);
		if (reply != NULL)
			g_dbus_send_message(connection, reply);

		vpn_provider_indicate_error(provider,
					VPN_PROVIDER_ERROR_CONNECT_FAILED);
		vpn_provider_set_state(provider, VPN_PROVIDER_STATE_FAILURE);
	} else
		g_dbus_send_reply(connection, pending, DBUS_TYPE_INVALID);

	dbus_message_unref(pending);
}

int __vpn_provider_connect(struct vpn_provider *provider, DBusMessage *msg)
{
	int err;

	DBG("provider %p", provider);

	if (provider->driver != NULL && provider->driver->connect != NULL) {
		dbus_message_ref(msg);
		err = provider->driver->connect(provider, connect_cb, msg);
	} else
		return -EOPNOTSUPP;

	if (err == -EINPROGRESS)
		vpn_provider_set_state(provider, VPN_PROVIDER_STATE_CONNECT);

	return err;
}

static void connection_removed_signal(struct vpn_provider *provider)
{
	DBusMessage *signal;
	DBusMessageIter iter;

	signal = dbus_message_new_signal(VPN_MANAGER_PATH,
			VPN_MANAGER_INTERFACE, "ConnectionRemoved");
	if (signal == NULL)
		return;

	dbus_message_iter_init_append(signal, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH,
							&provider->path);
	dbus_connection_send(connection, signal, NULL);
	dbus_message_unref(signal);
}

static char *get_ident(const char *path)
{
	char *pos;

	if (*path != '/')
		return NULL;

	pos = strrchr(path, '/');
	if (pos == NULL)
		return NULL;

	return pos + 1;
}

int __vpn_provider_remove(const char *path)
{
	struct vpn_provider *provider;
	char *ident;

	DBG("path %s", path);

	ident = get_ident(path);

	provider = __vpn_provider_lookup(ident);
	if (provider != NULL)
		return __vpn_provider_delete(provider);

	return -ENXIO;
}

int __vpn_provider_delete(struct vpn_provider *provider)
{
	DBG("Deleting VPN %s", provider->identifier);

	connection_removed_signal(provider);

	provider_unregister(provider);

	__connman_storage_remove_provider(provider->identifier);

	g_hash_table_remove(provider_hash, provider->identifier);

	return 0;
}

static void append_ipv4(DBusMessageIter *iter, void *user_data)
{
	struct vpn_provider *provider = user_data;
	const char *address, *gateway, *peer;

	address = __vpn_ipconfig_get_local(provider->ipconfig_ipv4);
	if (address != NULL) {
		in_addr_t addr;
		struct in_addr netmask;
		char *mask;
		int prefixlen;

		prefixlen = __vpn_ipconfig_get_prefixlen(
						provider->ipconfig_ipv4);

		addr = 0xffffffff << (32 - prefixlen);
		netmask.s_addr = htonl(addr);
		mask = inet_ntoa(netmask);

		connman_dbus_dict_append_basic(iter, "Address",
						DBUS_TYPE_STRING, &address);

		connman_dbus_dict_append_basic(iter, "Netmask",
						DBUS_TYPE_STRING, &mask);
	}

	gateway = __vpn_ipconfig_get_gateway(provider->ipconfig_ipv4);
	if (gateway != NULL)
		connman_dbus_dict_append_basic(iter, "Gateway",
						DBUS_TYPE_STRING, &gateway);

	peer = __vpn_ipconfig_get_peer(provider->ipconfig_ipv4);
	if (peer != NULL)
		connman_dbus_dict_append_basic(iter, "Peer",
						DBUS_TYPE_STRING, &peer);
}

static void append_ipv6(DBusMessageIter *iter, void *user_data)
{
	struct vpn_provider *provider = user_data;
	const char *address, *gateway, *peer;

	address = __vpn_ipconfig_get_local(provider->ipconfig_ipv6);
	if (address != NULL) {
		unsigned char prefixlen;

		connman_dbus_dict_append_basic(iter, "Address",
						DBUS_TYPE_STRING, &address);

		prefixlen = __vpn_ipconfig_get_prefixlen(
						provider->ipconfig_ipv6);

		connman_dbus_dict_append_basic(iter, "PrefixLength",
						DBUS_TYPE_BYTE, &prefixlen);
	}

	gateway = __vpn_ipconfig_get_gateway(provider->ipconfig_ipv6);
	if (gateway != NULL)
		connman_dbus_dict_append_basic(iter, "Gateway",
						DBUS_TYPE_STRING, &gateway);

	peer = __vpn_ipconfig_get_peer(provider->ipconfig_ipv6);
	if (peer != NULL)
		connman_dbus_dict_append_basic(iter, "Peer",
						DBUS_TYPE_STRING, &peer);
}

static const char *state2string(enum vpn_provider_state state)
{
	switch (state) {
	case VPN_PROVIDER_STATE_UNKNOWN:
		break;
	case VPN_PROVIDER_STATE_IDLE:
		return "idle";
	case VPN_PROVIDER_STATE_CONNECT:
		return "configuration";
	case VPN_PROVIDER_STATE_READY:
		return "ready";
	case VPN_PROVIDER_STATE_DISCONNECT:
		return "disconnect";
	case VPN_PROVIDER_STATE_FAILURE:
		return "failure";
	}

	return NULL;
}

static int provider_indicate_state(struct vpn_provider *provider,
				enum vpn_provider_state state)
{
	const char *str;
	enum vpn_provider_state old_state;

	str = state2string(state);
	DBG("provider %p state %s/%d", provider, str, state);
	if (str == NULL)
		return -EINVAL;

	old_state = provider->state;
	provider->state = state;

	if (state == VPN_PROVIDER_STATE_READY) {
		connman_dbus_property_changed_basic(provider->path,
					VPN_CONNECTION_INTERFACE, "Index",
					DBUS_TYPE_INT32, &provider->index);

		if (provider->family == AF_INET)
			connman_dbus_property_changed_dict(provider->path,
					VPN_CONNECTION_INTERFACE, "IPv4",
					append_ipv4, provider);
		else if (provider->family == AF_INET6)
			connman_dbus_property_changed_dict(provider->path,
					VPN_CONNECTION_INTERFACE, "IPv6",
					append_ipv6, provider);
	}

	if (old_state != state)
		connman_dbus_property_changed_basic(provider->path,
					VPN_CONNECTION_INTERFACE, "State",
					DBUS_TYPE_STRING, &str);

	/*
	 * We do not stay in failure state as clients like connmand can
	 * get confused about our current state.
	 */
	if (provider->state == VPN_PROVIDER_STATE_FAILURE)
		provider->state = VPN_PROVIDER_STATE_IDLE;

	return 0;
}

static void append_nameservers(DBusMessageIter *iter, char **servers)
{
	int i;

	DBG("%p", servers);

	for (i = 0; servers[i] != NULL; i++) {
		DBG("servers[%d] %s", i, servers[i]);
		dbus_message_iter_append_basic(iter,
					DBUS_TYPE_STRING, &servers[i]);
	}
}

static void append_dns(DBusMessageIter *iter, void *user_data)
{
	struct vpn_provider *provider = user_data;

	if (provider->nameservers != NULL)
		append_nameservers(iter, provider->nameservers);
}

static void append_state(DBusMessageIter *iter,
					struct vpn_provider *provider)
{
	char *str;

	switch (provider->state) {
	case VPN_PROVIDER_STATE_UNKNOWN:
	case VPN_PROVIDER_STATE_IDLE:
		str = "idle";
		break;
	case VPN_PROVIDER_STATE_CONNECT:
		str = "configuration";
		break;
	case VPN_PROVIDER_STATE_READY:
		str = "ready";
		break;
	case VPN_PROVIDER_STATE_DISCONNECT:
		str = "disconnect";
		break;
	case VPN_PROVIDER_STATE_FAILURE:
		str = "failure";
		break;
	}

	connman_dbus_dict_append_basic(iter, "State",
				DBUS_TYPE_STRING, &str);
}

static void append_properties(DBusMessageIter *iter,
					struct vpn_provider *provider)
{
	DBusMessageIter dict;
	GHashTableIter hash;
	gpointer value, key;

	connman_dbus_dict_open(iter, &dict);

	append_state(&dict, provider);

	if (provider->type != NULL)
		connman_dbus_dict_append_basic(&dict, "Type",
					DBUS_TYPE_STRING, &provider->type);

	if (provider->name != NULL)
		connman_dbus_dict_append_basic(&dict, "Name",
					DBUS_TYPE_STRING, &provider->name);

	if (provider->host != NULL)
		connman_dbus_dict_append_basic(&dict, "Host",
					DBUS_TYPE_STRING, &provider->host);
	if (provider->index >= 0)
		connman_dbus_dict_append_basic(&dict, "Index",
					DBUS_TYPE_INT32, &provider->index);
	if (provider->domain != NULL)
		connman_dbus_dict_append_basic(&dict, "Domain",
					DBUS_TYPE_STRING, &provider->domain);

	if (provider->family == AF_INET)
		connman_dbus_dict_append_dict(&dict, "IPv4", append_ipv4,
						provider);
	else if (provider->family == AF_INET6)
		connman_dbus_dict_append_dict(&dict, "IPv6", append_ipv6,
						provider);

	connman_dbus_dict_append_array(&dict, "Nameservers",
				DBUS_TYPE_STRING, append_dns, provider);

	connman_dbus_dict_append_array(&dict, "UserRoutes",
				DBUS_TYPE_DICT_ENTRY, append_routes,
				provider->user_routes);

	connman_dbus_dict_append_array(&dict, "ServerRoutes",
				DBUS_TYPE_DICT_ENTRY, append_routes,
				provider->routes);

	if (provider->setting_strings != NULL) {
		g_hash_table_iter_init(&hash, provider->setting_strings);

		while (g_hash_table_iter_next(&hash, &key, &value) == TRUE) {
			struct vpn_setting *setting = value;

			if (setting->hide_value == FALSE &&
							setting->value != NULL)
				connman_dbus_dict_append_basic(&dict, key,
							DBUS_TYPE_STRING,
							&setting->value);
		}
	}

	connman_dbus_dict_close(iter, &dict);
}

static void connection_added_signal(struct vpn_provider *provider)
{
	DBusMessage *signal;
	DBusMessageIter iter;

	signal = dbus_message_new_signal(VPN_MANAGER_PATH,
			VPN_MANAGER_INTERFACE, "ConnectionAdded");
	if (signal == NULL)
		return;

	dbus_message_iter_init_append(signal, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH,
							&provider->path);
	append_properties(&iter, provider);

	dbus_connection_send(connection, signal, NULL);
	dbus_message_unref(signal);
}

static connman_bool_t check_host(char **hosts, char *host)
{
	int i;

	if (hosts == NULL)
		return FALSE;

	for (i = 0; hosts[i] != NULL; i++) {
		if (g_strcmp0(hosts[i], host) == 0)
			return TRUE;
	}

	return FALSE;
}

static void provider_append_routes(gpointer key, gpointer value,
					gpointer user_data)
{
	struct vpn_route *route = value;
	struct vpn_provider *provider = user_data;
	int index = provider->index;

	if (handle_routes == FALSE)
		return;

	/*
	 * If the VPN administrator/user has given a route to
	 * VPN server, then we must discard that because the
	 * server cannot be contacted via VPN tunnel.
	 */
	if (check_host(provider->host_ip, route->network) == TRUE) {
		DBG("Discarding VPN route to %s via %s at index %d",
			route->network, route->gateway, index);
		return;
	}

	if (route->family == AF_INET6) {
		unsigned char prefix_len = atoi(route->netmask);

		connman_inet_add_ipv6_network_route(index, route->network,
							route->gateway,
							prefix_len);
	} else {
		connman_inet_add_network_route(index, route->network,
						route->gateway,
						route->netmask);
	}
}

static int set_connected(struct vpn_provider *provider,
					connman_bool_t connected)
{
	struct vpn_ipconfig *ipconfig;

	DBG("provider %p id %s connected %d", provider,
					provider->identifier, connected);

	if (connected == TRUE) {
		if (provider->family == AF_INET6)
			ipconfig = provider->ipconfig_ipv6;
		else
			ipconfig = provider->ipconfig_ipv4;

		__vpn_ipconfig_address_add(ipconfig, provider->family);

		if (handle_routes == TRUE)
			__vpn_ipconfig_gateway_add(ipconfig, provider->family);

		provider_indicate_state(provider,
					VPN_PROVIDER_STATE_READY);

		g_hash_table_foreach(provider->routes, provider_append_routes,
					provider);

		g_hash_table_foreach(provider->user_routes,
					provider_append_routes, provider);

	} else {
		provider_indicate_state(provider,
					VPN_PROVIDER_STATE_DISCONNECT);

		provider_indicate_state(provider,
					VPN_PROVIDER_STATE_IDLE);
	}

	return 0;
}

int vpn_provider_set_state(struct vpn_provider *provider,
					enum vpn_provider_state state)
{
	if (provider == NULL)
		return -EINVAL;

	switch (state) {
	case VPN_PROVIDER_STATE_UNKNOWN:
		return -EINVAL;
	case VPN_PROVIDER_STATE_IDLE:
		return set_connected(provider, FALSE);
	case VPN_PROVIDER_STATE_CONNECT:
		return provider_indicate_state(provider, state);
	case VPN_PROVIDER_STATE_READY:
		return set_connected(provider, TRUE);
	case VPN_PROVIDER_STATE_DISCONNECT:
		return provider_indicate_state(provider, state);
	case VPN_PROVIDER_STATE_FAILURE:
		return provider_indicate_state(provider, state);
	}
	return -EINVAL;
}

int vpn_provider_indicate_error(struct vpn_provider *provider,
					enum vpn_provider_error error)
{
	DBG("provider %p id %s error %d", provider, provider->identifier,
									error);

	switch (error) {
	case VPN_PROVIDER_ERROR_LOGIN_FAILED:
		break;
	case VPN_PROVIDER_ERROR_AUTH_FAILED:
		vpn_provider_set_state(provider, VPN_PROVIDER_STATE_FAILURE);
		break;
	case VPN_PROVIDER_ERROR_CONNECT_FAILED:
		break;
	default:
		break;
	}

	return 0;
}

static int connection_unregister(struct vpn_provider *provider)
{
	DBG("provider %p path %s", provider, provider->path);

	if (provider->path == NULL)
		return -EALREADY;

	g_dbus_unregister_interface(connection, provider->path,
				VPN_CONNECTION_INTERFACE);

	g_free(provider->path);
	provider->path = NULL;

	return 0;
}

static int connection_register(struct vpn_provider *provider)
{
	DBG("provider %p path %s", provider, provider->path);

	if (provider->path != NULL)
		return -EALREADY;

	provider->path = g_strdup_printf("%s/connection/%s", VPN_PATH,
						provider->identifier);

	g_dbus_register_interface(connection, provider->path,
				VPN_CONNECTION_INTERFACE,
				connection_methods, connection_signals,
				NULL, provider, NULL);

	return 0;
}

static void unregister_provider(gpointer data)
{
	struct vpn_provider *provider = data;

	configuration_count_del();

	connection_unregister(provider);

	vpn_provider_unref(provider);
}

static void provider_initialize(struct vpn_provider *provider)
{
	DBG("provider %p", provider);

	provider->index = 0;
	provider->fd = -1;
	provider->name = NULL;
	provider->type = NULL;
	provider->domain = NULL;
	provider->identifier = NULL;
	provider->user_networks = NULL;
	provider->routes = g_hash_table_new_full(g_direct_hash, g_direct_equal,
					NULL, free_route);
	provider->user_routes = g_hash_table_new_full(g_str_hash, g_str_equal,
					g_free, free_route);
	provider->setting_strings = g_hash_table_new_full(g_str_hash,
					g_str_equal, g_free, free_setting);
}

static struct vpn_provider *vpn_provider_new(void)
{
	struct vpn_provider *provider;

	provider = g_try_new0(struct vpn_provider, 1);
	if (provider == NULL)
		return NULL;

	provider->refcount = 1;

	DBG("provider %p", provider);
	provider_initialize(provider);

	return provider;
}

static struct vpn_provider *vpn_provider_get(const char *identifier)
{
	struct vpn_provider *provider;

	provider = g_hash_table_lookup(provider_hash, identifier);
	if (provider != NULL)
		return provider;

	provider = vpn_provider_new();
	if (provider == NULL)
		return NULL;

	DBG("provider %p", provider);

	provider->identifier = g_strdup(identifier);

	g_hash_table_insert(provider_hash, provider->identifier, provider);

	configuration_count_add();

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

static struct vpn_provider *provider_create_from_keyfile(GKeyFile *keyfile,
		const char *ident)
{
	struct vpn_provider *provider;

	if (keyfile == NULL || ident == NULL)
		return NULL;

	provider = __vpn_provider_lookup(ident);
	if (provider == NULL) {
		provider = vpn_provider_get(ident);
		if (provider == NULL) {
			DBG("can not create provider");
			return NULL;
		}

		provider_load_from_keyfile(provider, keyfile);

		if (provider->name == NULL || provider->host == NULL ||
				provider->domain == NULL) {
			DBG("cannot get name, host or domain");
			vpn_provider_unref(provider);
			return NULL;
		}

		if (provider_register(provider) == 0)
			connection_register(provider);
	}
	return provider;
}

static void provider_create_all_from_type(const char *provider_type)
{
	unsigned int i;
	char **providers;
	char *id, *type;
	GKeyFile *keyfile;

	DBG("provider type %s", provider_type);

	providers = __connman_storage_get_providers();

	if (providers == NULL)
		return;

	for (i = 0; providers[i] != NULL; i+=1) {

		if (strncmp(providers[i], "provider_", 9) != 0)
			continue;

		id = providers[i] + 9;
		keyfile = __connman_storage_load_provider(id);

		if (keyfile == NULL)
			continue;

		type = g_key_file_get_string(keyfile, id, "Type", NULL);

		DBG("keyfile %p id %s type %s", keyfile, id, type);

		if (strcmp(provider_type, type) != 0) {
			g_free(type);
			g_key_file_free(keyfile);
			continue;
		}

		if (provider_create_from_keyfile(keyfile, id) == NULL)
			DBG("could not create provider");

		g_free(type);
		g_key_file_free(keyfile);
	}
	g_strfreev(providers);
}

char *__vpn_provider_create_identifier(const char *host, const char *domain)
{
	char *ident;

	ident = g_strdup_printf("%s_%s", host, domain);
	if (ident == NULL)
		return NULL;

	provider_dbus_ident(ident);

	return ident;
}

int __vpn_provider_create(DBusMessage *msg)
{
	struct vpn_provider *provider;
	DBusMessageIter iter, array;
	const char *type = NULL, *name = NULL;
	const char *host = NULL, *domain = NULL;
	GSList *networks = NULL;
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
			else if (g_str_equal(key, "VPN.Domain") == TRUE ||
					g_str_equal(key, "Domain") == TRUE)
				dbus_message_iter_get_basic(&value, &domain);
			break;
		case DBUS_TYPE_ARRAY:
			if (g_str_equal(key, "UserRoutes") == TRUE)
				networks = get_user_networks(&value);
			break;
		}

		dbus_message_iter_next(&array);
	}

	if (host == NULL || domain == NULL)
		return -EINVAL;

	DBG("Type %s name %s networks %p", type, name, networks);

	if (type == NULL || name == NULL)
		return -EOPNOTSUPP;

	ident = __vpn_provider_create_identifier(host, domain);
	DBG("ident %s", ident);

	provider = __vpn_provider_lookup(ident);
	if (provider == NULL) {
		provider = vpn_provider_get(ident);
		if (provider == NULL) {
			DBG("can not create provider");
			g_free(ident);
			return -EOPNOTSUPP;
		}

		provider->host = g_strdup(host);
		provider->domain = g_strdup(domain);
		provider->name = g_strdup(name);
		provider->type = g_strdup(type);

		if (provider_register(provider) == 0)
			vpn_provider_load(provider);

		provider_resolv_host_addr(provider);
	}

	if (networks != NULL) {
		g_slist_free_full(provider->user_networks, free_route);
		provider->user_networks = networks;
		set_user_networks(provider, provider->user_networks);
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
			vpn_provider_set_string(provider, key, str);
			break;
		}

		dbus_message_iter_next(&array);
	}

	g_free(ident);

	vpn_provider_save(provider);

	err = provider_register(provider);
	if (err != 0 && err != -EALREADY)
		return err;

	connection_register(provider);

	DBG("provider %p index %d path %s", provider, provider->index,
							provider->path);

	g_dbus_send_reply(connection, msg,
				DBUS_TYPE_OBJECT_PATH, &provider->path,
				DBUS_TYPE_INVALID);

	connection_added_signal(provider);

	return 0;
}

static const char *get_string(GHashTable *settings, const char *key)
{
	DBG("settings %p key %s", settings, key);

	return g_hash_table_lookup(settings, key);
}

static GSList *parse_user_networks(const char *network_str)
{
	GSList *networks = NULL;
	char **elems = g_strsplit(network_str, ",", 0);
	int i = 0;

	if (elems == NULL)
		return NULL;

	while (elems[i] != NULL) {
		struct vpn_route *vpn_route;
		char *network, *netmask, *gateway;
		int family;
		char **route;

		route = g_strsplit(elems[i], "/", 0);
		if (route == NULL)
			goto next;

		network = route[0];
		if (network == NULL || network[0] == '\0')
			goto next;

		family = connman_inet_check_ipaddress(network);
		if (family < 0) {
			DBG("Cannot get address family of %s (%d/%s)", network,
				family, gai_strerror(family));

			goto next;
		}

		switch (family) {
		case AF_INET:
			break;
		case AF_INET6:
			break;
		default:
			DBG("Unsupported address family %d", family);
			goto next;
		}

		netmask = route[1];
		if (netmask == NULL || netmask[0] == '\0')
			goto next;

		gateway = route[2];

		vpn_route = g_try_new0(struct vpn_route, 1);
		if (vpn_route == NULL) {
			g_strfreev(route);
			break;
		}

		vpn_route->family = family;
		vpn_route->network = g_strdup(network);
		vpn_route->netmask = g_strdup(netmask);
		vpn_route->gateway = g_strdup(gateway);

		DBG("route %s/%s%s%s", network, netmask,
			gateway ? " via " : "", gateway ? gateway : "");

		networks = g_slist_prepend(networks, vpn_route);

	next:
		g_strfreev(route);
		i++;
	}

	g_strfreev(elems);

	return g_slist_reverse(networks);
}

int __vpn_provider_create_from_config(GHashTable *settings,
				const char *config_ident,
				const char *config_entry)
{
	struct vpn_provider *provider;
	const char *type, *name, *host, *domain, *networks_str;
	GSList *networks;
	char *ident = NULL;
	GHashTableIter hash;
	gpointer value, key;
	int err;

	type = get_string(settings, "Type");
	name = get_string(settings, "Name");
	host = get_string(settings, "Host");
	domain = get_string(settings, "Domain");
	networks_str = get_string(settings, "Networks");
	networks = parse_user_networks(networks_str);

	if (host == NULL || domain == NULL) {
		err = -EINVAL;
		goto fail;
	}

	DBG("type %s name %s networks %s", type, name, networks_str);

	if (type == NULL || name == NULL) {
		err = -EOPNOTSUPP;
		goto fail;
	}

	ident = __vpn_provider_create_identifier(host, domain);
	DBG("ident %s", ident);

	provider = __vpn_provider_lookup(ident);
	if (provider == NULL) {
		provider = vpn_provider_get(ident);
		if (provider == NULL) {
			DBG("can not create provider");
			err = -EOPNOTSUPP;
			goto fail;
		}

		provider->host = g_strdup(host);
		provider->domain = g_strdup(domain);
		provider->name = g_strdup(name);
		provider->type = g_ascii_strdown(type, -1);

		provider->config_file = g_strdup(config_ident);
		provider->config_entry = g_strdup(config_entry);

		if (provider_register(provider) == 0)
			vpn_provider_load(provider);

		provider_resolv_host_addr(provider);
	}

	if (networks != NULL) {
		g_slist_free_full(provider->user_networks, free_route);
		provider->user_networks = networks;
		set_user_networks(provider, provider->user_networks);
	}

	g_hash_table_iter_init(&hash, settings);

	while (g_hash_table_iter_next(&hash, &key, &value) == TRUE)
		vpn_provider_set_string(provider, key, value);

	vpn_provider_save(provider);

	err = provider_register(provider);
	if (err != 0 && err != -EALREADY)
		goto fail;

	connection_register(provider);

	DBG("provider %p index %d path %s", provider, provider->index,
							provider->path);

	connection_added_signal(provider);

	g_free(ident);

	return 0;

fail:
	g_free(ident);
	g_slist_free_full(networks, free_route);

	return err;
}

static void append_connection_structs(DBusMessageIter *iter, void *user_data)
{
	DBusMessageIter entry;
	GHashTableIter hash;
	gpointer value, key;

	g_hash_table_iter_init(&hash, provider_hash);

	while (g_hash_table_iter_next(&hash, &key, &value) == TRUE) {
		struct vpn_provider *provider = value;

		DBG("path %s", provider->path);

		if (provider->identifier == NULL)
			continue;

		dbus_message_iter_open_container(iter, DBUS_TYPE_STRUCT,
				NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_OBJECT_PATH,
				&provider->path);
		append_properties(&entry, provider);
		dbus_message_iter_close_container(iter, &entry);
	}
}

DBusMessage *__vpn_provider_get_connections(DBusMessage *msg)
{
	DBusMessage *reply;

	DBG("");

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	__connman_dbus_append_objpath_dict_array(reply,
			append_connection_structs, NULL);

	return reply;
}

const char * __vpn_provider_get_ident(struct vpn_provider *provider)
{
	if (provider == NULL)
		return NULL;

	return provider->identifier;
}

static int set_string(struct vpn_provider *provider,
		const char *key, const char *value, gboolean hide_value)
{
	DBG("provider %p key %s value %s", provider, key,
		hide_value ? "<not printed>" : value);

	if (g_str_equal(key, "Type") == TRUE) {
		g_free(provider->type);
		provider->type = g_ascii_strdown(value, -1);
		send_value(provider->path, "Type", provider->type);
	} else if (g_str_equal(key, "Name") == TRUE) {
		g_free(provider->name);
		provider->name = g_strdup(value);
		send_value(provider->path, "Name", provider->name);
	} else if (g_str_equal(key, "Host") == TRUE) {
		g_free(provider->host);
		provider->host = g_strdup(value);
		send_value(provider->path, "Host", provider->host);
	} else if (g_str_equal(key, "VPN.Domain") == TRUE ||
			g_str_equal(key, "Domain") == TRUE) {
		g_free(provider->domain);
		provider->domain = g_strdup(value);
		send_value(provider->path, "Domain", provider->domain);
	} else {
		struct vpn_setting *setting;

		setting = g_try_new(struct vpn_setting, 1);
		if (setting == NULL)
			return -ENOMEM;

		setting->value = g_strdup(value);
		setting->hide_value = hide_value;

		if (hide_value == FALSE)
			send_value(provider->path, key, setting->value);

		g_hash_table_replace(provider->setting_strings,
				g_strdup(key), setting);
	}

	return 0;
}

int vpn_provider_set_string(struct vpn_provider *provider,
					const char *key, const char *value)
{
	return set_string(provider, key, value, FALSE);
}

int vpn_provider_set_string_hide_value(struct vpn_provider *provider,
					const char *key, const char *value)
{
	return set_string(provider, key, value, TRUE);
}

const char *vpn_provider_get_string(struct vpn_provider *provider,
							const char *key)
{
	struct vpn_setting *setting;

	DBG("provider %p key %s", provider, key);

	if (g_str_equal(key, "Type") == TRUE)
		return provider->type;
	else if (g_str_equal(key, "Name") == TRUE)
		return provider->name;
	else if (g_str_equal(key, "Host") == TRUE)
		return provider->host;
	else if (g_str_equal(key, "HostIP") == TRUE) {
		if (provider->host_ip == NULL ||
				provider->host_ip[0] == NULL)
			return provider->host;
		else
			return provider->host_ip[0];
	} else if (g_str_equal(key, "VPN.Domain") == TRUE ||
			g_str_equal(key, "Domain") == TRUE)
		return provider->domain;

	setting = g_hash_table_lookup(provider->setting_strings, key);
	if (setting == NULL)
		return NULL;

	return setting->value;
}

connman_bool_t __vpn_provider_check_routes(struct vpn_provider *provider)
{
	if (provider == NULL)
		return FALSE;

	if (provider->user_routes != NULL &&
			g_hash_table_size(provider->user_routes) > 0)
		return TRUE;

	if (provider->routes != NULL &&
			g_hash_table_size(provider->routes) > 0)
		return TRUE;

	return FALSE;
}

void *vpn_provider_get_data(struct vpn_provider *provider)
{
	return provider->driver_data;
}

void vpn_provider_set_data(struct vpn_provider *provider, void *data)
{
	provider->driver_data = data;
}

void vpn_provider_set_index(struct vpn_provider *provider, int index)
{
	DBG("index %d provider %p", index, provider);

	if (provider->ipconfig_ipv4 == NULL) {
		provider->ipconfig_ipv4 = __vpn_ipconfig_create(index,
								AF_INET);
		if (provider->ipconfig_ipv4 == NULL) {
			DBG("Couldnt create ipconfig for IPv4");
			goto done;
		}
	}

	__vpn_ipconfig_set_index(provider->ipconfig_ipv4, index);

	if (provider->ipconfig_ipv6 == NULL) {
		provider->ipconfig_ipv6 = __vpn_ipconfig_create(index,
								AF_INET6);
		if (provider->ipconfig_ipv6 == NULL) {
			DBG("Couldnt create ipconfig for IPv6");
			goto done;
		}
	}

	__vpn_ipconfig_set_index(provider->ipconfig_ipv6, index);

done:
	provider->index = index;
}

int vpn_provider_get_index(struct vpn_provider *provider)
{
	return provider->index;
}

int vpn_provider_set_ipaddress(struct vpn_provider *provider,
					struct connman_ipaddress *ipaddress)
{
	struct vpn_ipconfig *ipconfig = NULL;

	switch (ipaddress->family) {
	case AF_INET:
		ipconfig = provider->ipconfig_ipv4;
		break;
	case AF_INET6:
		ipconfig = provider->ipconfig_ipv6;
		break;
	default:
		break;
	}

	DBG("provider %p ipconfig %p family %d", provider, ipconfig,
							ipaddress->family);

	if (ipconfig == NULL)
		return -EINVAL;

	provider->family = ipaddress->family;

	__vpn_ipconfig_set_local(ipconfig, ipaddress->local);
	__vpn_ipconfig_set_peer(ipconfig, ipaddress->peer);
	__vpn_ipconfig_set_broadcast(ipconfig, ipaddress->broadcast);
	__vpn_ipconfig_set_gateway(ipconfig, ipaddress->gateway);
	__vpn_ipconfig_set_prefixlen(ipconfig, ipaddress->prefixlen);

	return 0;
}

int vpn_provider_set_pac(struct vpn_provider *provider,
				const char *pac)
{
	DBG("provider %p pac %s", provider, pac);

	return 0;
}


int vpn_provider_set_domain(struct vpn_provider *provider,
					const char *domain)
{
	DBG("provider %p domain %s", provider, domain);

	g_free(provider->domain);
	provider->domain = g_strdup(domain);

	return 0;
}

int vpn_provider_set_nameservers(struct vpn_provider *provider,
					const char *nameservers)
{
	DBG("provider %p nameservers %s", provider, nameservers);

	g_strfreev(provider->nameservers);
	provider->nameservers = NULL;

	if (nameservers == NULL)
		return 0;

	provider->nameservers = g_strsplit(nameservers, " ", 0);

	return 0;
}

enum provider_route_type {
	PROVIDER_ROUTE_TYPE_NONE = 0,
	PROVIDER_ROUTE_TYPE_MASK = 1,
	PROVIDER_ROUTE_TYPE_ADDR = 2,
	PROVIDER_ROUTE_TYPE_GW   = 3,
};

static int route_env_parse(struct vpn_provider *provider, const char *key,
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
		} else if (g_str_has_prefix(key,
					"CISCO_IPV6_SPLIT_INC_") == TRUE) {
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

int vpn_provider_append_route(struct vpn_provider *provider,
					const char *key, const char *value)
{
	struct vpn_route *route;
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
		route = g_try_new0(struct vpn_route, 1);
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
		route->network = g_strdup(value);
		break;
	case PROVIDER_ROUTE_TYPE_GW:
		route->gateway = g_strdup(value);
		break;
	}

	if (handle_routes == FALSE) {
		if (route->netmask != NULL && route->gateway != NULL &&
							route->network != NULL)
			provider_schedule_changed(provider);
	}

	return 0;
}

const char *vpn_provider_get_driver_name(struct vpn_provider *provider)
{
	if (provider->driver == NULL)
		return NULL;

	return provider->driver->name;
}

const char *vpn_provider_get_save_group(struct vpn_provider *provider)
{
	return provider->identifier;
}

static gint compare_priority(gconstpointer a, gconstpointer b)
{
	return 0;
}

static void clean_provider(gpointer key, gpointer value, gpointer user_data)
{
	struct vpn_provider *provider = value;

	if (provider->driver != NULL && provider->driver->remove)
		provider->driver->remove(provider);

	connection_unregister(provider);
}

int vpn_provider_driver_register(struct vpn_provider_driver *driver)
{
	DBG("driver %p name %s", driver, driver->name);

	driver_list = g_slist_insert_sorted(driver_list, driver,
							compare_priority);
	provider_create_all_from_type(driver->name);
	return 0;
}

void vpn_provider_driver_unregister(struct vpn_provider_driver *driver)
{
	GHashTableIter iter;
	gpointer value, key;

	DBG("driver %p name %s", driver, driver->name);

	driver_list = g_slist_remove(driver_list, driver);

	g_hash_table_iter_init(&iter, provider_hash);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		struct vpn_provider *provider = value;

		if (provider != NULL && provider->driver != NULL &&
				provider->driver->type == driver->type &&
				g_strcmp0(provider->driver->name,
							driver->name) == 0) {
			provider->driver = NULL;
		}
	}
}

static gboolean check_vpn_count(gpointer data)
{
	if (configuration_count == 0) {
		connman_info("No VPN configurations found, quitting.");
		raise(SIGTERM);
	}

	return FALSE;
}

void __vpn_provider_check_connections(void)
{
	/*
	 * If we were started when there is no providers configured,
	 * then just quit. This happens when connman starts and its
	 * vpn plugin asks connman-vpnd if it has any connections
	 * configured. If there are none, then we can stop the vpn
	 * daemon.
	 */
	g_timeout_add(1000, check_vpn_count, NULL);
}

const char *vpn_provider_get_name(struct vpn_provider *provider)
{
	return provider->name;
}

const char *vpn_provider_get_host(struct vpn_provider *provider)
{
	return provider->host;
}

const char *vpn_provider_get_path(struct vpn_provider *provider)
{
	return provider->path;
}

static int agent_probe(struct connman_agent *agent)
{
	DBG("agent %p", agent);
	return 0;
}

static void agent_remove(struct connman_agent *agent)
{
	DBG("agent %p", agent);
}

static struct connman_agent_driver agent_driver = {
	.name		= "vpn",
	.interface      = VPN_AGENT_INTERFACE,
	.probe		= agent_probe,
	.remove		= agent_remove,
};

static void remove_unprovisioned_providers()
{
	gchar **providers;
	GKeyFile *keyfile, *configkeyfile;
	char *file, *section;
	int i = 0;

	providers = __connman_storage_get_providers();
	if (providers == NULL)
		return;

	for (; providers[i] != NULL; i++) {
		char *group = providers[i] + sizeof("provider_") - 1;
		file = section = NULL;
		keyfile = configkeyfile = NULL;

		keyfile = __connman_storage_load_provider(group);
		if (keyfile == NULL)
			continue;

		file = g_key_file_get_string(keyfile, group,
					"Config.file", NULL);
		if (file == NULL)
			goto next;

		section = g_key_file_get_string(keyfile, group,
					"Config.ident", NULL);
		if (section == NULL)
			goto next;

		configkeyfile = __connman_storage_load_provider_config(file);
		if (configkeyfile == NULL) {
			/*
			 * Config file is missing, remove the provisioned
			 * service.
			 */
			__connman_storage_remove_provider(group);
			goto next;
		}

		if (g_key_file_has_group(configkeyfile, section) == FALSE)
			/*
			 * Config section is missing, remove the provisioned
			 * service.
			 */
			__connman_storage_remove_provider(group);

	next:
		if (keyfile != NULL)
			g_key_file_free(keyfile);

		if (configkeyfile != NULL)
			g_key_file_free(configkeyfile);

		g_free(section);
		g_free(file);
	}

	g_strfreev(providers);
}

int __vpn_provider_init(gboolean do_routes)
{
	int err;

	DBG("");

	handle_routes = do_routes;

	err = connman_agent_driver_register(&agent_driver);
	if (err < 0) {
		connman_error("Cannot register agent driver for %s",
						agent_driver.name);
		return err;
	}

	connection = connman_dbus_get_connection();

	remove_unprovisioned_providers();

	provider_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						NULL, unregister_provider);
	return 0;
}

void __vpn_provider_cleanup(void)
{
	DBG("");

	g_hash_table_foreach(provider_hash, clean_provider, NULL);

	g_hash_table_destroy(provider_hash);
	provider_hash = NULL;

	connman_agent_driver_unregister(&agent_driver);

	dbus_connection_unref(connection);
}
