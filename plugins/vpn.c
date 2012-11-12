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

#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <glib.h>

#include <gdbus.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/technology.h>
#include <connman/plugin.h>
#include <connman/log.h>
#include <connman/dbus.h>
#include <connman/provider.h>
#include <connman/ipaddress.h>
#include <connman/vpn-dbus.h>

#define DBUS_TIMEOUT 10000

static DBusConnection *connection;

static GHashTable *vpn_connections = NULL;
static gboolean starting_vpnd = TRUE;
static guint watch;
static guint added_watch;
static guint removed_watch;
static guint property_watch;

struct connection_data {
	char *path;
	struct connman_provider *provider;
	int index;
	DBusPendingCall *call;

	char *state;
	char *type;
	char *name;
	char *host;
	char *domain;
	char **nameservers;

	GHashTable *setting_strings;

	struct connman_ipaddress *ip;
};

static int set_string(struct connman_provider *provider,
					const char *key, const char *value)
{
	struct connection_data *data;

	data = connman_provider_get_data(provider);
	if (data == NULL)
		return -EINVAL;

	DBG("data %p provider %p key %s value %s", data, provider, key, value);

	if (g_str_equal(key, "Type") == TRUE) {
		g_free(data->type);
		data->type = g_strdup(value);
	} else if (g_str_equal(key, "Name") == TRUE) {
		g_free(data->name);
		data->name = g_strdup(value);
	} else if (g_str_equal(key, "Host") == TRUE) {
		g_free(data->host);
		data->host = g_strdup(value);
	} else if (g_str_equal(key, "VPN.Domain") == TRUE ||
				g_str_equal(key, "Domain") == TRUE) {
		g_free(data->domain);
		data->domain = g_strdup(value);
	} else
		g_hash_table_replace(data->setting_strings,
				g_strdup(key), g_strdup(value));
	return 0;
}

static const char *get_string(struct connman_provider *provider,
							const char *key)
{
	struct connection_data *data;

	data = connman_provider_get_data(provider);
	if (data == NULL)
		return NULL;

	DBG("data %p provider %p key %s", data, provider, key);

	if (g_str_equal(key, "Type") == TRUE)
		return data->type;
	else if (g_str_equal(key, "Name") == TRUE)
		return data->name;
	else if (g_str_equal(key, "Host") == TRUE)
		return data->host;
	else if (g_str_equal(key, "VPN.Domain") == TRUE)
		return data->domain;

	return g_hash_table_lookup(data->setting_strings, key);
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

static void set_provider_state(struct connection_data *data)
{
	if (g_str_equal(data->state, "ready") == TRUE)
		connman_provider_set_state(data->provider,
					CONNMAN_PROVIDER_STATE_READY);
	else if (g_str_equal(data->state, "configuration") == TRUE)
		connman_provider_set_state(data->provider,
					CONNMAN_PROVIDER_STATE_CONNECT);
	else if (g_str_equal(data->state, "idle") == TRUE)
		connman_provider_set_state(data->provider,
					CONNMAN_PROVIDER_STATE_IDLE);
	else if (g_str_equal(data->state, "disconnect") == TRUE)
		connman_provider_set_state(data->provider,
					CONNMAN_PROVIDER_STATE_DISCONNECT);
	else if (g_str_equal(data->state, "failure") == TRUE)
		connman_provider_set_state(data->provider,
					CONNMAN_PROVIDER_STATE_FAILURE);
	else
		connman_provider_set_state(data->provider,
					CONNMAN_PROVIDER_STATE_UNKNOWN);
}

static int create_provider(struct connection_data *data, void *user_data)
{
	struct connman_provider_driver *driver = user_data;
	char *ident;
	int err = 0;

	DBG("%s", data->path);

	ident = g_strdup(get_ident(data->path));

	data->provider = connman_provider_get(ident);
	if (data->provider == NULL) {
		err = -ENOMEM;
		goto out;
	}

	DBG("provider %p name %s", data->provider, data->name);

	connman_provider_set_data(data->provider, data);
	connman_provider_set_driver(data->provider, driver);

	err = connman_provider_create_service(data->provider);
	if (err == 0) {
		if (g_str_equal(data->state, "ready") == TRUE) {
			connman_provider_set_index(data->provider,
							data->index);
			if (data->ip != NULL)
				connman_provider_set_ipaddress(data->provider,
								data->ip);
		}

		set_provider_state(data);
	}

out:
	g_free(ident);
	return err;
}

static struct connection_data *create_connection_data(const char *path)
{
	struct connection_data *data;

	data = g_try_new0(struct connection_data, 1);
	if (data == NULL)
		return NULL;

	DBG("path %s", path);

	data->path = g_strdup(path);
	data->index = -1;

	data->setting_strings = g_hash_table_new_full(g_str_hash,
						g_str_equal, g_free, g_free);

	return data;
}

static int extract_ip(DBusMessageIter *array, int family,
						struct connection_data *data)
{
	DBusMessageIter dict;
	char *address = NULL, *gateway = NULL, *netmask = NULL, *peer = NULL;
	unsigned char prefix_len;

	if (dbus_message_iter_get_arg_type(array) != DBUS_TYPE_ARRAY)
		return -EINVAL;

	dbus_message_iter_recurse(array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		if (g_str_equal(key, "Address") == TRUE) {
			dbus_message_iter_get_basic(&value, &address);
			DBG("address %s", address);
		} else if (g_str_equal(key, "Netmask") == TRUE) {
			dbus_message_iter_get_basic(&value, &netmask);
			DBG("netmask %s", netmask);
		} else if (g_str_equal(key, "PrefixLength") == TRUE) {
			dbus_message_iter_get_basic(&value, &netmask);
			DBG("prefix length %s", netmask);
		} else if (g_str_equal(key, "Peer") == TRUE) {
			dbus_message_iter_get_basic(&value, &peer);
			DBG("peer %s", peer);
		} else if (g_str_equal(key, "Gateway") == TRUE) {
			dbus_message_iter_get_basic(&value, &gateway);
			DBG("gateway %s", gateway);
		}

		dbus_message_iter_next(&dict);
	}

	data->ip = connman_ipaddress_alloc(family);
	if (data->ip == NULL)
		return -ENOMEM;

	switch (family) {
	case AF_INET:
		connman_ipaddress_set_ipv4(data->ip, address, netmask,
								gateway);
		break;
	case AF_INET6:
		prefix_len = atoi(netmask);
		connman_ipaddress_set_ipv6(data->ip, address, prefix_len,
								gateway);
		break;
	default:
		return -EINVAL;
	}

	connman_ipaddress_set_peer(data->ip, peer);

	return 0;
}

static int extract_nameservers(DBusMessageIter *array,
						struct connection_data *data)
{
	DBusMessageIter entry;
	char **nameservers = NULL;
	int i = 0;

	dbus_message_iter_recurse(array, &entry);

	while (dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_STRING) {
		const char *nameserver;

		dbus_message_iter_get_basic(&entry, &nameserver);

		nameservers = g_try_renew(char *, nameservers, i + 2);
		if (nameservers == NULL)
			return -ENOMEM;

		DBG("[%d] %s", i, nameserver);

		nameservers[i] = g_strdup(nameserver);
		if (nameservers[i] == NULL)
			return -ENOMEM;

		nameservers[++i] = NULL;

		dbus_message_iter_next(&entry);
	}

	g_strfreev(data->nameservers);
	data->nameservers = nameservers;

	return 0;
}

static void connect_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply;
	DBusError error;

	if (dbus_pending_call_get_completed(call) == FALSE)
		return;

	DBG("user_data %p", user_data);

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, reply) == TRUE) {
		if (dbus_error_has_name(&error, CONNMAN_ERROR_INTERFACE
						".InProgress") == FALSE) {
			connman_error("Connect reply: %s (%s)", error.message,
								error.name);
			dbus_error_free(&error);
			goto done;
		}
		dbus_error_free(&error);
	}

	/*
	 * The vpn connection is up when we get a "ready" state
	 * property so at this point we do nothing for the provider
	 * state.
	 */

done:
	dbus_message_unref(reply);

	dbus_pending_call_unref(call);
}

static int connect_provider(struct connection_data *data, void *user_data)
{
	DBusPendingCall *call;
	DBusMessage *message;

	DBG("data %p", data);

	message = dbus_message_new_method_call(VPN_SERVICE, data->path,
					VPN_CONNECTION_INTERFACE,
					VPN_CONNECT);
	if (message == NULL)
		return -ENOMEM;

	if (dbus_connection_send_with_reply(connection, message,
					&call, DBUS_TIMEOUT) == FALSE) {
		connman_error("Unable to call %s.%s()",
			VPN_CONNECTION_INTERFACE, VPN_CONNECT);
		dbus_message_unref(message);
		return -EINVAL;
	}

	if (call == NULL) {
		dbus_message_unref(message);
		return -EINVAL;
	}

	dbus_pending_call_set_notify(call, connect_reply, NULL, NULL);

	dbus_message_unref(message);

	return -EINPROGRESS;
}

static void add_connection(const char *path, DBusMessageIter *properties,
			void *user_data)
{
	struct connection_data *data;
	int err;

	data = g_hash_table_lookup(vpn_connections, path);
	if (data != NULL)
		return;

	data = create_connection_data(path);
	if (data == NULL)
		return;

	DBG("data %p path %s", data, path);

	while (dbus_message_iter_get_arg_type(properties) ==
			DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;
		char *str;

		dbus_message_iter_recurse(properties, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		if (g_str_equal(key, "State") == TRUE) {
			dbus_message_iter_get_basic(&value, &str);
			DBG("state %s -> %s", data->state, str);
			data->state = g_strdup(str);
		} else if (g_str_equal(key, "IPv4") == TRUE) {
			extract_ip(&value, AF_INET, data);
		} else if (g_str_equal(key, "IPv6") == TRUE) {
			extract_ip(&value, AF_INET6, data);
		} else if (g_str_equal(key, "Name") == TRUE) {
			dbus_message_iter_get_basic(&value, &str);
			data->name = g_strdup(str);
		} else if (g_str_equal(key, "Type") == TRUE) {
			dbus_message_iter_get_basic(&value, &str);
			data->type = g_strdup(str);
		} else if (g_str_equal(key, "Host") == TRUE) {
			dbus_message_iter_get_basic(&value, &str);
			data->host = g_strdup(str);
		} else if (g_str_equal(key, "Domain") == TRUE) {
			dbus_message_iter_get_basic(&value, &str);
			data->domain = g_strdup(str);
		} else if (g_str_equal(key, "Nameservers") == TRUE) {
			extract_nameservers(&value, data);
		} else if (g_str_equal(key, "Index") == TRUE) {
			dbus_message_iter_get_basic(&value, &data->index);
		} else {
			if (dbus_message_iter_get_arg_type(&value) ==
							DBUS_TYPE_STRING) {
				dbus_message_iter_get_basic(&value, &str);
				g_hash_table_replace(data->setting_strings,
						g_strdup(key), g_strdup(str));
			} else {
				DBG("unknown key %s", key);
			}
		}

		dbus_message_iter_next(properties);
	}

	g_hash_table_insert(vpn_connections, g_strdup(path), data);

	err = create_provider(data, user_data);
	if (err < 0)
		goto out;

	return;

out:
	DBG("removing %s", path);
	g_hash_table_remove(vpn_connections, path);
}

static void get_connections_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply;
	DBusError error;
	DBusMessageIter array, dict;
	const char *signature = DBUS_TYPE_ARRAY_AS_STRING
		DBUS_STRUCT_BEGIN_CHAR_AS_STRING
		DBUS_TYPE_OBJECT_PATH_AS_STRING
		DBUS_TYPE_ARRAY_AS_STRING
		DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
		DBUS_TYPE_STRING_AS_STRING
		DBUS_TYPE_VARIANT_AS_STRING
		DBUS_DICT_ENTRY_END_CHAR_AS_STRING
		DBUS_STRUCT_END_CHAR_AS_STRING;

	DBG("");

	reply = dbus_pending_call_steal_reply(call);

	if (dbus_message_has_signature(reply, signature) == FALSE) {
		connman_error("vpnd signature \"%s\" does not match "
							"expected \"%s\"",
			dbus_message_get_signature(reply), signature);
		goto done;
	}

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, reply) == TRUE) {
		connman_error("%s", error.message);
		dbus_error_free(&error);
		goto done;
	}

	if (dbus_message_iter_init(reply, &array) == FALSE)
		goto done;

	dbus_message_iter_recurse(&array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_STRUCT) {
		DBusMessageIter value, properties;
		const char *path;

		dbus_message_iter_recurse(&dict, &value);
		dbus_message_iter_get_basic(&value, &path);

		dbus_message_iter_next(&value);
		dbus_message_iter_recurse(&value, &properties);

		add_connection(path, &properties, user_data);

		dbus_message_iter_next(&dict);
	}

done:
	dbus_message_unref(reply);

	dbus_pending_call_unref(call);
}

static int get_connections(void *user_data)
{
	DBusPendingCall *call;
	DBusMessage *message;

	DBG("");

	message = dbus_message_new_method_call(VPN_SERVICE, "/",
					VPN_MANAGER_INTERFACE,
					GET_CONNECTIONS);
	if (message == NULL)
		return -ENOMEM;

	if (dbus_connection_send_with_reply(connection, message,
					&call, DBUS_TIMEOUT) == FALSE) {
		connman_error("Unable to call %s.%s()", VPN_MANAGER_INTERFACE,
							GET_CONNECTIONS);
		dbus_message_unref(message);
		return -EINVAL;
	}

	if (call == NULL) {
		dbus_message_unref(message);
		return -EINVAL;
	}

	dbus_pending_call_set_notify(call, get_connections_reply,
							user_data, NULL);

	dbus_message_unref(message);

	return -EINPROGRESS;
}

static int provider_probe(struct connman_provider *provider)
{
	return 0;
}

static void remove_connection_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply;
	DBusError error;

	DBG("");

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, reply) == TRUE) {
		/*
		 * If the returned error is NotFound, it means that we
		 * have actually removed the provider in vpnd already.
		 */
		if (dbus_error_has_name(&error, CONNMAN_ERROR_INTERFACE
						".NotFound") == FALSE)
			connman_error("%s", error.message);

		dbus_error_free(&error);
	}

	dbus_message_unref(reply);

	dbus_pending_call_unref(call);
}

static int provider_remove(struct connman_provider *provider)
{
	DBusPendingCall *call;
	DBusMessage *message;
	struct connection_data *data;

	data = connman_provider_get_data(provider);

	DBG("provider %p data %p", provider, data);

	/*
	 * When provider.c:provider_remove() calls this function,
	 * it will remove the provider itself after the call.
	 * This means that we cannot use the provider pointer later
	 * as it is no longer valid.
	 */
	data->provider = NULL;

	message = dbus_message_new_method_call(VPN_SERVICE, "/",
					VPN_MANAGER_INTERFACE,
					VPN_REMOVE);
	if (message == NULL)
		return -ENOMEM;

	dbus_message_append_args(message, DBUS_TYPE_OBJECT_PATH, &data->path,
				NULL);

	if (dbus_connection_send_with_reply(connection, message,
					&call, DBUS_TIMEOUT) == FALSE) {
		connman_error("Unable to call %s.%s()", VPN_MANAGER_INTERFACE,
							VPN_REMOVE);
		dbus_message_unref(message);
		return -EINVAL;
	}

	if (call == NULL) {
		dbus_message_unref(message);
		return -EINVAL;
	}

	dbus_pending_call_set_notify(call, remove_connection_reply,
							NULL, NULL);

	dbus_message_unref(message);

	return 0;
}

static int provider_connect(struct connman_provider *provider)
{
	struct connection_data *data;

	data = connman_provider_get_data(provider);
	if (data == NULL)
		return -EINVAL;

	return connect_provider(data, NULL);

}

static void disconnect_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply;
	DBusError error;

	DBG("");

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, reply) == TRUE) {
		connman_error("%s", error.message);
		dbus_error_free(&error);
		goto done;
	}

done:
	dbus_message_unref(reply);

	dbus_pending_call_unref(call);
}

static int disconnect_provider(struct connection_data *data)
{
	DBusPendingCall *call;
	DBusMessage *message;

	DBG("data %p path %s", data, data->path);

	message = dbus_message_new_method_call(VPN_SERVICE, data->path,
					VPN_CONNECTION_INTERFACE,
					VPN_DISCONNECT);
	if (message == NULL)
		return -ENOMEM;

	if (dbus_connection_send_with_reply(connection, message,
					&call, DBUS_TIMEOUT) == FALSE) {
		connman_error("Unable to call %s.%s()",
			VPN_CONNECTION_INTERFACE, VPN_DISCONNECT);
		dbus_message_unref(message);
		return -EINVAL;
	}

	if (call == NULL) {
		dbus_message_unref(message);
		return -EINVAL;
	}

	dbus_pending_call_set_notify(call, disconnect_reply, NULL, NULL);

	dbus_message_unref(message);

	connman_provider_set_state(data->provider,
					CONNMAN_PROVIDER_STATE_DISCONNECT);
	/*
	 * We return 0 here instead of -EINPROGRESS because
	 * __connman_service_disconnect() needs to return something
	 * to gdbus so that gdbus will not call Disconnect() more
	 * than once. This way we do not need to pass the dbus reply
	 * message around the code.
	 */
	return 0;
}

static int provider_disconnect(struct connman_provider *provider)
{
	struct connection_data *data;

	DBG("provider %p", provider);

	data = connman_provider_get_data(provider);
	if (data == NULL)
		return -EINVAL;

	if (g_str_equal(data->state, "ready") == TRUE ||
			g_str_equal(data->state, "configuration") == TRUE)
		return disconnect_provider(data);

	return 0;
}

static void configuration_create_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply;
	DBusError error;
	DBusMessageIter iter;
	const char *signature = DBUS_TYPE_OBJECT_PATH_AS_STRING;
	const char *path;

	DBG("user %p", user_data);

	reply = dbus_pending_call_steal_reply(call);

	if (dbus_message_has_signature(reply, signature) == FALSE) {
		connman_error("vpn configuration signature \"%s\" does not "
						"match expected \"%s\"",
			dbus_message_get_signature(reply), signature);
		goto done;
	}

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, reply) == TRUE) {
		connman_error("dbus error: %s", error.message);
		dbus_error_free(&error);
		goto done;
	}

	if (dbus_message_iter_init(reply, &iter) == FALSE)
		goto done;

	dbus_message_iter_get_basic(&iter, &path);

	/*
	 * Then try to connect the VPN as expected by ConnectProvider API
	 */
	// XXX:

done:
	dbus_message_unref(reply);

	dbus_pending_call_unref(call);
}

static void set_dbus_ident(char *ident)
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

static int create_configuration(DBusMessage *msg)
{
	DBusMessage *new_msg;
	DBusPendingCall *call;
	DBusMessageIter iter, array;
	const char *type = NULL, *name = NULL;
	const char *host = NULL, *domain = NULL;
	char *ident, *me;
	int err;
	dbus_bool_t result;
	struct connection_data *data;

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

	DBG("VPN type %s name %s host %s domain %s", type, name, host, domain);

	if (host == NULL || domain == NULL)
		return -EINVAL;

	if (type == NULL || name == NULL)
		return -EOPNOTSUPP;

	ident = g_strdup_printf("%s_%s", host, domain);
	set_dbus_ident(ident);

	DBG("ident %s", ident);

	data = g_hash_table_lookup(vpn_connections, ident);
	if (data != NULL) {
		if (data->call != NULL) {
			connman_error("Dbus call already pending");
			return -EINPROGRESS;
		}
	} else {
		data = create_connection_data(ident);
		if (data == NULL)
			return -ENOMEM;

		g_hash_table_insert(vpn_connections, g_strdup(ident), data);
	}

	/*
	 * User called net.connman.Manager.ConnectProvider if we are here.
	 * The config dict is already there in the original message so use it.
	 */
	me = g_strdup(dbus_message_get_destination(msg));

	new_msg = dbus_message_copy(msg);

	dbus_message_set_interface(new_msg, VPN_MANAGER_INTERFACE);
	dbus_message_set_path(new_msg, "/");
	dbus_message_set_destination(new_msg, VPN_SERVICE);
	dbus_message_set_sender(new_msg, me);
	dbus_message_set_member(new_msg, "Create");

	result = dbus_connection_send_with_reply(connection, new_msg,
						&call, DBUS_TIMEOUT);
	if (result == FALSE || call == NULL) {
		err = -EIO;
		goto done;
	}

	dbus_pending_call_set_notify(call, configuration_create_reply,
								NULL, NULL);
	data->call = call;

done:
	dbus_message_unref(new_msg);

	g_free(me);
	return err;
}

static struct connman_provider_driver provider_driver = {
	.name = "VPN",
	.type = CONNMAN_PROVIDER_TYPE_VPN,
	.probe = provider_probe,
	.remove = provider_remove,
	.connect = provider_connect,
	.disconnect = provider_disconnect,
	.set_property = set_string,
	.get_property = get_string,
	.create = create_configuration,
};

static void destroy_provider(struct connection_data *data)
{
	DBG("data %p", data);

	if (g_str_equal(data->state, "ready") == TRUE ||
			g_str_equal(data->state, "configuration") == TRUE)
		connman_provider_disconnect(data->provider);

	if (data->call != NULL)
		dbus_pending_call_cancel(data->call);

	connman_provider_put(data->provider);

	data->provider = NULL;
}

static void connection_destroy(gpointer hash_data)
{
	struct connection_data *data = hash_data;

	DBG("data %p", data);

	if (data->provider != NULL)
		destroy_provider(data);

	g_free(data->path);
	g_free(data->state);
	g_free(data->type);
	g_free(data->name);
	g_free(data->host);
	g_free(data->domain);
	g_strfreev(data->nameservers);
	g_hash_table_destroy(data->setting_strings);
	connman_ipaddress_free(data->ip);

	g_free(data);
}

static void vpnd_created(DBusConnection *conn, void *user_data)
{
	DBG("connection %p", conn);

	if (starting_vpnd == TRUE) {
		vpn_connections = g_hash_table_new_full(g_str_hash,
						g_str_equal,
						g_free, connection_destroy);
		get_connections(user_data);
		starting_vpnd = FALSE;
	}
}

static void vpnd_removed(DBusConnection *conn, void *user_data)
{
	DBG("connection %p", conn);

	g_hash_table_destroy(vpn_connections);
	vpn_connections = NULL;
	starting_vpnd = TRUE;
}

static void remove_connection(DBusConnection *conn, const char *path)
{
	DBG("path %s", path);

	g_hash_table_remove(vpn_connections, path);
}

static gboolean connection_removed(DBusConnection *conn, DBusMessage *message,
				void *user_data)
{
	const char *path;
	const char *signature = DBUS_TYPE_OBJECT_PATH_AS_STRING;

	if (dbus_message_has_signature(message, signature) == FALSE) {
		connman_error("vpn removed signature \"%s\" does not match "
							"expected \"%s\"",
			dbus_message_get_signature(message), signature);
		return TRUE;
	}

	dbus_message_get_args(message, NULL, DBUS_TYPE_OBJECT_PATH, &path,
				DBUS_TYPE_INVALID);
	remove_connection(conn, path);
	return TRUE;
}

static gboolean connection_added(DBusConnection *conn, DBusMessage *message,
				void *user_data)
{
	DBusMessageIter iter, properties;
	const char *path;
	const char *signature = DBUS_TYPE_OBJECT_PATH_AS_STRING
		DBUS_TYPE_ARRAY_AS_STRING
		DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
		DBUS_TYPE_STRING_AS_STRING
		DBUS_TYPE_VARIANT_AS_STRING
		DBUS_DICT_ENTRY_END_CHAR_AS_STRING;

	if (dbus_message_has_signature(message, signature) == FALSE) {
		connman_error("vpn ConnectionAdded signature \"%s\" does not "
						"match expected \"%s\"",
			dbus_message_get_signature(message), signature);
		return TRUE;
	}

	DBG("");

	if (dbus_message_iter_init(message, &iter) == FALSE)
		return TRUE;

	dbus_message_iter_get_basic(&iter, &path);

	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &properties);

	add_connection(path, &properties, user_data);

	return TRUE;
}

static gboolean property_changed(DBusConnection *conn,
				DBusMessage *message,
				void *user_data)
{
	const char *path = dbus_message_get_path(message);
	struct connection_data *data = NULL;
	DBusMessageIter iter, value;
	connman_bool_t ip_set = FALSE;
	int err;
	char *str;
	const char *key;
	const char *signature =	DBUS_TYPE_STRING_AS_STRING
		DBUS_TYPE_VARIANT_AS_STRING;

	if (dbus_message_has_signature(message, signature) == FALSE) {
		connman_error("vpn property signature \"%s\" does not match "
							"expected \"%s\"",
			dbus_message_get_signature(message), signature);
		return TRUE;
	}

	data = g_hash_table_lookup(vpn_connections, path);
	if (data == NULL)
		return TRUE;

	if (dbus_message_iter_init(message, &iter) == FALSE)
		return TRUE;

	dbus_message_iter_get_basic(&iter, &key);

	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &value);

	DBG("key %s", key);

	if (g_str_equal(key, "State") == TRUE) {
		dbus_message_iter_get_basic(&value, &str);

		DBG("%s %s -> %s", data->path, data->state, str);

		if (g_str_equal(data->state, str) == TRUE)
			return TRUE;

		g_free(data->state);
		data->state = g_strdup(str);

		set_provider_state(data);
	} else if (g_str_equal(key, "Index") == TRUE) {
		dbus_message_iter_get_basic(&value, &data->index);
		connman_provider_set_index(data->provider, data->index);
	} else if (g_str_equal(key, "IPv4") == TRUE) {
		err = extract_ip(&value, AF_INET, data);
		ip_set = TRUE;
	} else if (g_str_equal(key, "IPv6") == TRUE) {
		err = extract_ip(&value, AF_INET6, data);
		ip_set = TRUE;
	} else if (g_str_equal(key, "ServerRoutes") == TRUE) {
		/* XXX: TBD */
	} else if (g_str_equal(key, "UserRoutes") == TRUE) {
		/* XXX: TBD */
	} else if (g_str_equal(key, "Nameservers") == TRUE) {
		extract_nameservers(&value, data);
	}

	if (ip_set == TRUE && err == 0) {
		err = connman_provider_set_ipaddress(data->provider, data->ip);
		if (err < 0)
			DBG("setting provider IP address failed (%s/%d)",
				strerror(-err), -err);
	}

	return TRUE;
}

static int vpn_init(void)
{
	int err;

	connection = connman_dbus_get_connection();
	if (connection == NULL)
		return -EIO;

	watch = g_dbus_add_service_watch(connection, VPN_SERVICE,
			vpnd_created, vpnd_removed, &provider_driver, NULL);

	added_watch = g_dbus_add_signal_watch(connection, VPN_SERVICE, NULL,
					VPN_MANAGER_INTERFACE,
					CONNECTION_ADDED, connection_added,
					&provider_driver, NULL);

	removed_watch = g_dbus_add_signal_watch(connection, VPN_SERVICE, NULL,
					VPN_MANAGER_INTERFACE,
					CONNECTION_REMOVED, connection_removed,
					NULL, NULL);

	property_watch = g_dbus_add_signal_watch(connection, VPN_SERVICE, NULL,
					VPN_CONNECTION_INTERFACE,
					PROPERTY_CHANGED, property_changed,
					NULL, NULL);

	if (added_watch == 0 || removed_watch == 0 || property_watch == 0) {
		err = -EIO;
		goto remove;
	}

	err = connman_provider_driver_register(&provider_driver);
	if (err == 0)
		vpnd_created(connection, &provider_driver);

	return err;

remove:
	g_dbus_remove_watch(connection, watch);
	g_dbus_remove_watch(connection, added_watch);
	g_dbus_remove_watch(connection, removed_watch);
	g_dbus_remove_watch(connection, property_watch);

	dbus_connection_unref(connection);

	return err;
}

static void vpn_exit(void)
{
	g_dbus_remove_watch(connection, watch);
	g_dbus_remove_watch(connection, added_watch);
	g_dbus_remove_watch(connection, removed_watch);
	g_dbus_remove_watch(connection, property_watch);

	connman_provider_driver_unregister(&provider_driver);

	g_hash_table_destroy(vpn_connections);

	dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE(vpn, "VPN plugin", VERSION,
		CONNMAN_PLUGIN_PRIORITY_DEFAULT, vpn_init, vpn_exit)
