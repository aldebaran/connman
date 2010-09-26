/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2010  Intel Corporation. All rights reserved.
 *  Copyright (C) 2010 Nokia Corporation and/or its subsidiary(-ies).
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

#include <gdbus.h>
#include <string.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/element.h>
#include <connman/device.h>
#include <connman/network.h>
#include <connman/dbus.h>
#include <connman/inet.h>
#include <connman/log.h>

#define OFONO_SERVICE			"org.ofono"

#define OFONO_MANAGER_INTERFACE		OFONO_SERVICE ".Manager"
#define OFONO_MODEM_INTERFACE		OFONO_SERVICE ".Modem"
#define OFONO_GPRS_INTERFACE		OFONO_SERVICE ".ConnectionManager"
#define OFONO_CONTEXT_INTERFACE		OFONO_SERVICE ".ConnectionContext"
#define OFONO_SIM_INTERFACE		OFONO_SERVICE ".SimManager"
#define OFONO_REGISTRATION_INTERFACE	OFONO_SERVICE ".NetworkRegistration"

#define PROPERTY_CHANGED		"PropertyChanged"
#define GET_PROPERTIES			"GetProperties"
#define SET_PROPERTY			"SetProperty"
#define CONTEXT_ADDED			"ContextAdded"
#define CONTEXT_REMOVED			"ContextRemoved"
#define ADD_CONTEXT			"AddContext"
#define GET_MODEMS			"GetModems"
#define MODEM_ADDED			"ModemAdded"
#define MODEM_REMOVED			"ModemRemoved"


#define TIMEOUT 40000

static DBusConnection *connection;

static GHashTable *modem_hash = NULL;

static GHashTable *network_hash;

struct modem_data {
	char *path;
	struct connman_device *device;
	gboolean has_sim;
	gboolean has_reg;
	gboolean has_gprs;
	gboolean available;
	gboolean pending_online;
	gboolean requested_online;
	gboolean online;

	uint8_t strength, has_strength;
};

static int modem_probe(struct connman_device *device)
{
	DBG("device %p", device);

	return 0;
}

static void modem_remove(struct connman_device *device)
{
	DBG("device %p", device);
}

static int call_ofono(const char *path,
			const char *interface, const char *method,
			DBusPendingCallNotifyFunction notify, void *user_data,
			DBusFreeFunction free_function,
			int type, ...)
{
	DBusMessage *message;
	DBusPendingCall *call;
	dbus_bool_t ok;
	va_list va;

	DBG("path %s %s.%s", path, interface, method);

	if (path == NULL)
		return -EINVAL;

	message = dbus_message_new_method_call(OFONO_SERVICE, path,
					interface, method);
	if (message == NULL)
		return -ENOMEM;

	dbus_message_set_auto_start(message, FALSE);

	va_start(va, type);
	ok = dbus_message_append_args_valist(message, type, va);
	va_end(va);

	if (!ok)
		return -ENOMEM;

	if (dbus_connection_send_with_reply(connection, message,
						&call, TIMEOUT) == FALSE) {
		connman_error("Failed to call %s.%s", interface, method);
		dbus_message_unref(message);
		return -EINVAL;
	}

	if (call == NULL) {
		connman_error("D-Bus connection not available");
		dbus_message_unref(message);
		return -EINVAL;
	}

	dbus_pending_call_set_notify(call, notify, user_data, free_function);

	dbus_message_unref(message);

	return -EINPROGRESS;
}

static void set_property_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply;
	DBusError error;
	char const *name = user_data;

	DBG("");

	dbus_error_init(&error);

	reply = dbus_pending_call_steal_reply(call);

	if (dbus_set_error_from_message(&error, reply)) {
		connman_error("SetProperty(%s) %s %s", name,
				error.name, error.message);
		dbus_error_free(&error);
	}

	dbus_message_unref(reply);

	dbus_pending_call_unref(call);
}

static int set_property(const char *path, const char *interface,
			const char *property, int type, void *value,
			DBusPendingCallNotifyFunction notify, void *user_data,
			DBusFreeFunction free_function)
{
	DBusMessage *message;
	DBusMessageIter iter;
	DBusPendingCall *call;

	DBG("path %s %s.%s", path, interface, property);

	g_assert(notify == NULL ? free_function == NULL : 1);

	if (path == NULL)
		return -EINVAL;

	message = dbus_message_new_method_call(OFONO_SERVICE, path,
					interface, SET_PROPERTY);
	if (message == NULL)
		return -ENOMEM;

	dbus_message_set_auto_start(message, FALSE);

	dbus_message_iter_init_append(message, &iter);
	connman_dbus_property_append_basic(&iter, property, type, value);

	if (dbus_connection_send_with_reply(connection, message,
						&call, TIMEOUT) == FALSE) {
		connman_error("Failed to change \"%s\" property on %s",
				property, interface);
		dbus_message_unref(message);
		return -EINVAL;
	}

	if (call == NULL) {
		connman_error("D-Bus connection not available");
		dbus_message_unref(message);
		return -EINVAL;
	}

	if (notify == NULL) {
		notify = set_property_reply;
		user_data = (void *)property;
		free_function = NULL;
	}

	dbus_pending_call_set_notify(call, notify, user_data, free_function);

	dbus_message_unref(message);

	return -EINPROGRESS;
}

static void update_modem_online(struct modem_data *modem,
				connman_bool_t online)
{
	DBG("modem %p path %s online %d", modem, modem->path, online);

	modem->online = online;
	modem->requested_online = online;
	modem->pending_online = FALSE;

	if (modem->device)
		connman_device_set_powered(modem->device, online);
}

static void set_online_reply(DBusPendingCall *call, void *user_data)
{
	struct modem_data *modem;
	DBusMessage *reply;
	DBusError error;
	gboolean result;

	DBG("path %s", (char *)user_data);

	if (modem_hash == NULL)
		return;

	modem = g_hash_table_lookup(modem_hash, user_data);
	if (modem == NULL)
		return;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, reply)) {
		connman_error("SetProperty(Online) %s %s",
				error.name, error.message);
		dbus_error_free(&error);

		result = modem->online;
	} else
		result = modem->requested_online;

	if (modem->pending_online)
		update_modem_online(modem, result);

	dbus_message_unref(reply);

	dbus_pending_call_unref(call);
}

static int modem_change_online(char const *path, dbus_bool_t online)
{
	return set_property(path, OFONO_MODEM_INTERFACE, "Online",
				DBUS_TYPE_BOOLEAN, &online,
				set_online_reply,
				(void *)g_strdup(path), g_free);
}

static int modem_enable(struct connman_device *device)
{
	const char *path = connman_device_get_string(device, "Path");

	DBG("device %p, path, %s", device, path);

	return modem_change_online(path, TRUE);
}

static int modem_disable(struct connman_device *device)
{
	const char *path = connman_device_get_string(device, "Path");

	DBG("device %p path %s", device, path);

	return modem_change_online(path, FALSE);
}

static struct connman_device_driver modem_driver = {
	.name		= "modem",
	.type		= CONNMAN_DEVICE_TYPE_CELLULAR,
	.probe		= modem_probe,
	.remove		= modem_remove,
	.enable		= modem_enable,
	.disable	= modem_disable,
};

static void modem_remove_device(struct modem_data *modem)
{
	DBG("modem %p path %s device %p", modem, modem->path, modem->device);

	if (modem->device == NULL)
		return;

	connman_device_remove_all_networks(modem->device);
	connman_device_unregister(modem->device);
	connman_device_unref(modem->device);

	modem->device = NULL;
}

static void remove_modem(gpointer data)
{
	struct modem_data *modem = data;

	modem_remove_device(modem);

	g_free(modem->path);

	g_free(modem);
}

static void remove_network(gpointer data)
{
	connman_network_unref(data);
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

static void create_service(struct connman_network *network)
{
	const char *path;
	char *group;

	DBG("");

	path = connman_network_get_string(network, "Path");

	group = get_ident(path);

	connman_network_set_group(network, group);
}

static int network_probe(struct connman_network *network)
{
	create_service(network);
	return 0;
}

static gboolean pending_network_is_available(struct connman_network *network)
{
	/* Modem or network may be removed */
	if (network == NULL || connman_network_get_device(network) == NULL) {
		DBG("Modem or network was removed");
		return FALSE;
	}

	return TRUE;
}

static void set_active_reply(DBusPendingCall *call, void *user_data)
{
	char const *path = user_data;
	DBusMessage *reply;
	DBusError error;
	struct connman_network *network;

	network = g_hash_table_lookup(network_hash, path);

	DBG("path %s network %p", path, network);

	reply = dbus_pending_call_steal_reply(call);

	if (!pending_network_is_available(network))
		goto done;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, reply)) {
		connman_error("SetProperty(Active) %s %s",
				error.name, error.message);

		if (connman_network_get_index(network) < 0)
			connman_network_set_error(network,
				CONNMAN_NETWORK_ERROR_ASSOCIATE_FAIL);

		dbus_error_free(&error);
	}

done:
	dbus_message_unref(reply);

	dbus_pending_call_unref(call);
}

static int set_network_active(struct connman_network *network,
						dbus_bool_t active)
{
	int error;

	const char *path = connman_network_get_string(network, "Path");

	DBG("network %p, path %s, active %d", network, path, active);

	error = set_property(path, OFONO_CONTEXT_INTERFACE,
				"Active", DBUS_TYPE_BOOLEAN, &active,
				set_active_reply, g_strdup(path), NULL);

	if (active == FALSE && error == -EINPROGRESS)
		error = 0;

	return error;
}

static void set_apn(struct connman_network *network)
{
	const char *apn, *path;

	apn = connman_network_get_string(network, "Cellular.APN");
	if (apn == NULL)
		return;

	path = connman_network_get_string(network, "Path");
	if (path == NULL)
		return;

	DBG("path %s, apn %s", path, apn);

	set_property(path, OFONO_CONTEXT_INTERFACE,
			"AccessPointName", DBUS_TYPE_STRING, &apn,
			NULL, NULL, NULL);
}

static int network_connect(struct connman_network *network)
{
	DBG("network %p", network);

	if (connman_network_get_index(network) >= 0)
		return -EISCONN;

	return set_network_active(network, TRUE);
}

static int network_disconnect(struct connman_network *network)
{
	DBG("network %p", network);

	if (connman_network_get_index(network) < 0)
		return -ENOTCONN;

	return set_network_active(network, FALSE);
}

static void network_remove(struct connman_network *network)
{
	char const *path = connman_network_get_string(network, "Path");

	DBG("network %p path %s", network, path);

	g_hash_table_remove(network_hash, path);
}

static int network_setup(struct connman_network *network, const char *key)
{
	if (g_strcmp0(key, "Cellular.APN") == 0)
		set_apn(network);

	return 0;
}

static struct connman_network_driver network_driver = {
	.name		= "network",
	.type		= CONNMAN_NETWORK_TYPE_CELLULAR,
	.probe		= network_probe,
	.remove		= network_remove,
	.connect	= network_connect,
	.disconnect	= network_disconnect,
	.setup		= network_setup,
};

static void update_settings(DBusMessageIter *array,
				struct connman_network *network);

static void set_connected(struct connman_network *network,
				connman_bool_t connected);

static int add_network(struct connman_device *device,
			const char *path, DBusMessageIter *dict)
{
	struct modem_data *modem = connman_device_get_data(device);
	struct connman_network *network;
	char *ident;
	const char *hash_path;
	char const *operator;
	char const *reg_status;
	dbus_bool_t active = FALSE;

	DBG("modem %p device %p path %s", modem, device, path);

	ident = get_ident(path);

	network = connman_device_get_network(device, ident);
	if (network != NULL)
		return -EALREADY;

	network = g_hash_table_lookup(network_hash, path);
	if (network != NULL) {
		DBG("path %p already exists with device %p", path,
			connman_network_get_device(network));
		if (connman_network_get_device(network))
			return -EALREADY;
		g_hash_table_remove(network_hash, path);
	}

	network = connman_network_create(ident, CONNMAN_NETWORK_TYPE_CELLULAR);
	if (network == NULL)
		return -ENOMEM;

	connman_network_set_string(network, "Path", path);
	hash_path = connman_network_get_string(network, "Path");
	if (hash_path == NULL)
		goto error;
	connman_network_ref(network);
	g_hash_table_insert(network_hash, (char *)hash_path, network);

	connman_network_set_available(network, TRUE);
	connman_network_set_index(network, -1);

	operator = connman_device_get_string(device, "Operator");
	if (operator)
		connman_network_set_name(network, operator);

	if (modem->has_strength)
		connman_network_set_strength(network, modem->strength);

	reg_status = connman_device_get_string(device, "RegistrationStatus");

	if (!g_strcmp0(reg_status, "roaming"))
		connman_network_set_roaming(network, TRUE);
	else if (!g_strcmp0(reg_status, "registered"))
		connman_network_set_roaming(network, FALSE);

	while (dbus_message_iter_get_arg_type(dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;

		dbus_message_iter_recurse(dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		if (g_str_equal(key, "Type")) {
			const char *type;

			dbus_message_iter_get_basic(&value, &type);
			if (g_strcmp0(type, "internet") == 0) {
				connman_network_set_protocol(network,
						CONNMAN_NETWORK_PROTOCOL_IP);
			} else {
				DBG("path %p type %s", path, type);
				goto error;
			}
		} else if (g_str_equal(key, "AccessPointName")) {
			const char *ap;

			dbus_message_iter_get_basic(&value, &ap);

			connman_network_set_string(network, "Cellular.APN", ap);
		} else if (g_str_equal(key, "Settings"))
			update_settings(&value, network);
		else if (g_str_equal(key, "Active") == TRUE)
			dbus_message_iter_get_basic(&value, &active);

		dbus_message_iter_next(dict);
	}

	if (connman_device_add_network(device, network) != 0)
		goto error;

	if (active)
		set_connected(network, active);

	return 0;

error:
	connman_network_unref(network);
	g_hash_table_remove(network_hash, hash_path);
	return -EIO;
}

static void check_networks_reply(DBusPendingCall *call, void *user_data)
{
	char *path = user_data;
	struct modem_data *modem;
	DBusMessage *reply;
	DBusMessageIter array, entry, value, properties;

	DBG("path %s", path);

	modem = g_hash_table_lookup(modem_hash, path);
	if (modem == NULL)
		return;
	if (modem->device == NULL)
		return;

	reply = dbus_pending_call_steal_reply(call);

	if (dbus_message_has_signature(reply, "a(oa{sv})") == FALSE)
		goto done;

	dbus_message_iter_init(reply, &array);

	dbus_message_iter_recurse(&array, &entry);

	while (dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_STRUCT) {
		char const *network_path;

		dbus_message_iter_recurse(&entry, &value);
		dbus_message_iter_get_basic(&value, &network_path);

		dbus_message_iter_next(&value);
		dbus_message_iter_recurse(&value, &properties);

		add_network(modem->device, network_path, &properties);

		dbus_message_iter_next(&entry);
	}

done:
	dbus_message_unref(reply);

	dbus_pending_call_unref(call);
}

static void check_networks(struct modem_data *modem)
{
	char const *path = modem->path;

	DBG("modem %p path %s", modem, path);

	call_ofono(path, OFONO_GPRS_INTERFACE, "GetContexts",
			check_networks_reply, g_strdup(path), g_free,
			DBUS_TYPE_INVALID);
}

static void modem_operator_name_changed(struct modem_data *modem,
					char const *name)
{
	struct connman_device *device = modem->device;
	GHashTableIter i;
	gpointer value;

	if (device == NULL)
		return;

	connman_device_set_string(device, "Operator", name);

	for (g_hash_table_iter_init(&i, network_hash);
	     g_hash_table_iter_next(&i, NULL, &value);) {
		struct connman_network *network = value;

		if (connman_network_get_device(network) == device) {
			connman_network_set_name(network, name);
			connman_network_update(network);
		}
	}
}

static void modem_strength_changed(struct modem_data *modem, uint8_t strength)
{
	struct connman_device *device = modem->device;
	GHashTableIter i;
	gpointer value;

	modem->strength = strength;
	modem->has_strength = TRUE;

	if (device == NULL)
		return;

	for (g_hash_table_iter_init(&i, network_hash);
	     g_hash_table_iter_next(&i, NULL, &value);) {
		struct connman_network *network = value;

		if (connman_network_get_device(network) == device) {
			connman_network_set_strength(network, strength);
			connman_network_update(network);
		}
	}
}

static void modem_roaming_changed(struct modem_data *modem,
					char const *status)
{
	struct connman_device *device = modem->device;
	connman_bool_t roaming;
	GHashTableIter i;
	gpointer value;

	if (device == NULL)
		return;

	connman_device_set_string(device, "RegistrationStatus", status);

	if (g_str_equal(status, "roaming"))
		roaming = TRUE;
	else if (g_str_equal(status, "registered"))
		roaming = FALSE;
	else
		return;

	for (g_hash_table_iter_init(&i, network_hash);
	     g_hash_table_iter_next(&i, NULL, &value);) {
		struct connman_network *network = value;

		if (connman_network_get_device(network) == device) {
			connman_network_set_roaming(network, roaming);
			connman_network_update(network);
		}
	}
}

static void modem_registration_changed(struct modem_data *modem,
					DBusMessageIter *entry)
{
	DBusMessageIter iter;
	const char *key;
	int type;
	struct {
		char const *str;
		connman_uint8_t byte;
	} value;

	dbus_message_iter_get_basic(entry, &key);

	DBG("key %s", key);

	dbus_message_iter_next(entry);

	dbus_message_iter_recurse(entry, &iter);

	type = dbus_message_iter_get_arg_type(&iter);
	if (type != DBUS_TYPE_BYTE && type != DBUS_TYPE_STRING)
		return;

	dbus_message_iter_get_basic(&iter, &value);

	if (g_str_equal(key, "Name") && type == DBUS_TYPE_STRING)
		modem_operator_name_changed(modem, value.str);
	else if (g_str_equal(key, "Strength") && type == DBUS_TYPE_BYTE)
		modem_strength_changed(modem, value.byte);
	else if (g_str_equal(key, "Status") && type == DBUS_TYPE_STRING)
		modem_roaming_changed(modem, value.str);

}

static gboolean reg_changed(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	const char *path = dbus_message_get_path(message);
	struct modem_data *modem;
	DBusMessageIter iter;

	DBG("path %s", path);

	modem = g_hash_table_lookup(modem_hash, path);
	if (modem == NULL)
		return TRUE;

	if (dbus_message_iter_init(message, &iter))
		modem_registration_changed(modem, &iter);

	return TRUE;
}

static void check_registration_reply(DBusPendingCall *call, void *user_data)
{
	char const *path = user_data;
	struct modem_data *modem;
	DBusMessage *reply;
	DBusMessageIter array, dict, entry;

	DBG("path %s", path);

	modem = g_hash_table_lookup(modem_hash, path);
	if (modem == NULL)
		return;

	reply = dbus_pending_call_steal_reply(call);

	if (dbus_message_iter_init(reply, &array) == FALSE)
		goto done;

	if (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_ARRAY)
		goto done;

	dbus_message_iter_recurse(&array, &dict);
	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		dbus_message_iter_recurse(&dict, &entry);
		modem_registration_changed(modem, &entry);
		dbus_message_iter_next(&dict);
	}

done:
	dbus_message_unref(reply);

	dbus_pending_call_unref(call);
}

static void check_registration(struct modem_data *modem)
{
	char const *path = modem->path;

	DBG("modem %p path %s", modem, path);

	call_ofono(path, OFONO_REGISTRATION_INTERFACE, GET_PROPERTIES,
			check_registration_reply, g_strdup(path), g_free,
			DBUS_TYPE_INVALID);
}

static void add_device(const char *path, const char *imsi)
{
	struct modem_data *modem;
	struct connman_device *device;

	DBG("path %s imsi %s", path, imsi);

	if (path == NULL)
		return;

	if (imsi == NULL)
		return;

	modem = g_hash_table_lookup(modem_hash, path);
	if (modem == NULL)
		return;

	if (modem->device) {
		if (!g_strcmp0(imsi, connman_device_get_ident(modem->device)))
			return;

		modem_remove_device(modem);
	}

	if (strlen(imsi) == 0)
		return;

	device = connman_device_create(imsi, CONNMAN_DEVICE_TYPE_CELLULAR);
	if (device == NULL)
		return;

	connman_device_set_ident(device, imsi);

	connman_device_set_mode(device, CONNMAN_DEVICE_MODE_NETWORK_MULTIPLE);

	connman_device_set_string(device, "Path", path);

	connman_device_set_data(device, modem);

	if (connman_device_register(device) < 0) {
		connman_device_unref(device);
		return;
	}

	modem->device = device;

	if (modem->has_reg)
		check_registration(modem);
	if (modem->has_gprs)
		check_networks(modem);
}

static void sim_properties_reply(DBusPendingCall *call, void *user_data)
{
	const char *path = user_data;
	const char *imsi = NULL;
	DBusMessage *reply;
	DBusMessageIter array, dict;

	DBG("path %s", path);

	reply = dbus_pending_call_steal_reply(call);

	if (dbus_message_iter_init(reply, &array) == FALSE)
		goto done;

	if (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_ARRAY)
		goto done;

	dbus_message_iter_recurse(&array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		if (g_str_equal(key, "SubscriberIdentity")) {
			dbus_message_iter_get_basic(&value, &imsi);
			add_device(path, imsi);
		}

		dbus_message_iter_next(&dict);
	}

done:
	dbus_message_unref(reply);

	dbus_pending_call_unref(call);
}

static void get_imsi(const char *path)
{
	DBG("path %s", path);

	call_ofono(path, OFONO_SIM_INTERFACE, GET_PROPERTIES,
			sim_properties_reply, g_strdup(path), g_free,
			DBUS_TYPE_INVALID);
}

static int gprs_change_powered(const char *path, dbus_bool_t powered)
{
	DBG("path %s powered %d", path, powered);

	return set_property(path, OFONO_GPRS_INTERFACE, "Powered",
				DBUS_TYPE_BOOLEAN, &powered,
				NULL, NULL, NULL);
}

static int modem_change_powered(const char *path, dbus_bool_t powered)
{
	DBG("path %s powered %d", path, powered);

	return set_property(path, OFONO_MODEM_INTERFACE, "Powered",
				DBUS_TYPE_BOOLEAN, &powered,
				NULL, NULL, NULL);
}


static gboolean modem_has_interface(DBusMessageIter *array,
					char const *interface)
{
	DBusMessageIter entry;

	dbus_message_iter_recurse(array, &entry);

	while (dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_STRING) {
		const char *element;

		dbus_message_iter_get_basic(&entry, &element);

		if (g_strcmp0(interface, element) == 0)
			return TRUE;

		dbus_message_iter_next(&entry);
	}

	return FALSE;
}

static gboolean modem_has_sim(DBusMessageIter *array)
{
	return modem_has_interface(array, OFONO_SIM_INTERFACE);
}

static gboolean modem_has_reg(DBusMessageIter *array)
{
	return modem_has_interface(array, OFONO_REGISTRATION_INTERFACE);
}

static gboolean modem_has_gprs(DBusMessageIter *array)
{
	return modem_has_interface(array, OFONO_GPRS_INTERFACE);
}

static void add_modem(const char *path, DBusMessageIter *properties)
{
	struct modem_data *modem;
	DBusMessageIter dict;
	dbus_bool_t powered = FALSE;
	dbus_bool_t online = FALSE;
	dbus_bool_t has_online = FALSE;
	gboolean has_sim = FALSE;
	gboolean has_reg = FALSE;
	gboolean has_gprs = FALSE;

	modem = g_hash_table_lookup(modem_hash, path);

	if (modem != NULL)
		return;

	modem = g_try_new0(struct modem_data, 1);
	if (modem == NULL)
		return;

	modem->path = g_strdup(path);
	modem->device = NULL;
	modem->available = TRUE;

	g_hash_table_insert(modem_hash, g_strdup(path), modem);

	dbus_message_iter_recurse(properties, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		if (g_str_equal(key, "Powered") == TRUE)
			dbus_message_iter_get_basic(&value, &powered);
		else if (g_str_equal(key, "Online") == TRUE) {
			has_online = TRUE;
			dbus_message_iter_get_basic(&value, &online);
		} else if (g_str_equal(key, "Interfaces") == TRUE) {
			has_sim = modem_has_sim(&value);
			has_reg = modem_has_reg(&value);
			has_gprs = modem_has_gprs(&value);
		}

		dbus_message_iter_next(&dict);
	}

	if (!powered)
		modem_change_powered(path, TRUE);

	modem->has_sim = has_sim;
	modem->has_reg = has_reg;
	modem->has_gprs = has_gprs;

	update_modem_online(modem, online);

	if (has_sim)
		get_imsi(path);
}

static void manager_modems_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply;
	DBusError error;
	DBusMessageIter array, dict;

	DBG("");

	reply = dbus_pending_call_steal_reply(call);

	if (dbus_message_has_signature(reply, "a(oa{sv})") == FALSE)
		goto done;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, reply)) {
		connman_error("ModemManager.GetModems() %s %s",
				error.name, error.message);
		dbus_error_free(&error);
		goto done;
	}

	if (dbus_message_iter_init(reply, &array) == FALSE)
		goto done;

	dbus_message_iter_recurse(&array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_STRUCT) {
		DBusMessageIter value, properties;
		const char *modem_path;

		dbus_message_iter_recurse(&dict, &value);
		dbus_message_iter_get_basic(&value, &modem_path);

		dbus_message_iter_next(&value);
		dbus_message_iter_recurse(&value, &properties);

		/* Add modem */
		add_modem(modem_path, &properties);

		dbus_message_iter_next(&dict);
	}

done:
	dbus_message_unref(reply);

	dbus_pending_call_unref(call);
}

static void ofono_connect(DBusConnection *connection, void *user_data)
{
	DBG("connection %p", connection);

	modem_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						g_free, remove_modem);

	network_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						NULL, remove_network);

	call_ofono("/", OFONO_MANAGER_INTERFACE, GET_MODEMS,
			manager_modems_reply, NULL, NULL,
			DBUS_TYPE_INVALID);
}

static void ofono_disconnect(DBusConnection *connection, void *user_data)
{
	DBG("connection %p", connection);

	if (modem_hash == NULL)
		return;

	g_hash_table_destroy(modem_hash);

	modem_hash = NULL;
}

static gboolean modem_changed(DBusConnection *connection, DBusMessage *message,
				void *user_data)
{
	const char *path = dbus_message_get_path(message);
	struct modem_data *modem;
	DBusMessageIter iter, value;
	const char *key;

	DBG("path %s", path);

	modem = g_hash_table_lookup(modem_hash, path);
	if (modem == NULL)
		return TRUE;

	if (dbus_message_iter_init(message, &iter) == FALSE)
		return TRUE;

	dbus_message_iter_get_basic(&iter, &key);

	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &value);

	if (g_str_equal(key, "Powered") == TRUE) {
		dbus_bool_t powered;

		dbus_message_iter_get_basic(&value, &powered);
		if (powered == TRUE)
			return TRUE;

		modem->has_sim = FALSE;
		modem->has_reg = FALSE;
		modem->has_gprs = FALSE;

		modem_remove_device(modem);
	} else if (g_str_equal(key, "Online") == TRUE) {
		dbus_bool_t online;

		dbus_message_iter_get_basic(&value, &online);

		update_modem_online(modem, online);
	} else if (g_str_equal(key, "Interfaces") == TRUE) {
		gboolean has_sim = modem_has_sim(&value);
		gboolean has_reg = modem_has_reg(&value);
		gboolean added_reg = has_reg && !modem->has_reg;
		gboolean has_gprs = modem_has_gprs(&value);
		gboolean added_gprs = has_gprs && !modem->has_gprs;

		modem->has_sim = has_sim;
		modem->has_reg = has_reg;
		modem->has_gprs = has_gprs;

		if (modem->device == NULL) {
			if (has_sim)
				get_imsi(modem->path);
		} else if (!has_sim) {
			modem_remove_device(modem);
		} else {
			if (added_reg)
				check_registration(modem);
			if (added_gprs)
				gprs_change_powered(modem->path, TRUE);
		}
	}

	return TRUE;
}

static gboolean sim_changed(DBusConnection *connection, DBusMessage *message,
				void *user_data)
{
	const char *path = dbus_message_get_path(message);
	struct modem_data *modem;
	DBusMessageIter iter, value;
	const char *key;

	DBG("path %s", path);

	modem = g_hash_table_lookup(modem_hash, path);
	if (modem == NULL)
		return TRUE;

	if (dbus_message_iter_init(message, &iter) == FALSE)
		return TRUE;

	dbus_message_iter_get_basic(&iter, &key);

	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &value);

	if (g_str_equal(key, "SubscriberIdentity") == TRUE) {
		char *imsi;

		dbus_message_iter_get_basic(&value, &imsi);

		add_device(path, imsi);
	} else if (g_str_equal(key, "Present") == TRUE) {
		dbus_bool_t present;

		dbus_message_iter_get_basic(&value, &present);

		if (present)
			return TRUE;

		if (modem->device != NULL)
			modem_remove_device(modem);

		modem->has_gprs = FALSE;
		modem->has_reg = FALSE;
	}

	return TRUE;
}

static gboolean gprs_changed(DBusConnection *connection, DBusMessage *message,
				void *user_data)
{
	const char *path = dbus_message_get_path(message);
	struct modem_data *modem;
	DBusMessageIter iter, value;
	const char *key;

	DBG("path %s", path);

	modem = g_hash_table_lookup(modem_hash, path);
	if (modem == NULL)
		return TRUE;

	if (dbus_message_iter_init(message, &iter) == FALSE)
		return TRUE;

	dbus_message_iter_get_basic(&iter, &key);

	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &value);

	if (g_str_equal(key, "Attached") == TRUE) {
		dbus_bool_t attached;

		dbus_message_iter_get_basic(&value, &attached);

		DBG("Attached %d", attached);

		if (attached == TRUE)
			check_networks(modem);
		else if (modem->device != NULL)
			connman_device_remove_all_networks(modem->device);

	}

	return TRUE;
}

static gboolean modem_added(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	DBusMessageIter iter, properties;
	const char *modem_path;

	DBG("");

	if (dbus_message_iter_init(message, &iter) == FALSE)
		return TRUE;

	dbus_message_iter_get_basic(&iter, &modem_path);

	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &properties);

	add_modem(modem_path, &properties);

	return TRUE;
}

static gboolean modem_removed(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	DBusMessageIter iter;
	const char *modem_path;

	DBG("");

	if (dbus_message_iter_init(message, &iter) == FALSE)
		return TRUE;

	dbus_message_iter_get_basic(&iter, &modem_path);

	g_hash_table_remove(modem_hash, modem_path);

	return TRUE;
}


static void get_dns(DBusMessageIter *array, struct connman_element *parent)
{
	DBusMessageIter entry;
	gchar *nameserver = NULL, *nameserver_old = NULL;

	DBG("");

	dbus_message_iter_recurse(array, &entry);

	while (dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_STRING) {
		const char *dns;

		dbus_message_iter_get_basic(&entry, &dns);

		DBG("dns %s", dns);

		if (nameserver == NULL) {

			nameserver = g_strdup(dns);
		} else {

			nameserver_old = nameserver;
			nameserver = g_strdup_printf("%s %s",
						nameserver_old, dns);
			g_free(nameserver_old);
		}

		dbus_message_iter_next(&entry);
	}

	parent->ipv4.nameserver = nameserver;
}

static void update_settings(DBusMessageIter *array,
				struct connman_network *network)
{
	struct connman_element *parent = connman_network_get_element(network);
	DBusMessageIter dict;
	const char *interface = NULL;

	DBG("network %p", network);

	if (dbus_message_iter_get_arg_type(array) != DBUS_TYPE_ARRAY)
		return;

	dbus_message_iter_recurse(array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		DBG("key %s", key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		if (g_str_equal(key, "Interface") == TRUE) {
			int index;

			dbus_message_iter_get_basic(&value, &interface);

			DBG("interface %s", interface);

			index = connman_inet_ifindex(interface);
			if (index >= 0) {
				connman_network_set_index(network, index);
			} else {
				connman_error("Can not find interface %s",
								interface);
				break;
			}
		} else if (g_str_equal(key, "Method") == TRUE) {
			const char *method;

			dbus_message_iter_get_basic(&value, &method);
			if (g_strcmp0(method, "static") == 0) {

				parent->ipv4.method =
					CONNMAN_IPCONFIG_METHOD_FIXED;
			} else if (g_strcmp0(method, "dhcp") == 0) {

				parent->ipv4.method =
					CONNMAN_IPCONFIG_METHOD_DHCP;
				break;
			}
		} else if (g_str_equal(key, "Address") == TRUE) {
			const char *address;

			dbus_message_iter_get_basic(&value, &address);

			DBG("address %s", address);

			parent->ipv4.address = g_strdup(address);
		} else if (g_str_equal(key, "Netmask") == TRUE) {
			const char *netmask;

			dbus_message_iter_get_basic(&value, &netmask);

			DBG("netmask %s", netmask);

			parent->ipv4.netmask = g_strdup(netmask);
		} else if (g_str_equal(key, "DomainNameServers") == TRUE) {

			get_dns(&value, parent);
		} else if (g_str_equal(key, "Gateway") == TRUE) {
			const char *gateway;

			dbus_message_iter_get_basic(&value, &gateway);

			DBG("gateway %s", gateway);

			parent->ipv4.gateway = g_strdup(gateway);
		}

		dbus_message_iter_next(&dict);
	}

	/* deactive, oFono send NULL inteface before deactive signal */
	if (interface == NULL)
		connman_network_set_index(network, -1);
}

static void cleanup_ipconfig(struct connman_network *network)
{
	struct connman_element *parent = connman_network_get_element(network);

	g_free(parent->ipv4.address);
	parent->ipv4.address = NULL;

	g_free(parent->ipv4.netmask);
	parent->ipv4.netmask = NULL;

	g_free(parent->ipv4.nameserver);
	parent->ipv4.nameserver = NULL;

	g_free(parent->ipv4.gateway);
	parent->ipv4.gateway = NULL;

	parent->ipv4.method = CONNMAN_IPCONFIG_METHOD_UNKNOWN;
}


static void set_connected(struct connman_network *network,
				connman_bool_t connected)
{
	struct connman_element *parent = connman_network_get_element(network);
	enum connman_ipconfig_method method = parent->ipv4.method;

	switch (method) {
	case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
	case CONNMAN_IPCONFIG_METHOD_OFF:
	case CONNMAN_IPCONFIG_METHOD_MANUAL:
		return;

	case CONNMAN_IPCONFIG_METHOD_FIXED:
		connman_network_set_method(network, method);

		if (connected == FALSE)
			cleanup_ipconfig(network);

		connman_network_set_connected(network, connected);
		break;

	case CONNMAN_IPCONFIG_METHOD_DHCP:
		connman_network_set_method(network, method);

		connman_network_set_connected(network, connected);
		break;
	}
}

static gboolean context_changed(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	const char *path = dbus_message_get_path(message);
	struct connman_network *network;
	DBusMessageIter iter, value;
	const char *key;

	DBG("path %s", path);

	network = g_hash_table_lookup(network_hash, path);
	if (network == NULL)
		return TRUE;

	if (!pending_network_is_available(network)) {
		remove_network(network);
		return TRUE;
	}

	if (dbus_message_iter_init(message, &iter) == FALSE)
		return TRUE;

	dbus_message_iter_get_basic(&iter, &key);

	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &value);

	if (g_str_equal(key, "Settings") == TRUE)
		update_settings(&value, network);
	else if (g_str_equal(key, "Active") == TRUE) {
		dbus_bool_t active;

		dbus_message_iter_get_basic(&value, &active);

		set_connected(network, active);
	}

	return TRUE;
}

static guint watch;
static guint reg_watch;
static guint sim_watch;
static guint gprs_watch;
static guint modem_watch;
static guint modem_added_watch;
static guint modem_removed_watch;
static guint context_watch;

static int ofono_init(void)
{
	int err;

	connection = connman_dbus_get_connection();
	if (connection == NULL)
		return -EIO;

	watch = g_dbus_add_service_watch(connection, OFONO_SERVICE,
			ofono_connect, ofono_disconnect, NULL, NULL);

	reg_watch = g_dbus_add_signal_watch(connection, NULL, NULL,
						OFONO_REGISTRATION_INTERFACE,
						PROPERTY_CHANGED,
						reg_changed,
						NULL, NULL);

	gprs_watch = g_dbus_add_signal_watch(connection, NULL, NULL,
						OFONO_GPRS_INTERFACE,
						PROPERTY_CHANGED,
						gprs_changed,
						NULL, NULL);

	modem_watch = g_dbus_add_signal_watch(connection, NULL, NULL,
						OFONO_MODEM_INTERFACE,
						PROPERTY_CHANGED,
						modem_changed,
						NULL, NULL);

	sim_watch = g_dbus_add_signal_watch(connection, NULL, NULL,
						OFONO_SIM_INTERFACE,
						PROPERTY_CHANGED,
						sim_changed,
						NULL, NULL);

	modem_added_watch = g_dbus_add_signal_watch(connection, NULL, NULL,
						OFONO_MANAGER_INTERFACE,
						MODEM_ADDED,
						modem_added,
						NULL, NULL);

	modem_removed_watch = g_dbus_add_signal_watch(connection, NULL, NULL,
						OFONO_MANAGER_INTERFACE,
						MODEM_REMOVED,
						modem_removed,
						NULL, NULL);

	context_watch = g_dbus_add_signal_watch(connection, NULL, NULL,
						OFONO_CONTEXT_INTERFACE,
						PROPERTY_CHANGED,
						context_changed,
						NULL, NULL);

	if (watch == 0 || gprs_watch == 0 || modem_watch == 0 ||
			reg_watch == 0 || sim_watch == 0 ||
			modem_added_watch == 0 || modem_removed_watch == 0 ||
				context_watch == 0) {
		err = -EIO;
		goto remove;
	}

	err = connman_network_driver_register(&network_driver);
	if (err < 0)
		goto remove;

	err = connman_device_driver_register(&modem_driver);
	if (err < 0) {
		connman_network_driver_unregister(&network_driver);
		goto remove;
	}

	return 0;

remove:
	g_dbus_remove_watch(connection, watch);
	g_dbus_remove_watch(connection, sim_watch);
	g_dbus_remove_watch(connection, reg_watch);
	g_dbus_remove_watch(connection, gprs_watch);
	g_dbus_remove_watch(connection, modem_watch);
	g_dbus_remove_watch(connection, modem_added_watch);
	g_dbus_remove_watch(connection, modem_removed_watch);
	g_dbus_remove_watch(connection, context_watch);

	dbus_connection_unref(connection);

	return err;
}

static void ofono_exit(void)
{
	g_dbus_remove_watch(connection, watch);
	g_dbus_remove_watch(connection, sim_watch);
	g_dbus_remove_watch(connection, reg_watch);
	g_dbus_remove_watch(connection, gprs_watch);
	g_dbus_remove_watch(connection, modem_watch);
	g_dbus_remove_watch(connection, modem_added_watch);
	g_dbus_remove_watch(connection, modem_removed_watch);
	g_dbus_remove_watch(connection, context_watch);

	ofono_disconnect(connection, NULL);

	connman_device_driver_unregister(&modem_driver);
	connman_network_driver_unregister(&network_driver);

	dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE(ofono, "oFono telephony plugin", VERSION,
		CONNMAN_PLUGIN_PRIORITY_DEFAULT, ofono_init, ofono_exit)
