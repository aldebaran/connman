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

#include <errno.h>
#include <stdlib.h>

#include <gdbus.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/device.h>
#include <connman/dbus.h>
#include <connman/log.h>

#include "inet.h"

#define BLUEZ_SERVICE			"org.bluez"
#define BLUEZ_MANAGER_INTERFACE		BLUEZ_SERVICE ".Manager"
#define BLUEZ_ADAPTER_INTERFACE		BLUEZ_SERVICE ".Adapter"
#define BLUEZ_DEVICE_INTERFACE		BLUEZ_SERVICE ".Device"
#define BLUEZ_NETWORK_INTERFACE		BLUEZ_SERVICE ".Network"

#define LIST_ADAPTERS			"ListAdapters"
#define ADAPTER_ADDED			"AdapterAdded"
#define ADAPTER_REMOVED			"AdapterRemoved"

#define PROPERTY_CHANGED		"PropertyChanged"
#define GET_PROPERTIES			"GetProperties"
#define SET_PROPERTY			"SetProperty"

#define CONNECT				"Connect"
#define DISCONNECT			"Disconnect"

#define TIMEOUT 5000

typedef void (* properties_callback_t) (DBusConnection *connection,
							const char *path,
							DBusMessage *message,
							void *user_data);

struct properties_data {
	DBusConnection *connection;
	DBusMessage *message;
	properties_callback_t callback;
	void *user_data;
};

static void get_properties_reply(DBusPendingCall *call, void *user_data)
{
	struct properties_data *data = user_data;
	DBusMessage *reply;
	const char *path;

	reply = dbus_pending_call_steal_reply(call);
	if (reply == NULL)
		goto done;

	path = dbus_message_get_path(data->message);

	data->callback(data->connection, path, reply, data->user_data);

	dbus_message_unref(reply);

done:
	dbus_message_unref(data->message);
	g_free(data);
}

static void get_properties(DBusConnection *connection,
				const char *path, const char *interface,
				properties_callback_t callback, void *user_data)
{
	struct properties_data *data;
	DBusMessage *message;
	DBusPendingCall *call;

	DBG("path %s interface %s", path, interface);

	data = g_try_new0(struct properties_data, 1);
	if (data == NULL)
		return;

	message = dbus_message_new_method_call(BLUEZ_SERVICE, path,
						interface, GET_PROPERTIES);
	if (message == NULL) {
		g_free(data);
		return;
	}

	if (dbus_connection_send_with_reply(connection, message,
						&call, TIMEOUT) == FALSE) {
		connman_error("Failed to get properties for %s", interface);
		dbus_message_unref(message);
		g_free(data);
		return;
	}

	if (call == NULL) {
		connman_error("D-Bus connection not available");
		dbus_message_unref(message);
		g_free(data);
		return;
	}

	data->connection = connection;
	data->message    = message;
	data->callback   = callback;
	data->user_data  = user_data;

	dbus_pending_call_set_notify(call, get_properties_reply, data, NULL);
}

struct adapter_data {
	DBusConnection *connection;
};

struct network_data {
	DBusConnection *connection;
	char *interface;
};

static int pan_probe(struct connman_network *network)
{
	struct connman_device *device = connman_network_get_device(network);
	struct adapter_data *adapter;
	struct network_data *data;

	DBG("network %p", network);

	if (device == NULL)
		return -EINVAL;

	adapter = connman_device_get_data(device);
	if (adapter == NULL)
		return -EINVAL;

	data = g_try_new0(struct network_data, 1);
	if (data == NULL)
		return -ENOMEM;

	data->connection = adapter->connection;

	connman_network_set_data(network, data);

	return 0;
}

static void pan_remove(struct connman_network *network)
{
	struct network_data *data = connman_network_get_data(network);

	DBG("network %p", network);

	connman_network_set_data(network, NULL);

	g_free(data);
}

static void connect_reply(DBusPendingCall *call, void *user_data)
{
	struct connman_network *network = user_data;
	struct network_data *data = connman_network_get_data(network);
	DBusMessage *reply;
	DBusError error;
	const char *interface = NULL;
	int index;

	DBG("network %p", network);

	reply = dbus_pending_call_steal_reply(call);
	if (reply == NULL)
		return;

	dbus_error_init(&error);

	if (dbus_message_get_args(reply, &error,
					DBUS_TYPE_STRING, &interface,
						DBUS_TYPE_INVALID) == FALSE) {
		if (dbus_error_is_set(&error) == TRUE) {
			connman_error("%s", error.message);
			dbus_error_free(&error);
		} else
			connman_error("Wrong arguments for connect");
		goto done;
	}

	if (interface == NULL)
		goto done;

	DBG("interface %s", interface);

	data->interface = g_strdup(interface);

	index = inet_name2index(interface);

	connman_network_set_index(network, index);
	connman_network_set_connected(network, TRUE);

done:
	dbus_message_unref(reply);
}

static int pan_connect(struct connman_network *network)
{
	struct network_data *data = connman_network_get_data(network);
	const char *path = connman_network_get_string(network, "Node");
	const char *uuid = "nap";
	DBusMessage *message;
	DBusPendingCall *call;

	DBG("network %p", network);

	message = dbus_message_new_method_call(BLUEZ_SERVICE, path,
					BLUEZ_NETWORK_INTERFACE, CONNECT);
	if (message == NULL)
		return -ENOMEM;

	dbus_message_append_args(message, DBUS_TYPE_STRING, &uuid,
							DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(data->connection, message,
					&call, TIMEOUT * 10) == FALSE) {
		connman_error("Failed to connect service");
		dbus_message_unref(message);
		return -EINVAL;
	}

	if (call == NULL) {
		connman_error("D-Bus connection not available");
		dbus_message_unref(message);
		return -EINVAL;
	}

	dbus_pending_call_set_notify(call, connect_reply, network, NULL);

	dbus_message_unref(message);

	return -EINPROGRESS;
}

static void disconnect_reply(DBusPendingCall *call, void *user_data)
{
	struct connman_network *network = user_data;
	struct network_data *data = connman_network_get_data(network);
	DBusMessage *reply;
	DBusError error;

	DBG("network %p", network);

	reply = dbus_pending_call_steal_reply(call);
	if (reply == NULL)
		return;

	dbus_error_init(&error);

	if (dbus_message_get_args(reply, &error, DBUS_TYPE_INVALID) == FALSE) {
		if (dbus_error_is_set(&error) == TRUE) {
			connman_error("%s", error.message);
			dbus_error_free(&error);
		} else
			connman_error("Wrong arguments for disconnect");
		goto done;
	}

	g_free(data->interface);
	data->interface = NULL;

	connman_network_set_connected(network, FALSE);
	connman_network_set_index(network, -1);

done:
	dbus_message_unref(reply);
}

static int pan_disconnect(struct connman_network *network)
{
	struct network_data *data = connman_network_get_data(network);
	const char *path = connman_network_get_string(network, "Node");
	DBusMessage *message;
	DBusPendingCall *call;

	DBG("network %p", network);

	if (data->interface == NULL)
		return -EINVAL;

	message = dbus_message_new_method_call(BLUEZ_SERVICE, path,
					BLUEZ_NETWORK_INTERFACE, DISCONNECT);
	if (message == NULL)
		return -ENOMEM;

	dbus_message_append_args(message, DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(data->connection, message,
						&call, TIMEOUT) == FALSE) {
		connman_error("Failed to disconnect service");
		dbus_message_unref(message);
		return -EINVAL;
	}

	if (call == NULL) {
		connman_error("D-Bus connection not available");
		dbus_message_unref(message);
		return -EINVAL;
	}

	dbus_pending_call_set_notify(call, disconnect_reply, network, NULL);

	dbus_message_unref(message);

	return -EINPROGRESS;
}

static struct connman_network_driver pan_driver = {
	.name		= "bluetooth-pan",
	.type		= CONNMAN_NETWORK_TYPE_BLUETOOTH_PAN,
	.probe		= pan_probe,
	.remove		= pan_remove,
	.connect	= pan_connect,
	.disconnect	= pan_disconnect,
};

static int bluetooth_probe(struct connman_device *adapter)
{
	struct adapter_data *data;

	DBG("adapter %p", adapter);

	data = g_try_new0(struct adapter_data, 1);
	if (data == NULL)
		return -ENOMEM;

	data->connection = connman_dbus_get_connection();
	if (data->connection == NULL) {
		g_free(data);
		return -EIO;
	}

	connman_device_set_data(adapter, data);

	return 0;
}

static void bluetooth_remove(struct connman_device *adapter)
{
	struct adapter_data *data = connman_device_get_data(adapter);

	DBG("adapter %p", adapter);

	connman_device_set_data(adapter, NULL);

	dbus_connection_unref(data->connection);

	g_free(data);
}

static void powered_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply;

	DBG("");

	reply = dbus_pending_call_steal_reply(call);

	dbus_message_unref(reply);
}

static int change_powered(DBusConnection *connection, const char *path,
							dbus_bool_t powered)
{
	DBusMessage *message;
	DBusMessageIter iter;
	DBusPendingCall *call;

	DBG("");

	message = dbus_message_new_method_call(BLUEZ_SERVICE, path,
					BLUEZ_ADAPTER_INTERFACE, SET_PROPERTY);
	if (message == NULL)
		return -ENOMEM;

	dbus_message_iter_init_append(message, &iter);
	connman_dbus_property_append_variant(&iter, "Powered",
						DBUS_TYPE_BOOLEAN, &powered);

	if (dbus_connection_send_with_reply(connection, message,
						&call, TIMEOUT) == FALSE) {
		connman_error("Failed to change Powered property");
		dbus_message_unref(message);
		return -EINVAL;
	}

	if (call == NULL) {
		connman_error("D-Bus connection not available");
		dbus_message_unref(message);
		return -EINVAL;
	}

	dbus_pending_call_set_notify(call, powered_reply, NULL, NULL);

	dbus_message_unref(message);

	return -EINPROGRESS;
}

static int bluetooth_enable(struct connman_device *adapter)
{
	struct adapter_data *data = connman_device_get_data(adapter);
	const char *path = connman_device_get_string(adapter, "Node");

	DBG("adapter %p", adapter);

	return change_powered(data->connection, path, TRUE);
}

static int bluetooth_disable(struct connman_device *adapter)
{
	struct adapter_data *data = connman_device_get_data(adapter);
	const char *path = connman_device_get_string(adapter, "Node");

	DBG("adapter %p", adapter);

	return change_powered(data->connection, path, FALSE);
}

static int bluetooth_scan(struct connman_device *adapter)
{
	DBG("adapter %p", adapter);

	return -EIO;
}

static struct connman_device_driver bluetooth_driver = {
	.name		= "bluetooth",
	.type		= CONNMAN_DEVICE_TYPE_BLUETOOTH,
	.probe		= bluetooth_probe,
	.remove		= bluetooth_remove,
	.enable		= bluetooth_enable,
	.disable	= bluetooth_disable,
	.scan		= bluetooth_scan,
};

static GSList *adapter_list = NULL;

static void free_adapters(void)
{
	GSList *list;

	DBG("");

	for (list = adapter_list; list; list = list->next) {
		struct connman_device *adapter = list->data;

		connman_device_unregister(adapter);
		connman_device_unref(adapter);
	}

	g_slist_free(adapter_list);
	adapter_list = NULL;
}

static struct connman_device *find_adapter(const char *path)
{
	GSList *list;

	DBG("path %s", path);

	for (list = adapter_list; list; list = list->next) {
		struct connman_device *adapter = list->data;
		const char *adapter_path = connman_device_get_string(adapter,
									"Node");

		if (adapter_path == NULL)
			continue;

		if (g_str_equal(adapter_path, path) == TRUE)
			return adapter;
	}

	return NULL;
}

static void device_properties(DBusConnection *connection, const char *path,
				DBusMessage *message, void *user_data)
{
	struct connman_device *device = user_data;
	const char *node = g_basename(path);
	struct connman_network *network;

	DBG("path %s", path);

	network = connman_device_get_network(device, node);
	if (network != NULL)
		return;

	network = connman_network_create(node,
					CONNMAN_NETWORK_TYPE_BLUETOOTH_PAN);
	if (network == NULL)
		return;

	connman_network_set_protocol(network, CONNMAN_NETWORK_PROTOCOL_IP);

	connman_network_set_string(network, "Node", path);

	connman_device_add_network(device, network);
}

static void check_devices(struct connman_device *adapter,
			DBusConnection *connection, DBusMessageIter *array)
{
	DBusMessageIter value;

	if (dbus_message_iter_get_arg_type(array) != DBUS_TYPE_ARRAY)
		return;

	dbus_message_iter_recurse(array, &value);

	while (dbus_message_iter_get_arg_type(&value) == DBUS_TYPE_OBJECT_PATH) {
		const char *path;

		dbus_message_iter_get_basic(&value, &path);

		get_properties(connection, path, BLUEZ_DEVICE_INTERFACE,
						device_properties, adapter);

		dbus_message_iter_next(&value);
	}
}

static void property_changed(DBusConnection *connection, DBusMessage *message)
{
	const char *path = dbus_message_get_path(message);
	struct connman_device *adapter;
	DBusMessageIter iter, value;
	const char *key;

	DBG("path %s", path);

	adapter = find_adapter(path);
	if (adapter == NULL)
		return;

	if (dbus_message_iter_init(message, &iter) == FALSE)
		return;

	dbus_message_iter_get_basic(&iter, &key);

	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &value);

	if (g_str_equal(key, "Powered") == TRUE) {
		gboolean val;

		dbus_message_iter_get_basic(&value, &val);
		connman_device_set_powered(adapter, val);
	} else if (g_str_equal(key, "Discovering") == TRUE) {
		gboolean val;

		dbus_message_iter_get_basic(&value, &val);
		connman_device_set_scanning(adapter, val);
	}
}

static void parse_adapter_properties(struct connman_device *adapter,
						DBusConnection *connection,
							DBusMessage *reply)
{
	DBusMessageIter array, dict;

	if (dbus_message_iter_init(reply, &array) == FALSE)
		return;

	if (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_ARRAY)
		return;

	dbus_message_iter_recurse(&array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		if (g_str_equal(key, "Powered") == TRUE) {
			gboolean val;

			dbus_message_iter_get_basic(&value, &val);
			connman_device_set_powered(adapter, val);
		} else if (g_str_equal(key, "Discovering") == TRUE) {
			gboolean val;

			dbus_message_iter_get_basic(&value, &val);
			connman_device_set_scanning(adapter, val);
		} else if (g_str_equal(key, "Devices") == TRUE) {
			check_devices(adapter, connection, &value);
		}

		dbus_message_iter_next(&dict);
	}
}

static void adapter_properties(DBusConnection *connection, const char *path,
				DBusMessage *message, void *user_data)
{
	const char *node = g_basename(path);
	struct connman_device *adapter;

	DBG("path %s", path);

	adapter = find_adapter(path);
	if (adapter != NULL)
		goto done;

	adapter = connman_device_create(node, CONNMAN_DEVICE_TYPE_BLUETOOTH);
	if (adapter == NULL)
		return;

	connman_device_set_string(adapter, "Node", path);

	if (node != NULL && g_str_has_prefix(node, "hci") == TRUE) {
		int index;
		errno = 0;
		index = atoi(node + 3);
		if (errno == 0)
			connman_device_set_index(adapter, index);
	}

	connman_device_set_interface(adapter, node);

	connman_device_set_policy(adapter, CONNMAN_DEVICE_POLICY_MANUAL);
	connman_device_set_mode(adapter, CONNMAN_DEVICE_MODE_NETWORK_MULTIPLE);

	if (connman_device_register(adapter) < 0) {
		connman_device_unref(adapter);
		return;
	}

	adapter_list = g_slist_append(adapter_list, adapter);

done:
	parse_adapter_properties(adapter, connection, message);
}

static void add_adapter(DBusConnection *connection, const char *path)
{
	DBG("path %s", path);

	get_properties(connection, path, BLUEZ_ADAPTER_INTERFACE,
						adapter_properties, NULL);
}

static void remove_adapter(DBusConnection *connection, const char *path)
{
	struct connman_device *adapter;

	DBG("path %s", path);

	adapter = find_adapter(path);
	if (adapter == NULL)
		return;

	adapter_list = g_slist_remove(adapter_list, adapter);

	connman_device_unregister(adapter);
	connman_device_unref(adapter);
}

static void list_adapters_reply(DBusPendingCall *call, void *user_data)
{
	DBusConnection *connection = user_data;
	DBusMessage *reply;
	DBusError error;
	char **adapters;
	int i, num_adapters;

	DBG("");

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&error);

	if (dbus_message_get_args(reply, &error,
				DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH,
						&adapters, &num_adapters,
						DBUS_TYPE_INVALID) == FALSE) {
		if (dbus_error_is_set(&error) == TRUE) {
			connman_error("%s", error.message);
			dbus_error_free(&error);
		} else
			connman_error("Wrong arguments for adapter list");
		goto done;
	}

	for (i = 0; i < num_adapters; i++)
		get_properties(connection, adapters[i],
					BLUEZ_ADAPTER_INTERFACE,
						adapter_properties, NULL);

	g_strfreev(adapters);

done:
	dbus_message_unref(reply);
}

static void bluetooth_connect(DBusConnection *connection, void *user_data)
{
	DBusMessage *message;
	DBusPendingCall *call;

	DBG("connection %p", connection);

	message = dbus_message_new_method_call(BLUEZ_SERVICE, "/",
				BLUEZ_MANAGER_INTERFACE, LIST_ADAPTERS);
	if (message == NULL)
		return;

	if (dbus_connection_send_with_reply(connection, message,
						&call, TIMEOUT) == FALSE) {
		connman_error("Failed to get Bluetooth adapters");
		goto done;
	}

	if (call == NULL) {
		connman_error("D-Bus connection not available");
		goto done;
	}

	dbus_pending_call_set_notify(call, list_adapters_reply,
							connection, NULL);

done:
	dbus_message_unref(message);
}

static void bluetooth_disconnect(DBusConnection *connection, void *user_data)
{
	DBG("connection %p", connection);

	free_adapters();
}

static DBusHandlerResult bluetooth_signal(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	if (dbus_message_has_interface(message,
			BLUEZ_MANAGER_INTERFACE) == FALSE &&
				dbus_message_has_interface(message,
					BLUEZ_ADAPTER_INTERFACE) == FALSE)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	DBG("connection %p", connection);

	if (dbus_message_is_signal(message, BLUEZ_ADAPTER_INTERFACE,
						PROPERTY_CHANGED) == TRUE) {
		property_changed(connection, message);
	} else if (dbus_message_is_signal(message, BLUEZ_MANAGER_INTERFACE,
						ADAPTER_ADDED) == TRUE) {
		const char *path;
		dbus_message_get_args(message, NULL,
					DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID);
		add_adapter(connection, path);
	} else if (dbus_message_is_signal(message, BLUEZ_MANAGER_INTERFACE,
						ADAPTER_REMOVED) == TRUE) {
		const char *path;
		dbus_message_get_args(message, NULL,
					DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID);
		remove_adapter(connection, path);
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusConnection *connection;
static guint watch;

static const char *added_rule = "type=signal,member=" ADAPTER_ADDED
					",interface=" BLUEZ_MANAGER_INTERFACE;
static const char *removed_rule = "type=signal,member=" ADAPTER_REMOVED
					",interface=" BLUEZ_MANAGER_INTERFACE;

static const char *adapter_rule = "type=signal,member=" PROPERTY_CHANGED
					",interface=" BLUEZ_ADAPTER_INTERFACE;

static int bluetooth_init(void)
{
	int err = -EIO;

	connection = connman_dbus_get_connection();
	if (connection == NULL)
		return -EIO;

	if (dbus_connection_add_filter(connection, bluetooth_signal,
							NULL, NULL) == FALSE)
		goto unref;

	err = connman_network_driver_register(&pan_driver);
	if (err < 0)
		goto remove;

	err = connman_device_driver_register(&bluetooth_driver);
	if (err < 0) {
		connman_network_driver_unregister(&pan_driver);
		goto remove;
	}

	watch = g_dbus_add_service_watch(connection, BLUEZ_SERVICE,
			bluetooth_connect, bluetooth_disconnect, NULL, NULL);
	if (watch == 0) {
		connman_device_driver_unregister(&bluetooth_driver);
		connman_network_driver_unregister(&pan_driver);
		err = -EIO;
		goto remove;
	}

	if (g_dbus_check_service(connection, BLUEZ_SERVICE) == TRUE)
		bluetooth_connect(connection, NULL);

	dbus_bus_add_match(connection, added_rule, NULL);
	dbus_bus_add_match(connection, removed_rule, NULL);
	dbus_bus_add_match(connection, adapter_rule, NULL);
	dbus_connection_flush(connection);

	return 0;

remove:
	dbus_connection_remove_filter(connection, bluetooth_signal, NULL);

unref:
	dbus_connection_unref(connection);

	return err;
}

static void bluetooth_exit(void)
{
	dbus_bus_remove_match(connection, adapter_rule, NULL);
	dbus_bus_remove_match(connection, removed_rule, NULL);
	dbus_bus_remove_match(connection, added_rule, NULL);
	dbus_connection_flush(connection);

	g_dbus_remove_watch(connection, watch);

	free_adapters();

	connman_device_driver_unregister(&bluetooth_driver);
	connman_network_driver_unregister(&pan_driver);

	dbus_connection_remove_filter(connection, bluetooth_signal, NULL);

	dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE(bluetooth, "Bluetooth technology plugin", VERSION,
		CONNMAN_PLUGIN_PRIORITY_DEFAULT, bluetooth_init, bluetooth_exit)
