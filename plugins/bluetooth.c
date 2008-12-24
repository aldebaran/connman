/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2008  Intel Corporation. All rights reserved.
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

#include <connman/plugin.h>
#include <connman/device.h>
#include <connman/driver.h>
#include <connman/dbus.h>
#include <connman/log.h>

#define BLUEZ_SERVICE			"org.bluez"
#define BLUEZ_MANAGER_INTERFACE		BLUEZ_SERVICE ".Manager"
#define BLUEZ_ADAPTER_INTERFACE		BLUEZ_SERVICE ".Adapter"

#define LIST_ADAPTERS			"ListAdapters"
#define ADAPTER_ADDED			"AdapterAdded"
#define ADAPTER_REMOVED			"AdapterRemoved"

#define PROPERTY_CHANGED		"PropertyChanged"
#define GET_PROPERTIES			"GetProperties"
#define SET_PROPERTY			"SetProperty"

#define TIMEOUT 5000

struct adapter_data {
	DBusConnection *connection;
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

	dbus_pending_call_set_notify(call, powered_reply, NULL, NULL);

	dbus_message_unref(message);

	return -EINPROGRESS;
}

static int bluetooth_enable(struct connman_device *adapter)
{
	struct adapter_data *data = connman_device_get_data(adapter);

	DBG("adapter %p", adapter);

	return change_powered(data->connection,
					adapter->element->devpath, TRUE);
}

static int bluetooth_disable(struct connman_device *adapter)
{
	struct adapter_data *data = connman_device_get_data(adapter);

	DBG("adapter %p", adapter);

	return change_powered(data->connection,
					adapter->element->devpath, FALSE);
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

static GSList *device_list = NULL;

static struct connman_element *find_adapter(const char *path)
{
	GSList *list;

	DBG("path %s", path);

	for (list = device_list; list; list = list->next) {
		struct connman_element *device = list->data;

		if (g_str_equal(device->devpath, path) == TRUE)
			return device;
	}

	return NULL;
}

static void check_devices(struct connman_element *adapter,
						DBusMessageIter *array)
{
	DBusMessageIter value;

	DBG("adapter %p name %s", adapter, adapter->name);

	if (dbus_message_iter_get_arg_type(array) != DBUS_TYPE_ARRAY)
		return;

	dbus_message_iter_recurse(array, &value);

	while (dbus_message_iter_get_arg_type(&value) == DBUS_TYPE_OBJECT_PATH) {
		const char *path;

		dbus_message_iter_get_basic(&value, &path);

		DBG("device %s", path);

		dbus_message_iter_next(&value);
	}
}

static void property_changed(DBusConnection *connection, DBusMessage *message)
{
	const char *path = dbus_message_get_path(message);
	struct connman_element *device;
	DBusMessageIter iter, value;
	const char *key;

	DBG("path %s", path);

	device = find_adapter(path);
	if (device == NULL)
		return;

	if (dbus_message_iter_init(message, &iter) == FALSE)
		return;

	dbus_message_iter_get_basic(&iter, &key);

	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &value);

	if (g_str_equal(key, "Powered") == TRUE) {
		struct connman_device *dev = connman_element_get_data(device);
		gboolean val;

		dbus_message_iter_get_basic(&value, &val);
		if (dev != NULL)
			connman_device_set_powered(dev, val);
	} else if (g_str_equal(key, "Discovering") == TRUE) {
		struct connman_device *dev = connman_element_get_data(device);
		gboolean val;

		dbus_message_iter_get_basic(&value, &val);
		if (dev != NULL)
			connman_device_set_scanning(dev, val);
	}
}

static void properties_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *message = user_data;
	const char *path = dbus_message_get_path(message);
	struct connman_element *device;
	DBusMessageIter array, dict;
	DBusMessage *reply;

	DBG("path %s", path);

	device = find_adapter(path);

	dbus_message_unref(message);

	reply = dbus_pending_call_steal_reply(call);

	if (device == NULL)
		goto done;

	if (dbus_message_iter_init(reply, &array) == FALSE)
		goto done;

	if (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_ARRAY)
		goto done;

	dbus_message_iter_recurse(&array, &dict);
	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		struct connman_device *dev = connman_element_get_data(device);
		DBusMessageIter entry, value;
		const char *key;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		if (g_str_equal(key, "Powered") == TRUE) {
			gboolean val;

			dbus_message_iter_get_basic(&value, &val);
			if (dev != NULL)
				connman_device_set_powered(dev, val);
		} else if (g_str_equal(key, "Discovering") == TRUE) {
			gboolean val;

			dbus_message_iter_get_basic(&value, &val);
			if (dev != NULL)
				connman_device_set_scanning(dev, val);
		} else if (g_str_equal(key, "Devices") == TRUE) {
			check_devices(device, &value);
		}

		dbus_message_iter_next(&dict);
	}

done:
	dbus_message_unref(reply);
}

static void add_adapter(DBusConnection *connection, const char *path)
{
	struct connman_element *device;
	DBusMessage *message;
	DBusPendingCall *call;

	DBG("path %s", path);

	device = find_adapter(path);
	if (device != NULL)
		return;

	device = connman_element_create(NULL);
	device->type = CONNMAN_ELEMENT_TYPE_DEVICE;
	device->subtype = CONNMAN_ELEMENT_SUBTYPE_BLUETOOTH;
	device->policy = CONNMAN_ELEMENT_POLICY_IGNORE;

	device->name = g_path_get_basename(path);
	device->devpath = g_strdup(path);

	if (connman_element_register(device, NULL) < 0) {
		connman_element_unref(device);
		return;
	}

	device_list = g_slist_append(device_list, device);

	message = dbus_message_new_method_call(BLUEZ_SERVICE, path,
				BLUEZ_ADAPTER_INTERFACE, GET_PROPERTIES);
	if (message == NULL)
		return;

	if (dbus_connection_send_with_reply(connection, message,
						&call, TIMEOUT) == FALSE) {
		connman_error("Failed to get adapter properties");
		dbus_message_unref(message);
		return;
	}

	dbus_pending_call_set_notify(call, properties_reply, message, NULL);
}

static void remove_adapter(DBusConnection *connection, const char *path)
{
	struct connman_element *device;

	DBG("path %s", path);

	device = find_adapter(path);
	if (device == NULL)
		return;

	device_list = g_slist_remove(device_list, device);

	connman_element_unregister(device);
	connman_element_unref(device);
}

static void adapters_reply(DBusPendingCall *call, void *user_data)
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
		add_adapter(connection, adapters[i]);

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
		dbus_message_unref(message);
		return;
	}

	dbus_pending_call_set_notify(call, adapters_reply, connection, NULL);

	dbus_message_unref(message);
}

static void bluetooth_disconnect(DBusConnection *connection, void *user_data)
{
	GSList *list;

	DBG("connection %p", connection);

	for (list = device_list; list; list = list->next) {
		struct connman_element *device = list->data;

		connman_element_unregister(device);
		connman_element_unref(device);
	}

	g_slist_free(device_list);
	device_list = NULL;
}

static DBusHandlerResult bluetooth_signal(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
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

	err = connman_device_driver_register(&bluetooth_driver);
	if (err < 0)
		goto remove;

	watch = g_dbus_add_service_watch(connection, BLUEZ_SERVICE,
			bluetooth_connect, bluetooth_disconnect, NULL, NULL);
	if (watch == 0) {
		connman_device_driver_unregister(&bluetooth_driver);
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

	bluetooth_disconnect(connection, NULL);

	connman_device_driver_unregister(&bluetooth_driver);

	dbus_connection_remove_filter(connection, bluetooth_signal, NULL);

	dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE(bluetooth, "Bluetooth technology plugin", VERSION,
						bluetooth_init, bluetooth_exit)
