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

#include "connman.h"

static int set_powered(struct connman_device *device, gboolean powered)
{
	struct connman_device_driver *driver = device->driver;
	int err;

	DBG("device %p powered %d", device, powered);

	if (!driver)
		return -EINVAL;

	if (powered == TRUE) {
		if (driver->enable)
			err = driver->enable(device);
		else
			err = -EINVAL;
	} else {
		if (driver->disable)
			err = driver->disable(device);
		else
			err = -EINVAL;
	}

	return err;
}

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_device *device = data;
	DBusMessage *reply;
	DBusMessageIter array, dict;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &array);

	dbus_message_iter_open_container(&array, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	connman_dbus_dict_append_variant(&dict, "Powered",
					DBUS_TYPE_BOOLEAN, &device->powered);

	if (device->driver && device->driver->scan)
		connman_dbus_dict_append_variant(&dict, "Scanning",
					DBUS_TYPE_BOOLEAN, &device->scanning);

	dbus_message_iter_close_container(&array, &dict);

	return reply;
}

static DBusMessage *set_property(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_device *device = data;
	DBusMessageIter iter, value;
	const char *name;

	DBG("conn %p", conn);

	if (dbus_message_iter_init(msg, &iter) == FALSE)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &name);
	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &value);

	if (__connman_security_check_privileges(msg) < 0)
		return __connman_error_permission_denied(msg);

	if (g_str_equal(name, "Powered") == TRUE) {
		gboolean powered;
		int err;

		dbus_message_iter_get_basic(&value, &powered);

		if (device->powered == powered)
			return __connman_error_invalid_arguments(msg);

		err = set_powered(device, powered);
		if (err < 0 && err != -EINPROGRESS)
			return __connman_error_failed(msg);
	}

	__connman_element_store(device->element);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *create_network(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBG("conn %p", conn);

	if (__connman_security_check_privileges(msg) < 0)
		return __connman_error_permission_denied(msg);

	return __connman_error_invalid_arguments(msg);
}

static DBusMessage *remove_network(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBG("conn %p", conn);

	if (__connman_security_check_privileges(msg) < 0)
		return __connman_error_permission_denied(msg);

	return __connman_error_invalid_arguments(msg);
}

static DBusMessage *propose_scan(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBG("conn %p", conn);

	return __connman_error_failed(msg);
}

static GDBusMethodTable device_methods[] = {
	{ "GetProperties", "",      "a{sv}", get_properties },
	{ "SetProperty",   "sv",    "",      set_property   },
	{ "CreateNetwork", "a{sv}", "o",     create_network },
	{ "RemoveNetwork", "o",     "",      remove_network },
	{ "ProposeScan",   "",      "",      propose_scan   },
	{ },
};

static GDBusSignalTable device_signals[] = {
	{ "PropertyChanged", "sv" },
	{ },
};

static DBusConnection *connection;

static int register_interface(struct connman_element *element)
{
	struct connman_device *device = connman_element_get_data(element);

	g_dbus_unregister_interface(connection, element->path,
						CONNMAN_DEVICE_INTERFACE);

	if (g_dbus_register_interface(connection, element->path,
					CONNMAN_DEVICE_INTERFACE,
					device_methods, device_signals,
					NULL, device, NULL) == FALSE) {
		connman_error("Failed to register %s device", element->path);
		return -EIO;
	}

	return 0;
}

static void unregister_interface(struct connman_element *element)
{
	g_dbus_unregister_interface(connection, element->path,
						CONNMAN_DEVICE_INTERFACE);
}

static GSList *driver_list = NULL;

static gint compare_priority(gconstpointer a, gconstpointer b)
{
	const struct connman_device_driver *driver1 = a;
	const struct connman_device_driver *driver2 = b;

	return driver2->priority - driver1->priority;
}

/**
 * connman_device_driver_register:
 * @driver: device driver definition
 *
 * Register a new device driver
 *
 * Returns: %0 on success
 */
int connman_device_driver_register(struct connman_device_driver *driver)
{
	DBG("driver %p name %s", driver, driver->name);

	driver_list = g_slist_insert_sorted(driver_list, driver,
							compare_priority);

	//__connman_driver_rescan(&device_driver);

	return 0;
}

/**
 * connman_device_driver_unregister:
 * @driver: device driver definition
 *
 * Remove a previously registered device driver
 */
void connman_device_driver_unregister(struct connman_device_driver *driver)
{
	DBG("driver %p name %s", driver, driver->name);

	driver_list = g_slist_remove(driver_list, driver);
}

/**
 * connman_device_set_powered:
 * @device: device structure
 *
 * Change power state of device
 */
int connman_device_set_powered(struct connman_device *device,
							gboolean powered)
{
	DBusMessage *signal;
	DBusMessageIter entry, value;
	const char *key = "Powered";

	DBG("driver %p powered %d", device, powered);

	if (device->powered == powered)
		return -EALREADY;

	device->powered = powered;

	signal = dbus_message_new_signal(device->element->path,
				CONNMAN_DEVICE_INTERFACE, "PropertyChanged");
	if (signal == NULL)
		return 0;

	dbus_message_iter_init_append(signal, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
					DBUS_TYPE_BOOLEAN_AS_STRING, &value);
	dbus_message_iter_append_basic(&value, DBUS_TYPE_BOOLEAN, &powered);
	dbus_message_iter_close_container(&entry, &value);

	g_dbus_send_message(connection, signal);

	return 0;
}

/**
 * connman_device_set_scanning:
 * @device: device structure
 *
 * Change scanning state of device
 */
int connman_device_set_scanning(struct connman_device *device,
							gboolean scanning)
{
	DBusMessage *signal;
	DBusMessageIter entry, value;
	const char *key = "Scanning";

	DBG("driver %p scanning %d", device, scanning);

	if (!device->driver)
		return -EINVAL;

	if (!device->driver->scan)
		return -EINVAL;

	if (device->scanning == scanning)
		return -EALREADY;

	device->scanning = scanning;

	signal = dbus_message_new_signal(device->element->path,
				CONNMAN_DEVICE_INTERFACE, "PropertyChanged");
	if (signal == NULL)
		return 0;

	dbus_message_iter_init_append(signal, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
					DBUS_TYPE_BOOLEAN_AS_STRING, &value);
	dbus_message_iter_append_basic(&value, DBUS_TYPE_BOOLEAN, &scanning);
	dbus_message_iter_close_container(&entry, &value);

	g_dbus_send_message(connection, signal);

	return 0;
}

static gboolean match_driver(struct connman_device *device,
					struct connman_device_driver *driver)
{
	if (device->element->subtype == driver->type ||
			driver->type == CONNMAN_DEVICE_TYPE_UNKNOWN)
		return TRUE;

	return FALSE;
}

static int device_probe(struct connman_element *element)
{
	struct connman_device *device;
	GSList *list;
	int err;

	DBG("element %p name %s", element, element->name);

	if (element->subtype == CONNMAN_ELEMENT_SUBTYPE_NETWORK)
		return -ENODEV;

	device = g_try_new0(struct connman_device, 1);
	if (device == NULL)
		return -ENOMEM;

	device->element = element;

	connman_element_set_data(element, device);

	err = register_interface(element);
	if (err < 0) {
		g_free(device);
		return err;
	}

	for (list = driver_list; list; list = list->next) {
		struct connman_device_driver *driver = list->data;

		if (match_driver(device, driver) == FALSE)
			continue;

		DBG("driver %p name %s", driver, driver->name);

		if (driver->probe(device) == 0) {
			device->driver = driver;
			break;
		}
	}

	return 0;
}

static void device_remove(struct connman_element *element)
{
	struct connman_device *device = connman_element_get_data(element);

	DBG("element %p name %s", element, element->name);

	unregister_interface(element);

	if (device->driver && device->driver->remove)
		device->driver->remove(device);

	connman_element_set_data(element, NULL);

	g_free(device);
}

static struct connman_driver device_driver = {
	.name		= "device",
	.type		= CONNMAN_ELEMENT_TYPE_DEVICE,
	.priority	= CONNMAN_DRIVER_PRIORITY_LOW,
	.probe		= device_probe,
	.remove		= device_remove,
};

int __connman_device_init(void)
{
	DBG("");

	connection = connman_dbus_get_connection();

	return connman_driver_register(&device_driver);
}

void __connman_device_cleanup(void)
{
	DBG("");

	connman_driver_unregister(&device_driver);

	dbus_connection_unref(connection);
}
