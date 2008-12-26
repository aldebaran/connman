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

struct connman_device {
	struct connman_element element;
	enum connman_device_type type;
	enum connman_device_mode mode;
	enum connman_device_policy policy;
	gboolean powered;
	gboolean carrier;
	gboolean scanning;
	char *path;
	char *interface;

	struct connman_device_driver *driver;
	void *driver_data;

	GHashTable *networks;
};

static const char *type2description(enum connman_device_type type)
{
	switch (type) {
	case CONNMAN_DEVICE_TYPE_ETHERNET:
		return "Ethernet";
	case CONNMAN_DEVICE_TYPE_WIFI:
		return "Wireless";
	case CONNMAN_DEVICE_TYPE_WIMAX:
		return "WiMAX";
	case CONNMAN_DEVICE_TYPE_BLUETOOTH:
		return "Bluetooth";
	default:
		return NULL;
	}
}

static const char *type2string(enum connman_device_type type)
{
	switch (type) {
	case CONNMAN_DEVICE_TYPE_ETHERNET:
		return "ethernet";
	case CONNMAN_DEVICE_TYPE_WIFI:
		return "wifi";
	case CONNMAN_DEVICE_TYPE_WIMAX:
		return "wimax";
	case CONNMAN_DEVICE_TYPE_MODEM:
		return "modem";
	case CONNMAN_DEVICE_TYPE_BLUETOOTH:
		return "bluetooth";
	default:
		return NULL;
	}
}

static const char *policy2string(enum connman_device_policy policy)
{
	switch (policy) {
	case CONNMAN_DEVICE_POLICY_IGNORE:
		return "ignore";
	case CONNMAN_DEVICE_POLICY_AUTO:
		return "auto";
	case CONNMAN_DEVICE_POLICY_OFF:
		return "off";
	default:
		return NULL;
	}
}

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

static void append_networks(struct connman_device *device,
						DBusMessageIter *entry)
{
	DBusMessageIter value, iter;
	const char *key = "Networks";

	dbus_message_iter_append_basic(entry, DBUS_TYPE_STRING, &key);

	dbus_message_iter_open_container(entry, DBUS_TYPE_VARIANT,
		DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_OBJECT_PATH_AS_STRING,
								&value);

	dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY,
				DBUS_TYPE_OBJECT_PATH_AS_STRING, &iter);
	/* FIXME append networks */
	dbus_message_iter_close_container(&value, &iter);

	dbus_message_iter_close_container(entry, &value);
}

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_device *device = data;
	DBusMessage *reply;
	DBusMessageIter array, dict, entry;
	const char *str;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &array);

	dbus_message_iter_open_container(&array, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	str = type2description(device->type);
	if (str != NULL && device->interface != NULL) {
		char *name = g_strdup_printf("%s (%s)", str, device->interface);
		if (name != NULL)
			connman_dbus_dict_append_variant(&dict, "Name",
						DBUS_TYPE_STRING, &name);
		g_free(name);
	}

	str = type2string(device->type);
	if (str != NULL)
		connman_dbus_dict_append_variant(&dict, "Type",
						DBUS_TYPE_STRING, &str);

	if (device->interface != NULL)
		connman_dbus_dict_append_variant(&dict, "Interface",
					DBUS_TYPE_STRING, &device->interface);

	str = policy2string(device->policy);
	if (str != NULL)
		connman_dbus_dict_append_variant(&dict, "Policy",
						DBUS_TYPE_STRING, &str);

	connman_dbus_dict_append_variant(&dict, "Powered",
					DBUS_TYPE_BOOLEAN, &device->powered);

	if (device->driver && device->driver->scan)
		connman_dbus_dict_append_variant(&dict, "Scanning",
					DBUS_TYPE_BOOLEAN, &device->scanning);

	if (device->mode != CONNMAN_DEVICE_MODE_NO_NETWORK) {
		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY,
								NULL, &entry);
		append_networks(device, &entry);
		dbus_message_iter_close_container(&dict, &entry);
	}

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

	__connman_element_store(&device->element);

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
	struct connman_device *device = data;
	int err;

	DBG("conn %p", conn);

	if (device->mode == CONNMAN_DEVICE_MODE_NO_NETWORK)
		return __connman_error_not_supported(msg);

	if (!device->driver || !device->driver->scan)
		return __connman_error_not_supported(msg);

	err = device->driver->scan(device);
	if (err < 0)
		return __connman_error_failed(msg);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
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
	struct connman_device *device = element->device;

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

static void unregister_network(gpointer data)
{
	struct connman_network *network = data;

	DBG("network %p", network);

	connman_element_unregister((struct connman_element *) network);

	connman_network_unref(network);
}

static void device_destruct(struct connman_element *element)
{
	struct connman_device *device = element->device;

	DBG("element %p name %s", element, element->name);

	g_free(device->interface);

	g_hash_table_destroy(device->networks);
}

/**
 * connman_device_create:
 * @node: device node name (for example an address)
 * @type: device type
 *
 * Allocate a new device of given #type and assign the #node name to it.
 *
 * Returns: a newly-allocated #connman_device structure
 */
struct connman_device *connman_device_create(const char *node,
						enum connman_device_type type)
{
	struct connman_device *device;

	DBG("node %s type %d", node, type);

	device = g_try_new0(struct connman_device, 1);
	if (device == NULL)
		return NULL;

	DBG("device %p", device);

	device->element.refcount = 1;

	device->element.name = g_strdup(node);
	device->element.type = CONNMAN_ELEMENT_TYPE_DEVICE;
	device->element.index = -1;

	device->element.device = device;
	device->element.destruct = device_destruct;

	device->type = type;
	device->mode = CONNMAN_DEVICE_MODE_NO_NETWORK;
	device->policy = CONNMAN_DEVICE_POLICY_AUTO;

	device->networks = g_hash_table_new_full(g_str_hash, g_str_equal,
						g_free, unregister_network);

	return device;
}

/**
 * connman_device_ref:
 * @device: device structure
 *
 * Increase reference counter of device
 */
struct connman_device *connman_device_ref(struct connman_device *device)
{
	if (connman_element_ref(&device->element) == NULL)
		return NULL;

	return device;
}

/**
 * connman_device_unref:
 * @device: device structure
 *
 * Decrease reference counter of device
 */
void connman_device_unref(struct connman_device *device)
{
	connman_element_unref(&device->element);
}

/**
 * connman_device_set_path:
 * @device: device structure
 * @path: path name
 *
 * Set path name of device
 */
void connman_device_set_path(struct connman_device *device, const char *path)
{
	g_free(device->element.devpath);
	device->element.devpath = g_strdup(path);

	g_free(device->path);
	device->path = g_strdup(path);
}

/**
 * connman_device_get_path:
 * @device: device structure
 *
 * Get path name of device
 */
const char *connman_device_get_path(struct connman_device *device)
{
	return device->path;
}

/**
 * connman_device_set_index:
 * @device: device structure
 * @index: index number
 *
 * Set index number of device
 */
void connman_device_set_index(struct connman_device *device, int index)
{
	device->element.index = index;
}

/**
 * connman_device_get_index:
 * @device: device structure
 *
 * Get index number of device
 */
int connman_device_get_index(struct connman_device *device)
{
	return device->element.index;
}

/**
 * connman_device_set_interface:
 * @device: device structure
 * @interface: interface name
 *
 * Set interface name of device
 */
void connman_device_set_interface(struct connman_device *device,
							const char *interface)
{
	g_free(device->element.devname);
	device->element.devname = g_strdup(interface);

	g_free(device->interface);
	device->interface = g_strdup(interface);
}

/**
 * connman_device_get_interface:
 * @device: device structure
 *
 * Get interface name of device
 */
const char *connman_device_get_interface(struct connman_device *device)
{
	return device->interface;
}

/**
 * connman_device_set_mode:
 * @device: device structure
 * @mode: network mode
 *
 * Change network mode of device
 */
void connman_device_set_mode(struct connman_device *device,
						enum connman_device_mode mode)
{
	device->mode = mode;
}

/**
 * connman_device_set_powered:
 * @device: device structure
 * @powered: powered state
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

	signal = dbus_message_new_signal(device->element.path,
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
 * connman_device_set_carrier:
 * @device: device structure
 * @carrier: carrier state
 *
 * Change carrier state of device (only for device without scanning)
 */
int connman_device_set_carrier(struct connman_device *device,
							gboolean carrier)
{
	DBG("driver %p carrier %d", device, carrier);

	if (device->mode != CONNMAN_DEVICE_MODE_NO_NETWORK)
		return -EINVAL;

	if (device->carrier == carrier)
		return -EALREADY;

	device->carrier = carrier;

	if (carrier == TRUE) {
		struct connman_element *element;

		element = connman_element_create(NULL);
		if (element != NULL) {
			element->type    = CONNMAN_ELEMENT_TYPE_DEVICE;
			element->subtype = CONNMAN_ELEMENT_SUBTYPE_NETWORK;
			element->index   = device->element.index;

			if (connman_element_register(element,
							&device->element) < 0)
				connman_element_unref(element);
		}
	} else
		connman_element_unregister_children(&device->element);

	return 0;
}

/**
 * connman_device_set_scanning:
 * @device: device structure
 * @scanning: scanning state
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

	if (!device->driver || !device->driver->scan)
		return -EINVAL;

	if (device->scanning == scanning)
		return -EALREADY;

	device->scanning = scanning;

	signal = dbus_message_new_signal(device->element.path,
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

/**
 * connman_device_add_network:
 * @device: device structure
 * @network: network structure
 *
 * Add new network to the device
 */
int connman_device_add_network(struct connman_device *device,
					struct connman_network *network)
{
	const char *identifier = connman_network_get_identifier(network);
	int err;

	DBG("device %p network %p", device, network);

	if (device->mode == CONNMAN_DEVICE_MODE_NO_NETWORK)
		return -EINVAL;

	err = connman_element_register(&device->element,
					(struct connman_element *) network);
	if (err < 0)
		return err;

	g_hash_table_insert(device->networks, g_strdup(identifier),
								network);

	return 0;
}

/**
 * connman_device_get_network:
 * @device: device structure
 * @indentifier: network identifier
 *
 * Get network for given identifier
 */
struct connman_network *connman_device_get_network(struct connman_device *device,
							const char *identifier)
{
	DBG("device %p identifier %s", device, identifier);

	return g_hash_table_lookup(device->networks, identifier);
}

/**
 * connman_device_remove_network:
 * @device: device structure
 * @indentifier: network identifier
 *
 * Remove network for given identifier
 */
int connman_device_remove_network(struct connman_device *device,
							const char *identifier)
{
	DBG("device %p identifier %s", device, identifier);

	g_hash_table_remove(device->networks, identifier);

	return 0;
}

/**
 * connman_device_register:
 * @device: device structure
 *
 * Register device with the system
 */
int connman_device_register(struct connman_device *device)
{
	return connman_element_register(&device->element, NULL);
}

/**
 * connman_device_unregister:
 * @device: device structure
 *
 * Unregister device with the system
 */
void connman_device_unregister(struct connman_device *device)
{
	connman_element_unregister(&device->element);
}

/**
 * connman_device_get_data:
 * @device: device structure
 *
 * Get private device data pointer
 */
void *connman_device_get_data(struct connman_device *device)
{
	return device->driver_data;
}

/**
 * connman_device_set_data:
 * @device: device structure
 * @data: data pointer
 *
 * Set private device data pointer
 */
void connman_device_set_data(struct connman_device *device, void *data)
{
	device->driver_data = data;
}

static void device_enable(struct connman_device *device)
{
	DBG("device %p", device);

	if (device->policy != CONNMAN_DEVICE_POLICY_AUTO)
		return;

	if (device->powered == TRUE)
		return;

	if (device->driver->enable)
		device->driver->enable(device);
}

static void device_disable(struct connman_device *device)
{
	DBG("device %p", device);

	if (device->policy != CONNMAN_DEVICE_POLICY_AUTO)
		return;

	if (device->powered == FALSE)
		return;

	if (device->driver->disable)
		device->driver->disable(device);
}

static gboolean match_driver(struct connman_device *device,
					struct connman_device_driver *driver)
{
	if (device->type == driver->type ||
			driver->type == CONNMAN_DEVICE_TYPE_UNKNOWN)
		return TRUE;

	return FALSE;
}

static int device_probe(struct connman_element *element)
{
	struct connman_device *device = element->device;
	GSList *list;
	int err;

	DBG("element %p name %s", element, element->name);

	if (device == NULL)
		return -ENODEV;

	err = register_interface(element);
	if (err < 0)
		return err;

	for (list = driver_list; list; list = list->next) {
		struct connman_device_driver *driver = list->data;

		if (match_driver(device, driver) == FALSE)
			continue;

		DBG("driver %p name %s", driver, driver->name);

		if (driver->probe(device) == 0) {
			device->driver = driver;
			device_enable(device);
			break;
		}
	}

	return 0;
}

static void device_remove(struct connman_element *element)
{
	struct connman_device *device = element->device;

	DBG("element %p name %s", element, element->name);

	if (device == NULL)
		return;

	unregister_interface(element);

	if (device->driver) {
		device_disable(device);

		if (device->driver->remove)
			device->driver->remove(device);
	}
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
