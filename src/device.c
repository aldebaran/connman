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
#include <string.h>

#include <gdbus.h>

#include "connman.h"

static DBusConnection *connection = NULL;

struct connman_device {
	struct connman_element element;
	enum connman_device_type type;
	enum connman_device_mode mode;
	connman_bool_t offlinemode;
	connman_bool_t blocked;
	connman_bool_t powered;
	connman_bool_t powered_pending;
	connman_bool_t powered_persistent;
	connman_bool_t scanning;
	connman_bool_t disconnected;
	connman_bool_t reconnect;
	connman_uint16_t scan_interval;
	char *name;
	char *node;
	char *address;
	char *interface;
	char *control;
	char *ident;
	int phyindex;
	unsigned int connections;
	guint scan_timeout;

	struct connman_device_driver *driver;
	void *driver_data;

	connman_bool_t registered;

	char *last_network;
	struct connman_network *network;
	GHashTable *networks;

	DBusMessage *pending;
	guint timeout;
};

static gboolean device_scan_trigger(gpointer user_data)
{
	struct connman_device *device = user_data;

	DBG("device %p", device);

	if (device->driver == NULL) {
		device->scan_timeout = 0;
		return FALSE;
	}

	if (device->driver->scan)
		device->driver->scan(device);

	return TRUE;
}

static void clear_scan_trigger(struct connman_device *device)
{
	if (device->scan_timeout > 0) {
		g_source_remove(device->scan_timeout);
		device->scan_timeout = 0;
	}
}

static void reset_scan_trigger(struct connman_device *device)
{
	clear_scan_trigger(device);

	if (device->scan_interval > 0) {
		guint interval = device->scan_interval;
		device->scan_timeout = g_timeout_add_seconds(interval,
					device_scan_trigger, device);
	}
}

static void force_scan_trigger(struct connman_device *device)
{
	clear_scan_trigger(device);

	device->scan_timeout = g_timeout_add_seconds(5,
					device_scan_trigger, device);
}

void connman_device_schedule_scan(struct connman_device *device)
{
	reset_scan_trigger(device);
}

static const char *type2description(enum connman_device_type type)
{
	switch (type) {
	case CONNMAN_DEVICE_TYPE_UNKNOWN:
	case CONNMAN_DEVICE_TYPE_VENDOR:
		break;
	case CONNMAN_DEVICE_TYPE_ETHERNET:
		return "Ethernet";
	case CONNMAN_DEVICE_TYPE_WIFI:
		return "Wireless";
	case CONNMAN_DEVICE_TYPE_WIMAX:
		return "WiMAX";
	case CONNMAN_DEVICE_TYPE_BLUETOOTH:
		return "Bluetooth";
	case CONNMAN_DEVICE_TYPE_GPS:
		return "GPS";
	case CONNMAN_DEVICE_TYPE_CELLULAR:
		return "Cellular";
	}

	return NULL;
}

static const char *type2string(enum connman_device_type type)
{
	switch (type) {
	case CONNMAN_DEVICE_TYPE_UNKNOWN:
	case CONNMAN_DEVICE_TYPE_VENDOR:
		break;
	case CONNMAN_DEVICE_TYPE_ETHERNET:
		return "ethernet";
	case CONNMAN_DEVICE_TYPE_WIFI:
		return "wifi";
	case CONNMAN_DEVICE_TYPE_WIMAX:
		return "wimax";
	case CONNMAN_DEVICE_TYPE_BLUETOOTH:
		return "bluetooth";
	case CONNMAN_DEVICE_TYPE_GPS:
		return "gps";
	case CONNMAN_DEVICE_TYPE_CELLULAR:
		return "cellular";
	}

	return NULL;
}

enum connman_service_type __connman_device_get_service_type(struct connman_device *device)
{
	enum connman_device_type type = connman_device_get_type(device);

	switch (type) {
	case CONNMAN_DEVICE_TYPE_UNKNOWN:
	case CONNMAN_DEVICE_TYPE_VENDOR:
	case CONNMAN_DEVICE_TYPE_GPS:
		break;
	case CONNMAN_DEVICE_TYPE_ETHERNET:
		return CONNMAN_SERVICE_TYPE_ETHERNET;
	case CONNMAN_DEVICE_TYPE_WIFI:
		return CONNMAN_SERVICE_TYPE_WIFI;
	case CONNMAN_DEVICE_TYPE_WIMAX:
		return CONNMAN_SERVICE_TYPE_WIMAX;
	case CONNMAN_DEVICE_TYPE_BLUETOOTH:
		return CONNMAN_SERVICE_TYPE_BLUETOOTH;
	case CONNMAN_DEVICE_TYPE_CELLULAR:
		return CONNMAN_SERVICE_TYPE_CELLULAR;
	}

	return CONNMAN_SERVICE_TYPE_UNKNOWN;
}

static void powered_changed(struct connman_device *device)
{
	connman_dbus_property_changed_basic(device->element.path,
				CONNMAN_DEVICE_INTERFACE, "Powered",
					DBUS_TYPE_BOOLEAN, &device->powered);
}

static void blocked_changed(struct connman_device *device)
{
	connman_dbus_property_changed_basic(device->element.path,
				CONNMAN_DEVICE_INTERFACE, "Blocked",
					DBUS_TYPE_BOOLEAN, &device->blocked);
}

int __connman_device_enable(struct connman_device *device)
{
	int err;

	DBG("device %p", device);

	if (!device->driver || !device->driver->enable)
		return -EOPNOTSUPP;

	if (device->powered_pending == TRUE)
		return -EALREADY;

	if (device->blocked == TRUE)
		return -ENOLINK;

	err = device->driver->enable(device);
	if (err < 0) {
		if (err == -EINPROGRESS) {
			device->powered_pending = TRUE;
			device->offlinemode = FALSE;
			if (__connman_profile_get_offlinemode() == TRUE)
				__connman_profile_set_offlinemode(FALSE, FALSE);
		}
		return err;
	}

	device->powered_pending = TRUE;
	device->powered = TRUE;
	device->offlinemode = FALSE;
	if (__connman_profile_get_offlinemode() == TRUE)
		__connman_profile_set_offlinemode(FALSE, FALSE);

	__connman_technology_enable_device(device);

	return 0;
}

int __connman_device_disable(struct connman_device *device)
{
	int err;

	DBG("device %p", device);

	if (!device->driver || !device->driver->disable)
		return -EOPNOTSUPP;

	if (device->powered == FALSE)
		return -ENOLINK;

	if (device->powered_pending == FALSE)
		return -EALREADY;

	device->reconnect = FALSE;

	clear_scan_trigger(device);

	g_hash_table_remove_all(device->networks);

	err = device->driver->disable(device);
	if (err < 0) {
		if (err == -EINPROGRESS)
			device->powered_pending = FALSE;
		return err;
	}

	device->powered_pending = FALSE;
	device->powered = FALSE;

	__connman_technology_disable_device(device);

	return 0;
}

static int set_powered(struct connman_device *device, connman_bool_t powered)
{
	DBG("device %p powered %d", device, powered);

	if (powered == TRUE)
		return __connman_device_enable(device);
	else
		return __connman_device_disable(device);
}

void __connman_device_list(DBusMessageIter *iter, void *user_data)
{
	__connman_element_list(NULL, CONNMAN_ELEMENT_TYPE_DEVICE, iter);
}

static void append_path(gpointer key, gpointer value, gpointer user_data)
{
	struct connman_element *element = value;
	DBusMessageIter *iter = user_data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH,
							&element->path);
}

static void append_networks(DBusMessageIter *iter, void *user_data)
{
	struct connman_device *device = user_data;

	g_hash_table_foreach(device->networks, append_path, iter);
}

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_device *device = data;
	DBusMessage *reply;
	DBusMessageIter array, dict;
	const char *str;

	DBG("conn %p", conn);

	if (__connman_security_check_privilege(msg,
					CONNMAN_SECURITY_PRIVILEGE_PUBLIC) < 0)
		return __connman_error_permission_denied(msg);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &array);

	connman_dbus_dict_open(&array, &dict);

	if (device->name != NULL)
		connman_dbus_dict_append_basic(&dict, "Name",
					DBUS_TYPE_STRING, &device->name);

	str = type2string(device->type);
	if (str != NULL)
		connman_dbus_dict_append_basic(&dict, "Type",
						DBUS_TYPE_STRING, &str);

	if (device->address != NULL)
		connman_dbus_dict_append_basic(&dict, "Address",
					DBUS_TYPE_STRING, &device->address);

	if (device->interface != NULL)
		connman_dbus_dict_append_basic(&dict, "Interface",
					DBUS_TYPE_STRING, &device->interface);

	connman_dbus_dict_append_basic(&dict, "Powered",
					DBUS_TYPE_BOOLEAN, &device->powered);

	connman_dbus_dict_append_basic(&dict, "Blocked",
					DBUS_TYPE_BOOLEAN, &device->blocked);

	if (device->driver && device->driver->scan)
		connman_dbus_dict_append_basic(&dict, "Scanning",
					DBUS_TYPE_BOOLEAN, &device->scanning);

	switch (device->mode) {
	case CONNMAN_DEVICE_MODE_UNKNOWN:
		break;
	case CONNMAN_DEVICE_MODE_NETWORK_SINGLE:
	case CONNMAN_DEVICE_MODE_NETWORK_MULTIPLE:
		if (device->scan_interval > 0)
			connman_dbus_dict_append_basic(&dict, "ScanInterval",
				DBUS_TYPE_UINT16, &device->scan_interval);

		connman_dbus_dict_append_array(&dict, "Networks",
				DBUS_TYPE_OBJECT_PATH, append_networks, device);
		break;
	}

	connman_dbus_dict_close(&array, &dict);

	return reply;
}

static gboolean powered_timeout(gpointer user_data)
{
	struct connman_device *device = user_data;

	DBG("device %p", device);

	device->timeout = 0;

	if (device->pending != NULL) {
		DBusMessage *reply;

		reply = __connman_error_operation_timeout(device->pending);
		if (reply != NULL)
			g_dbus_send_message(connection, reply);

		dbus_message_unref(device->pending);
		device->pending = NULL;
	}

	return FALSE;
}

static DBusMessage *set_property(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_device *device = data;
	DBusMessageIter iter, value;
	const char *name;
	int type;

	DBG("conn %p", conn);

	if (dbus_message_iter_init(msg, &iter) == FALSE)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &name);
	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &value);

	if (__connman_security_check_privilege(msg,
					CONNMAN_SECURITY_PRIVILEGE_MODIFY) < 0)
		return __connman_error_permission_denied(msg);

	type = dbus_message_iter_get_arg_type(&value);

	if (g_str_equal(name, "Powered") == TRUE) {
		connman_bool_t powered;
		int err;

		if (type != DBUS_TYPE_BOOLEAN)
			return __connman_error_invalid_arguments(msg);

		dbus_message_iter_get_basic(&value, &powered);

		device->powered_persistent = powered;

		__connman_storage_save_device(device);

		if (device->powered == powered)
			return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);

		if (device->pending != NULL)
			return __connman_error_in_progress(msg);

		err = set_powered(device, powered);
		if (err < 0) {
			if (err != -EINPROGRESS)
				return __connman_error_failed(msg, -err);

			device->pending = dbus_message_ref(msg);

			device->timeout = g_timeout_add_seconds(15,
						powered_timeout, device);

			return NULL;
		}
	} else if (g_str_equal(name, "ScanInterval") == TRUE) {
		connman_uint16_t interval;

		switch (device->mode) {
		case CONNMAN_DEVICE_MODE_UNKNOWN:
		case CONNMAN_DEVICE_MODE_NETWORK_SINGLE:
		case CONNMAN_DEVICE_MODE_NETWORK_MULTIPLE:
			break;
		}

		if (type != DBUS_TYPE_UINT16)
			return __connman_error_invalid_arguments(msg);

		dbus_message_iter_get_basic(&value, &interval);

		if (device->scan_interval != interval) {
			device->scan_interval = interval;

			__connman_storage_save_device(device);

			reset_scan_trigger(device);
		}
	} else
		return __connman_error_invalid_property(msg);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *propose_scan(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_device *device = data;
	int err;

	DBG("conn %p", conn);

	switch (device->mode) {
	case CONNMAN_DEVICE_MODE_UNKNOWN:
		return __connman_error_not_supported(msg);
	case CONNMAN_DEVICE_MODE_NETWORK_SINGLE:
	case CONNMAN_DEVICE_MODE_NETWORK_MULTIPLE:
		break;
	}

	err = __connman_device_scan(device);
	if (err < 0)
		return __connman_error_failed(msg, -err);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static GDBusMethodTable device_methods[] = {
	{ "GetProperties", "",      "a{sv}", get_properties },
	{ "SetProperty",   "sv",    "",      set_property,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ "ProposeScan",   "",      "",      propose_scan   },
	{ },
};

static GDBusSignalTable device_signals[] = {
	{ "PropertyChanged", "sv" },
	{ },
};

static int register_interface(struct connman_element *element)
{
	struct connman_device *device = element->device;

	DBG("element %p name %s", element, element->name);

	if (g_dbus_register_interface(connection, element->path,
					CONNMAN_DEVICE_INTERFACE,
					device_methods, device_signals,
					NULL, device, NULL) == FALSE) {
		connman_error("Failed to register %s device", element->path);
		return -EIO;
	}

	device->registered = TRUE;

	return 0;
}

static void unregister_interface(struct connman_element *element)
{
	struct connman_device *device = element->device;

	DBG("element %p name %s", element, element->name);

	device->registered = FALSE;

	g_dbus_unregister_interface(connection, element->path,
						CONNMAN_DEVICE_INTERFACE);
}

static int setup_device(struct connman_device *device)
{
	int err;

	DBG("device %p", device);

	err = register_interface(&device->element);
	if (err < 0) {
		if (device->driver->remove)
			device->driver->remove(device);
		device->driver = NULL;
		return err;
	}

	__connman_technology_add_device(device);

	switch (device->mode) {
	case CONNMAN_DEVICE_MODE_UNKNOWN:
	case CONNMAN_DEVICE_MODE_NETWORK_SINGLE:
	case CONNMAN_DEVICE_MODE_NETWORK_MULTIPLE:
		break;
	}

	if (__connman_udev_get_blocked(device->phyindex) == TRUE)
		return 0;

	if (device->offlinemode == FALSE &&
				device->powered_persistent == TRUE)
		__connman_device_enable(device);

	return 0;
}

static void probe_driver(struct connman_element *element, gpointer user_data)
{
	struct connman_device_driver *driver = user_data;

	DBG("element %p name %s", element, element->name);

	if (element->device == NULL)
		return;

	if (element->device->driver != NULL)
		return;

	if (driver->type != element->device->type)
		return;

	if (driver->probe(element->device) < 0)
		return;

	element->device->driver = driver;

	setup_device(element->device);
}

static void remove_device(struct connman_device *device)
{
	int err;

	DBG("device %p", device);

	err = __connman_device_disable(device);
	if (err < 0 && err == -EINPROGRESS)
		__connman_technology_disable_device(device);

	switch (device->mode) {
	case CONNMAN_DEVICE_MODE_UNKNOWN:
	case CONNMAN_DEVICE_MODE_NETWORK_SINGLE:
	case CONNMAN_DEVICE_MODE_NETWORK_MULTIPLE:
		break;
	}

	__connman_technology_remove_device(device);

	unregister_interface(&device->element);

	if (device->driver->remove)
		device->driver->remove(device);

	device->driver = NULL;
}

static void remove_driver(struct connman_element *element, gpointer user_data)
{
	struct connman_device_driver *driver = user_data;

	DBG("element %p name %s", element, element->name);

	if (element->device == NULL)
		return;

	if (element->device->driver == driver)
		remove_device(element->device);
}

connman_bool_t __connman_device_has_driver(struct connman_device *device)
{
	if (device == NULL || device->driver == NULL)
		return FALSE;

	return device->registered;
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

	__connman_element_foreach(NULL, CONNMAN_ELEMENT_TYPE_DEVICE,
						probe_driver, driver);

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

	__connman_element_foreach(NULL, CONNMAN_ELEMENT_TYPE_DEVICE,
						remove_driver, driver);
}

static void unregister_network(gpointer data)
{
	struct connman_network *network = data;

	DBG("network %p", network);

	connman_element_unregister((struct connman_element *) network);

	__connman_network_set_device(network, NULL);

	connman_network_unref(network);
}

static void device_destruct(struct connman_element *element)
{
	struct connman_device *device = element->device;

	DBG("element %p name %s", element, element->name);

	if (device->timeout > 0) {
		g_source_remove(device->timeout);
		device->timeout = 0;
	}

	clear_scan_trigger(device);

	if (device->pending != NULL) {
		dbus_message_unref(device->pending);
		device->pending = NULL;
	}

	g_free(device->ident);
	g_free(device->node);
	g_free(device->name);
	g_free(device->address);
	g_free(device->control);
	g_free(device->interface);

	g_free(device->last_network);

	g_hash_table_destroy(device->networks);
	device->networks = NULL;
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
	const char *str;

	DBG("node %s type %d", node, type);

	device = g_try_new0(struct connman_device, 1);
	if (device == NULL)
		return NULL;

	DBG("device %p", device);

	__connman_element_initialize(&device->element);

	device->element.name = g_strdup(node);
	device->element.type = CONNMAN_ELEMENT_TYPE_DEVICE;

	device->element.device = device;
	device->element.destruct = device_destruct;

	str = type2string(type);
	if (str != NULL)
		connman_element_set_string(&device->element,
					CONNMAN_PROPERTY_ID_TYPE, str);

	device->element.ipv4.method = CONNMAN_IPCONFIG_METHOD_DHCP;

	device->type = type;
	device->name = g_strdup(type2description(device->type));
	device->mode = CONNMAN_DEVICE_MODE_UNKNOWN;

	device->powered_persistent = TRUE;

	device->phyindex = -1;

	switch (type) {
	case CONNMAN_DEVICE_TYPE_UNKNOWN:
	case CONNMAN_DEVICE_TYPE_VENDOR:
		device->scan_interval = 0;
		break;
	case CONNMAN_DEVICE_TYPE_ETHERNET:
	case CONNMAN_DEVICE_TYPE_WIFI:
		device->scan_interval = 300;
		break;
	case CONNMAN_DEVICE_TYPE_WIMAX:
		device->scan_interval = 0;
		break;
	case CONNMAN_DEVICE_TYPE_BLUETOOTH:
		device->scan_interval = 0;
		break;
	case CONNMAN_DEVICE_TYPE_GPS:
		device->scan_interval = 0;
		break;
	case CONNMAN_DEVICE_TYPE_CELLULAR:
		device->scan_interval = 0;
		break;
	}

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

const char *__connman_device_get_type(struct connman_device *device)
{
	return type2string(device->type);
}

/**
 * connman_device_get_type:
 * @device: device structure
 *
 * Get type of device
 */
enum connman_device_type connman_device_get_type(struct connman_device *device)
{
	return device->type;
}

/**
 * connman_device_get_name:
 * @device: device structure
 *
 * Get unique name of device
 */
const char *connman_device_get_name(struct connman_device *device)
{
	return device->element.name;
}

/**
 * connman_device_get_path:
 * @device: device structure
 *
 * Get path name of device
 */
const char *connman_device_get_path(struct connman_device *device)
{
	return device->element.path;
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

int __connman_device_get_phyindex(struct connman_device *device)
{
	return device->phyindex;
}

void __connman_device_set_phyindex(struct connman_device *device,
							int phyindex)
{
	device->phyindex = phyindex;
}

/**
 * connman_device_set_interface:
 * @device: device structure
 * @interface: interface name
 * @control: control interface
 *
 * Set interface name of device
 */
void connman_device_set_interface(struct connman_device *device,
				const char *interface, const char *control)
{
	g_free(device->element.devname);
	device->element.devname = g_strdup(interface);

	g_free(device->interface);
	device->interface = g_strdup(interface);

	g_free(device->control);
	device->control = g_strdup(control);

	if (device->name == NULL) {
		const char *str = type2description(device->type);
		if (str != NULL && device->interface != NULL)
			device->name = g_strdup_printf("%s (%s)", str,
							device->interface);
	}
}

const char *connman_device_get_control(struct connman_device *device)
{
	return device->control;
}

/**
 * connman_device_set_ident:
 * @device: device structure
 * @ident: unique identifier
 *
 * Set unique identifier of device
 */
void connman_device_set_ident(struct connman_device *device,
							const char *ident)
{
	g_free(device->ident);
	device->ident = g_strdup(ident);
}

const char *__connman_device_get_ident(struct connman_device *device)
{
	return device->ident;
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
 * connman_device_get_mode:
 * @device: device structure
 *
 * Get network mode of device
 */
enum connman_device_mode connman_device_get_mode(struct connman_device *device)
{
	return device->mode;
}

/**
 * connman_device_set_powered:
 * @device: device structure
 * @powered: powered state
 *
 * Change power state of device
 */
int connman_device_set_powered(struct connman_device *device,
						connman_bool_t powered)
{
	DBG("driver %p powered %d", device, powered);

	if (device->timeout > 0) {
		g_source_remove(device->timeout);
		device->timeout = 0;
	}

	if (device->pending != NULL) {
		g_dbus_send_reply(connection, device->pending,
							DBUS_TYPE_INVALID);

		dbus_message_unref(device->pending);
		device->pending = NULL;
	}

	if (device->powered == powered) {
		device->powered_pending = powered;
		return -EALREADY;
	}

	if (powered == TRUE)
		__connman_device_enable(device);
	else
		__connman_device_disable(device);

	device->powered = powered;
	device->powered_pending = powered;

	if (device->powered == TRUE)
		__connman_technology_enable_device(device);
	else
		__connman_technology_disable_device(device);

	if (device->offlinemode == TRUE && powered == TRUE) {
		powered_changed(device);
		return connman_device_set_powered(device, FALSE);
	}

	if (device->registered == FALSE)
		return 0;

	powered_changed(device);

	if (powered == FALSE)
		return 0;

	reset_scan_trigger(device);

	if (device->driver->scan)
		device->driver->scan(device);

	return 0;
}

int __connman_device_set_blocked(struct connman_device *device,
						connman_bool_t blocked)
{
	connman_bool_t powered;

	DBG("device %p blocked %d", device, blocked);

	device->blocked = blocked;

	blocked_changed(device);

	if (device->offlinemode == TRUE)
		return 0;

	connman_info("%s {rfkill} blocked %d", device->interface, blocked);

	if (blocked == FALSE)
		powered = device->powered_persistent;
	else
		powered = FALSE;

	return set_powered(device, powered);
}

connman_bool_t __connman_device_get_blocked(struct connman_device *device)
{
	return device->blocked;
}

int __connman_device_scan(struct connman_device *device)
{
	if (!device->driver || !device->driver->scan)
		return -EOPNOTSUPP;

	if (device->powered == FALSE)
		return -ENOLINK;

	reset_scan_trigger(device);

	return device->driver->scan(device);
}

int __connman_device_enable_persistent(struct connman_device *device)
{
	int err;

	DBG("device %p", device);

	device->powered_persistent = TRUE;

	__connman_storage_save_device(device);

	err = __connman_device_enable(device);
	if (err == 0 || err == -EINPROGRESS) {
		device->offlinemode = FALSE;
		if (__connman_profile_get_offlinemode() == TRUE) {
			__connman_profile_set_offlinemode(FALSE, FALSE);

			__connman_profile_save_default();
		}
	}

	return err;
}

int __connman_device_disable_persistent(struct connman_device *device)
{
	DBG("device %p", device);

	device->powered_persistent = FALSE;

	__connman_storage_save_device(device);

	return __connman_device_disable(device);
}

int __connman_device_disconnect(struct connman_device *device)
{
	GHashTableIter iter;
	gpointer key, value;

	DBG("device %p", device);

	connman_device_set_disconnected(device, TRUE);

	g_hash_table_iter_init(&iter, device->networks);

	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		struct connman_network *network = value;

		if (__connman_network_get_connecting(network) == TRUE) {
			/*
			 * Skip network in the process of connecting.
			 * This is a workaround for WiFi networks serviced
			 * by the supplicant plugin that hold a reference
			 * to the network.  If we disconnect the network
			 * here then the referenced object will not be
			 * registered and usage (like launching DHCP client)
			 * will fail.  There is nothing to be gained by
			 * removing the network here anyway.
			 */
			connman_warn("Skipping disconnect of %s",
				connman_network_get_identifier(network));
			continue;
		}

		__connman_network_disconnect(network);
	}

	return 0;
}

static void mark_network_unavailable(gpointer key, gpointer value,
							gpointer user_data)
{
	struct connman_network *network = value;

	if (connman_network_get_connected(network) == TRUE)
		return;

	connman_network_set_available(network, FALSE);
}

static gboolean remove_unavailable_network(gpointer key, gpointer value,
							gpointer user_data)
{
	struct connman_network *network = value;

	if (connman_network_get_connected(network) == TRUE)
		return FALSE;

	if (connman_network_get_available(network) == TRUE)
		return FALSE;

	return TRUE;
}

void __connman_device_cleanup_networks(struct connman_device *device)
{
	g_hash_table_foreach_remove(device->networks,
					remove_unavailable_network, NULL);
}

static void scanning_changed(struct connman_device *device)
{
	connman_dbus_property_changed_basic(device->element.path,
				CONNMAN_DEVICE_INTERFACE, "Scanning",
					DBUS_TYPE_BOOLEAN, &device->scanning);
}

/**
 * connman_device_set_scanning:
 * @device: device structure
 * @scanning: scanning state
 *
 * Change scanning state of device
 */
int connman_device_set_scanning(struct connman_device *device,
						connman_bool_t scanning)
{
	DBG("device %p scanning %d", device, scanning);

	if (!device->driver || !device->driver->scan)
		return -EINVAL;

	if (device->scanning == scanning)
		return -EALREADY;

	device->scanning = scanning;

	scanning_changed(device);

	if (scanning == TRUE) {
		reset_scan_trigger(device);

		g_hash_table_foreach(device->networks,
					mark_network_unavailable, NULL);

		return 0;
	}

	__connman_device_cleanup_networks(device);

	if (device->connections > 0)
		return 0;

	if (device->disconnected == TRUE)
		return 0;

	__connman_service_auto_connect();

	return 0;
}

/**
 * connman_device_set_disconnected:
 * @device: device structure
 * @disconnected: disconnected state
 *
 * Change disconnected state of device (only for device with networks)
 */
int connman_device_set_disconnected(struct connman_device *device,
						connman_bool_t disconnected)
{
	DBG("device %p disconnected %d", device, disconnected);

	switch (device->mode) {
	case CONNMAN_DEVICE_MODE_UNKNOWN:
		return -EINVAL;
	case CONNMAN_DEVICE_MODE_NETWORK_SINGLE:
	case CONNMAN_DEVICE_MODE_NETWORK_MULTIPLE:
		break;
	}

	if (device->disconnected == disconnected)
		return -EALREADY;

	device->disconnected = disconnected;

	if (disconnected == TRUE)
		force_scan_trigger(device);

	return 0;
}

/**
 * connman_device_get_disconnected:
 * @device: device structure
 *
 * Get device disconnected state
 */
connman_bool_t connman_device_get_disconnected(struct connman_device *device)
{
	return device->disconnected;
}

/**
 * connman_device_set_string:
 * @device: device structure
 * @key: unique identifier
 * @value: string value
 *
 * Set string value for specific key
 */
int connman_device_set_string(struct connman_device *device,
					const char *key, const char *value)
{
	DBG("device %p key %s value %s", device, key, value);

	if (g_str_equal(key, "Address") == TRUE) {
		g_free(device->address);
		device->address = g_strdup(value);
	} else if (g_str_equal(key, "Name") == TRUE) {
		g_free(device->name);
		device->name = g_strdup(value);
	} else if (g_str_equal(key, "Node") == TRUE) {
		g_free(device->node);
		device->node = g_strdup(value);
	}

	return connman_element_set_string(&device->element, key, value);
}

/**
 * connman_device_get_string:
 * @device: device structure
 * @key: unique identifier
 *
 * Get string value for specific key
 */
const char *connman_device_get_string(struct connman_device *device,
							const char *key)
{
	DBG("device %p key %s", device, key);

	if (g_str_equal(key, "Address") == TRUE)
		return device->address;
	else if (g_str_equal(key, "Name") == TRUE)
		return device->name;
	else if (g_str_equal(key, "Node") == TRUE)
		return device->node;

	return connman_element_get_string(&device->element, key);
}

static void set_offlinemode(struct connman_element *element, gpointer user_data)
{
	struct connman_device *device = element->device;
	connman_bool_t offlinemode = GPOINTER_TO_UINT(user_data);
	connman_bool_t powered;

	DBG("element %p name %s", element, element->name);

	if (device == NULL)
		return;

	device->offlinemode = offlinemode;

	if (device->blocked == TRUE)
		return;

	powered = (offlinemode == TRUE) ? FALSE : TRUE;

	if (device->powered == powered)
		return;

	if (device->powered_persistent == FALSE)
		powered = FALSE;

	set_powered(device, powered);
}

int __connman_device_set_offlinemode(connman_bool_t offlinemode)
{
	DBG("offlinmode %d", offlinemode);

	__connman_element_foreach(NULL, CONNMAN_ELEMENT_TYPE_DEVICE,
			set_offlinemode, GUINT_TO_POINTER(offlinemode));

	__connman_notifier_offlinemode(offlinemode);

	return 0;
}

void __connman_device_increase_connections(struct connman_device *device)
{
	device->connections++;
}

void __connman_device_decrease_connections(struct connman_device *device)
{
	device->connections--;
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

	if (identifier == NULL)
		return -EINVAL;

	switch (device->mode) {
	case CONNMAN_DEVICE_MODE_UNKNOWN:
		return -EINVAL;
	case CONNMAN_DEVICE_MODE_NETWORK_SINGLE:
	case CONNMAN_DEVICE_MODE_NETWORK_MULTIPLE:
		break;
	}

	__connman_network_set_device(network, device);

	err = connman_element_register((struct connman_element *) network,
							&device->element);
	if (err < 0) {
		__connman_network_set_device(network, NULL);
		return err;
	}

	g_hash_table_insert(device->networks, g_strdup(identifier),
								network);

	return 0;
}

/**
 * connman_device_get_network:
 * @device: device structure
 * @identifier: network identifier
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
 * @identifier: network identifier
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

void connman_device_remove_all_networks(struct connman_device *device)
{
	g_hash_table_remove_all(device->networks);
}

void __connman_device_set_network(struct connman_device *device,
					struct connman_network *network)
{
	const char *name;

	if (device == NULL)
		return;

	if (device->network == network)
		return;

	if (device->network != NULL)
		connman_network_unref(device->network);

	if (network != NULL) {
		name = connman_network_get_string(network,
						CONNMAN_PROPERTY_ID_NAME);
		g_free(device->last_network);
		device->last_network = g_strdup(name);

		device->network = connman_network_ref(network);
	} else {
		g_free(device->last_network);
		device->last_network = NULL;

		device->network = NULL;
	}
}

void __connman_device_set_reconnect(struct connman_device *device,
						connman_bool_t reconnect)
{
	device->reconnect = reconnect;
}

connman_bool_t  __connman_device_get_reconnect(
				struct connman_device *device)
{
	return device->reconnect;
}

/**
 * connman_device_register:
 * @device: device structure
 *
 * Register device with the system
 */
int connman_device_register(struct connman_device *device)
{
	__connman_storage_load_device(device);

	device->offlinemode = __connman_profile_get_offlinemode();

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
	__connman_storage_save_device(device);

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

	DBG("element %p name %s", element, element->name);

	if (device == NULL)
		return -ENODEV;

	if (device->driver != NULL)
		return -EALREADY;

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

	if (device->driver == NULL)
		return -ENODEV;

	return setup_device(device);
}

static void device_remove(struct connman_element *element)
{
	struct connman_device *device = element->device;

	DBG("element %p name %s", element, element->name);

	if (device == NULL)
		return;

	if (device->driver == NULL)
		return;

	remove_device(device);
}

static struct connman_driver device_driver = {
	.name		= "device",
	.type		= CONNMAN_ELEMENT_TYPE_DEVICE,
	.priority	= CONNMAN_DRIVER_PRIORITY_LOW,
	.probe		= device_probe,
	.remove		= device_remove,
};

static int device_load(struct connman_device *device)
{
	const char *ident = __connman_profile_active_ident();
	GKeyFile *keyfile;
	GError *error = NULL;
	gchar *identifier;
	connman_bool_t powered;
	int val;

	DBG("device %p", device);

	keyfile = __connman_storage_open_profile(ident);
	if (keyfile == NULL)
		return 0;

	identifier = g_strdup_printf("device_%s", device->element.name);
	if (identifier == NULL)
		goto done;

	powered = g_key_file_get_boolean(keyfile, identifier,
						"Powered", &error);
	if (error == NULL)
		device->powered_persistent = powered;
	g_clear_error(&error);

	switch (device->mode) {
	case CONNMAN_DEVICE_MODE_UNKNOWN:
		break;
	case CONNMAN_DEVICE_MODE_NETWORK_SINGLE:
	case CONNMAN_DEVICE_MODE_NETWORK_MULTIPLE:
		val = g_key_file_get_integer(keyfile, identifier,
						"ScanInterval", &error);
		if (error == NULL && val > 0)
			device->scan_interval = val;
		g_clear_error(&error);
		break;
	}

done:
	g_free(identifier);

	__connman_storage_close_profile(ident, keyfile, FALSE);

	return 0;
}

static int device_save(struct connman_device *device)
{
	const char *ident = __connman_profile_active_ident();
	GKeyFile *keyfile;
	gchar *identifier;

	DBG("device %p", device);

	keyfile = __connman_storage_open_profile(ident);
	if (keyfile == NULL)
		return 0;

	identifier = g_strdup_printf("device_%s", device->element.name);
	if (identifier == NULL)
		goto done;

	g_key_file_set_boolean(keyfile, identifier,
					"Powered", device->powered_persistent);

	switch (device->mode) {
	case CONNMAN_DEVICE_MODE_UNKNOWN:
		break;
	case CONNMAN_DEVICE_MODE_NETWORK_SINGLE:
	case CONNMAN_DEVICE_MODE_NETWORK_MULTIPLE:
		if (device->scan_interval > 0)
			g_key_file_set_integer(keyfile, identifier,
					"ScanInterval", device->scan_interval);
		break;
	}

done:
	g_free(identifier);

	__connman_storage_close_profile(ident, keyfile, TRUE);

	return 0;
}

static struct connman_storage device_storage = {
	.name		= "device",
	.priority	= CONNMAN_STORAGE_PRIORITY_LOW,
	.device_load	= device_load,
	.device_save	= device_save,
};

int __connman_device_init(void)
{
	DBG("");

	connection = connman_dbus_get_connection();

	if (connman_storage_register(&device_storage) < 0)
		connman_error("Failed to register device storage");

	return connman_driver_register(&device_driver);
}

void __connman_device_cleanup(void)
{
	DBG("");

	connman_driver_unregister(&device_driver);

	connman_storage_unregister(&device_storage);

	dbus_connection_unref(connection);
}
