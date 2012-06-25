/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2012  Intel Corporation. All rights reserved.
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

#include "connman.h"

static GSList *device_list = NULL;
static gchar **device_filter = NULL;
static gchar **nodevice_filter = NULL;

enum connman_pending_type {
	PENDING_NONE	= 0,
	PENDING_ENABLE	= 1,
	PENDING_DISABLE = 2,
};

struct connman_device {
	int refcount;
	enum connman_device_type type;
	enum connman_pending_type powered_pending;	/* Indicates a pending
							enable/disable request */
	connman_bool_t powered;
	connman_bool_t scanning;
	connman_bool_t disconnected;
	connman_bool_t reconnect;
	char *name;
	char *node;
	char *address;
	char *interface;
	char *ident;
	char *path;
	char *devname;
	int phyindex;
	int index;
	guint pending_timeout;

	struct connman_device_driver *driver;
	void *driver_data;

	char *last_network;
	struct connman_network *network;
	GHashTable *networks;
};

static void clear_pending_trigger(struct connman_device *device)
{
	if (device->pending_timeout > 0) {
		g_source_remove(device->pending_timeout);
		device->pending_timeout = 0;
	}
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
	case CONNMAN_DEVICE_TYPE_GADGET:
		return "Gadget";

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
	case CONNMAN_DEVICE_TYPE_GADGET:
		return "gadget";

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
	case CONNMAN_DEVICE_TYPE_GADGET:
		return CONNMAN_SERVICE_TYPE_GADGET;

	}

	return CONNMAN_SERVICE_TYPE_UNKNOWN;
}

static gboolean device_pending_reset(gpointer user_data)
{
	struct connman_device *device = user_data;

	DBG("device %p", device);

	/* Power request timedout, reset power pending state. */
	device->pending_timeout = 0;
	device->powered_pending = PENDING_NONE;

	return FALSE;
}

int __connman_device_enable(struct connman_device *device)
{
	int err;

	DBG("device %p", device);

	if (!device->driver || !device->driver->enable)
		return -EOPNOTSUPP;

	/* There is an ongoing power disable request. */
	if (device->powered_pending == PENDING_DISABLE)
		return -EBUSY;

	if (device->powered_pending == PENDING_ENABLE)
		return -EALREADY;

	if (device->powered_pending == PENDING_NONE && device->powered == TRUE)
		return -EALREADY;

	device->powered_pending = PENDING_ENABLE;

	err = device->driver->enable(device);
	/*
	 * device gets enabled right away.
	 * Invoke the callback
	 */
	if (err == 0) {
		connman_device_set_powered(device, TRUE);
		goto done;
	}

	if (err == -EALREADY) {
		/* If device is already powered, but connman is not updated */
		connman_device_set_powered(device, TRUE);
		goto done;
	}
	/*
	 * if err == -EINPROGRESS, then the DBus call to the respective daemon
	 * was successful. We set a 4 sec timeout so if the daemon never
	 * returns a reply, we would reset the pending request.
	 */
	if (err == -EINPROGRESS)
		device->pending_timeout = g_timeout_add_seconds(4,
					device_pending_reset, device);
done:
	return err;
}

int __connman_device_disable(struct connman_device *device)
{
	int err;

	DBG("device %p", device);

	if (!device->driver || !device->driver->disable)
		return -EOPNOTSUPP;

	/* Ongoing power enable request */
	if (device->powered_pending == PENDING_ENABLE)
		return -EBUSY;

	if (device->powered_pending == PENDING_DISABLE)
		return -EALREADY;

	if (device->powered_pending == PENDING_NONE && device->powered == FALSE)
		return -EALREADY;

	device->powered_pending = PENDING_DISABLE;
	device->reconnect = FALSE;

	if (device->network) {
		struct connman_service *service =
			__connman_service_lookup_from_network(device->network);

		if (service != NULL)
			__connman_service_disconnect(service);
		else
			connman_network_set_connected(device->network, FALSE);
	}

	err = device->driver->disable(device);
	if (err == 0 || err == -EALREADY) {
		connman_device_set_powered(device, FALSE);
		goto done;
	}

	if (err == -EINPROGRESS)
		device->pending_timeout = g_timeout_add_seconds(4,
					device_pending_reset, device);
done:
	return err;
}

static void probe_driver(struct connman_device_driver *driver)
{
	GSList *list;

	DBG("driver %p name %s", driver, driver->name);

	for (list = device_list; list != NULL; list = list->next) {
		struct connman_device *device = list->data;

		if (device->driver != NULL)
			continue;

		if (driver->type != device->type)
			continue;

		if (driver->probe(device) < 0)
			continue;

		device->driver = driver;

		__connman_technology_add_device(device);
	}
}

static void remove_device(struct connman_device *device)
{
	DBG("device %p", device);

	__connman_device_disable(device);

	__connman_technology_remove_device(device);

	if (device->driver->remove)
		device->driver->remove(device);

	device->driver = NULL;
}

static void remove_driver(struct connman_device_driver *driver)
{
	GSList *list;

	DBG("driver %p name %s", driver, driver->name);

	for (list = device_list; list != NULL; list = list->next) {
		struct connman_device *device = list->data;

		if (device->driver == driver)
			remove_device(device);
	}
}

connman_bool_t __connman_device_has_driver(struct connman_device *device)
{
	if (device == NULL || device->driver == NULL)
		return FALSE;

	return TRUE;
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
	probe_driver(driver);

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

	remove_driver(driver);
}

static void free_network(gpointer data)
{
	struct connman_network *network = data;

	DBG("network %p", network);

	__connman_network_set_device(network, NULL);

	connman_network_unref(network);
}

static void device_destruct(struct connman_device *device)
{
	DBG("device %p name %s", device, device->name);

	clear_pending_trigger(device);

	g_free(device->ident);
	g_free(device->node);
	g_free(device->name);
	g_free(device->address);
	g_free(device->interface);
	g_free(device->path);
	g_free(device->devname);

	g_free(device->last_network);

	g_hash_table_destroy(device->networks);
	device->networks = NULL;

	g_free(device);
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

	device->refcount = 1;

	device->type = type;
	device->name = g_strdup(type2description(device->type));

	device->phyindex = -1;

	device->networks = g_hash_table_new_full(g_str_hash, g_str_equal,
						g_free, free_network);

	device_list = g_slist_append(device_list, device);

	return device;
}

/**
 * connman_device_ref:
 * @device: device structure
 *
 * Increase reference counter of device
 */
struct connman_device *connman_device_ref_debug(struct connman_device *device,
				const char *file, int line, const char *caller)
{
	DBG("%p ref %d by %s:%d:%s()", device, device->refcount + 1,
		file, line, caller);

	__sync_fetch_and_add(&device->refcount, 1);

	return device;
}

/**
 * connman_device_unref:
 * @device: device structure
 *
 * Decrease reference counter of device
 */
void connman_device_unref_debug(struct connman_device *device,
				const char *file, int line, const char *caller)
{
	DBG("%p ref %d by %s:%d:%s()", device, device->refcount - 1,
		file, line, caller);

	if (__sync_fetch_and_sub(&device->refcount, 1) != 1)
		return;

	if (device->driver) {
		device->driver->remove(device);
		device->driver = NULL;
	}

	device_list = g_slist_remove(device_list, device);

	device_destruct(device);
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
 * connman_device_set_index:
 * @device: device structure
 * @index: index number
 *
 * Set index number of device
 */
void connman_device_set_index(struct connman_device *device, int index)
{
	device->index = index;
}

/**
 * connman_device_get_index:
 * @device: device structure
 *
 * Get index number of device
 */
int connman_device_get_index(struct connman_device *device)
{
	return device->index;
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
 *
 * Set interface name of device
 */
void connman_device_set_interface(struct connman_device *device,
						const char *interface)
{
	g_free(device->devname);
	device->devname = g_strdup(interface);

	g_free(device->interface);
	device->interface = g_strdup(interface);

	if (device->name == NULL) {
		const char *str = type2description(device->type);
		if (str != NULL && device->interface != NULL)
			device->name = g_strdup_printf("%s (%s)", str,
							device->interface);
	}
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

const char *connman_device_get_ident(struct connman_device *device)
{
	return device->ident;
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
	enum connman_service_type type;

	DBG("driver %p powered %d", device, powered);

	if (device->powered == powered)
		return -EALREADY;

	clear_pending_trigger(device);

	device->powered_pending = PENDING_NONE;

	device->powered = powered;

	type = __connman_device_get_service_type(device);

	if (device->powered == FALSE) {
		__connman_technology_disabled(type);
		return 0;
	}

	__connman_technology_enabled(type);

	connman_device_set_disconnected(device, FALSE);
	device->scanning = FALSE;

	if (device->driver && device->driver->scan_fast)
		device->driver->scan_fast(device);
	else if (device->driver && device->driver->scan)
		device->driver->scan(device);

	return 0;
}

static int device_scan(struct connman_device *device)
{
	if (!device->driver || !device->driver->scan)
		return -EOPNOTSUPP;

	if (device->powered == FALSE)
		return -ENOLINK;

	return device->driver->scan(device);
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

		if (connman_network_get_connecting(network) == TRUE) {
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
			connman_warn("Skipping disconnect of %s, network is connecting.",
				connman_network_get_identifier(network));
			continue;
		}

		__connman_network_disconnect(network);
	}

	return 0;
}

static void mark_network_available(gpointer key, gpointer value,
							gpointer user_data)
{
	struct connman_network *network = value;

	connman_network_set_available(network, TRUE);
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

connman_bool_t connman_device_get_scanning(struct connman_device *device)
{
	return device->scanning;
}

void connman_device_reset_scanning(struct connman_device *device)
{
	g_hash_table_foreach(device->networks,
				mark_network_available, NULL);
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

	if (scanning == TRUE) {
		__connman_technology_scan_started(device);

		g_hash_table_foreach(device->networks,
					mark_network_unavailable, NULL);

		return 0;
	}

	__connman_device_cleanup_networks(device);

	__connman_technology_scan_stopped(device);

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

	if (device->disconnected == disconnected)
		return -EALREADY;

	device->disconnected = disconnected;

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
	} else if (g_str_equal(key, "Path") == TRUE) {
		g_free(device->path);
		device->path = g_strdup(value);
	} else {
		return -EINVAL;
	}

	return 0;
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
	else if (g_str_equal(key, "Interface") == TRUE)
		return device->interface;
	else if (g_str_equal(key, "Path") == TRUE)
		return device->path;

	return NULL;
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

	DBG("device %p network %p", device, network);

	if (identifier == NULL)
		return -EINVAL;

	connman_network_ref(network);

	__connman_network_set_device(network, device);

	g_hash_table_replace(device->networks, g_strdup(identifier),
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
						struct connman_network *network)
{
	const char *identifier;

	DBG("device %p network %p", device, network);

	if (network == NULL)
		return 0;

	identifier = connman_network_get_identifier(network);
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

	if (network != NULL) {
		name = connman_network_get_string(network, "Name");
		g_free(device->last_network);
		device->last_network = g_strdup(name);

		device->network = network;
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

static gboolean match_driver(struct connman_device *device,
					struct connman_device_driver *driver)
{
	if (device->type == driver->type ||
			driver->type == CONNMAN_DEVICE_TYPE_UNKNOWN)
		return TRUE;

	return FALSE;
}

/**
 * connman_device_register:
 * @device: device structure
 *
 * Register device with the system
 */
int connman_device_register(struct connman_device *device)
{
	GSList *list;

	DBG("device %p name %s", device, device->name);

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
		return 0;

	return __connman_technology_add_device(device);
}

/**
 * connman_device_unregister:
 * @device: device structure
 *
 * Unregister device with the system
 */
void connman_device_unregister(struct connman_device *device)
{
	DBG("device %p name %s", device, device->name);

	if (device->driver == NULL)
		return;

	remove_device(device);
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

struct connman_device *__connman_device_find_device(
				enum connman_service_type type)
{
	GSList *list;

	for (list = device_list; list != NULL; list = list->next) {
		struct connman_device *device = list->data;
		enum connman_service_type service_type =
			__connman_device_get_service_type(device);

		if (service_type != type)
			continue;

		return device;
	}

	return NULL;
}

int __connman_device_request_scan(enum connman_service_type type)
{
	connman_bool_t success = FALSE;
	int last_err = -ENOSYS;
	GSList *list;
	int err;

	switch (type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_ETHERNET:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_VPN:
	case CONNMAN_SERVICE_TYPE_GADGET:
		return -EOPNOTSUPP;
	case CONNMAN_SERVICE_TYPE_WIFI:
	case CONNMAN_SERVICE_TYPE_WIMAX:
		break;
	}

	for (list = device_list; list != NULL; list = list->next) {
		struct connman_device *device = list->data;
		enum connman_service_type service_type =
			__connman_device_get_service_type(device);

		if (service_type != CONNMAN_SERVICE_TYPE_UNKNOWN &&
				service_type != type) {
			continue;
		}

		err = device_scan(device);
		if (err == 0 || err == -EALREADY || err == -EINPROGRESS) {
			success = TRUE;
		} else {
			last_err = err;
			DBG("device %p err %d", device, err);
		}
	}

	if (success == TRUE)
		return 0;

	return last_err;
}

int __connman_device_request_hidden_scan(struct connman_device *device,
				const char *ssid, unsigned int ssid_len,
				const char *identity, const char *passphrase,
				void *user_data)
{
	DBG("device %p", device);

	if (device == NULL || device->driver == NULL ||
			device->driver->scan_hidden == NULL)
		return -EINVAL;

	if (device->scanning == TRUE)
		return -EALREADY;

	return device->driver->scan_hidden(device, ssid, ssid_len,
					identity, passphrase, user_data);
}

connman_bool_t __connman_device_isfiltered(const char *devname)
{
	char **pattern;
	char **blacklisted_interfaces;

	if (device_filter == NULL)
		goto nodevice;

	for (pattern = device_filter; *pattern; pattern++) {
		if (g_pattern_match_simple(*pattern, devname) == FALSE) {
			DBG("ignoring device %s (match)", devname);
			return TRUE;
		}
	}

nodevice:
	if (g_pattern_match_simple("dummy*", devname) == TRUE) {
		DBG("ignoring dummy networking devices");
		return TRUE;
	}

	if (nodevice_filter == NULL)
		goto list;

	for (pattern = nodevice_filter; *pattern; pattern++) {
		if (g_pattern_match_simple(*pattern, devname) == TRUE) {
			DBG("ignoring device %s (no match)", devname);
			return TRUE;
		}
	}

list:
	blacklisted_interfaces =
		connman_setting_get_string_list("NetworkInterfaceBlacklist");
	if (blacklisted_interfaces == NULL)
		return FALSE;

	for (pattern = blacklisted_interfaces; *pattern; pattern++) {
		if (g_str_has_prefix(devname, *pattern) == TRUE) {
			DBG("ignoring device %s (blacklist)", devname);
			return TRUE;
		}
	}

	return FALSE;
}

int __connman_device_init(const char *device, const char *nodevice)
{
	DBG("");

	if (device != NULL)
		device_filter = g_strsplit(device, ",", -1);

	if (nodevice != NULL)
		nodevice_filter = g_strsplit(nodevice, ",", -1);

	return 0;
}

void __connman_device_cleanup(void)
{
	DBG("");

	g_strfreev(nodevice_filter);
	g_strfreev(device_filter);
}
