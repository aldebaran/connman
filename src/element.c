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
#include <stdarg.h>
#include <string.h>

#include <glib.h>
#include <gdbus.h>

#include "connman.h"

static DBusConnection *connection;

static GNode *element_root = NULL;
static GSList *driver_list = NULL;
static gchar **device_filter = NULL;
static gchar **nodevice_filter = NULL;

static gboolean started = FALSE;

static const char *type2string(enum connman_element_type type)
{
	switch (type) {
	case CONNMAN_ELEMENT_TYPE_UNKNOWN:
		return "unknown";
	case CONNMAN_ELEMENT_TYPE_ROOT:
		return "root";
	case CONNMAN_ELEMENT_TYPE_PROFILE:
		return "profile";
	case CONNMAN_ELEMENT_TYPE_DEVICE:
		return "device";
	case CONNMAN_ELEMENT_TYPE_NETWORK:
		return "network";
	case CONNMAN_ELEMENT_TYPE_SERVICE:
		return "service";
	case CONNMAN_ELEMENT_TYPE_BOOTP:
		return "bootp";
	case CONNMAN_ELEMENT_TYPE_ZEROCONF:
		return "zeroconf";
	case CONNMAN_ELEMENT_TYPE_VENDOR:
		return "vendor";
	}

	return NULL;
}

struct foreach_data {
	enum connman_element_type type;
	element_cb_t callback;
	gpointer user_data;
};

static gboolean foreach_callback(GNode *node, gpointer user_data)
{
	struct connman_element *element = node->data;
	struct foreach_data *data = user_data;

	DBG("element %p name %s", element, element->name);

	if (element->type == CONNMAN_ELEMENT_TYPE_ROOT)
		return FALSE;

	if (data->type != CONNMAN_ELEMENT_TYPE_UNKNOWN &&
					data->type != element->type)
		return FALSE;

	if (data->callback)
		data->callback(element, data->user_data);

	return FALSE;
}

void __connman_element_foreach(struct connman_element *element,
				enum connman_element_type type,
				element_cb_t callback, gpointer user_data)
{
	struct foreach_data data = { type, callback, user_data };
	GNode *node;

	DBG("");

	if (element != NULL) {
		node = g_node_find(element_root, G_PRE_ORDER,
						G_TRAVERSE_ALL, element);
		if (node == NULL)
			return;
	} else
		node = element_root;

	g_node_traverse(node, G_PRE_ORDER, G_TRAVERSE_ALL, -1,
						foreach_callback, &data);
}

struct append_filter {
	enum connman_element_type type;
	DBusMessageIter *iter;
};

static gboolean append_path(GNode *node, gpointer user_data)
{
	struct connman_element *element = node->data;
	struct append_filter *filter = user_data;

	DBG("element %p name %s", element, element->name);

	if (element->type == CONNMAN_ELEMENT_TYPE_ROOT)
		return FALSE;

	if (filter->type != CONNMAN_ELEMENT_TYPE_UNKNOWN &&
					filter->type != element->type)
		return FALSE;

	if (filter->type == CONNMAN_ELEMENT_TYPE_DEVICE &&
			__connman_device_has_driver(element->device) == FALSE)
		return FALSE;

	if (filter->type == CONNMAN_ELEMENT_TYPE_NETWORK &&
			__connman_network_has_driver(element->network) == FALSE)
		return FALSE;

	dbus_message_iter_append_basic(filter->iter,
				DBUS_TYPE_OBJECT_PATH, &element->path);

	return FALSE;
}

void __connman_element_list(struct connman_element *element,
					enum connman_element_type type,
							DBusMessageIter *iter)
{
	struct append_filter filter = { type, iter };
	GNode *node;

	DBG("");

	if (element != NULL) {
		node = g_node_find(element_root, G_PRE_ORDER,
						G_TRAVERSE_ALL, element);
		if (node == NULL)
			return;
	} else
		node = element_root;

	g_node_traverse(node, G_PRE_ORDER, G_TRAVERSE_ALL, -1,
						append_path, &filter);
}

static struct connman_network *get_network(struct connman_element *element)
{
	if (element->type == CONNMAN_ELEMENT_TYPE_NETWORK &&
						element->network != NULL)
		return element->network;

	if (element->parent == NULL)
		return NULL;

	return get_network(element->parent);
}

struct connman_service *__connman_element_get_service(struct connman_element *element)
{
	struct connman_service *service = NULL;
	struct connman_network *network;
	struct connman_device *device;
	enum connman_device_type type;

	device = __connman_element_get_device(element);
	if (device == NULL) {
		/* Workaround for the connection removal. */
		service = __connman_service_lookup_from_index(element->index);
		return service;
	}

	type = connman_device_get_type(device);

	switch (type) {
	case CONNMAN_DEVICE_TYPE_UNKNOWN:
	case CONNMAN_DEVICE_TYPE_VENDOR:
	case CONNMAN_DEVICE_TYPE_GPS:
	case CONNMAN_DEVICE_TYPE_GADGET:
		break;
	case CONNMAN_DEVICE_TYPE_ETHERNET:
	case CONNMAN_DEVICE_TYPE_WIFI:
	case CONNMAN_DEVICE_TYPE_WIMAX:
	case CONNMAN_DEVICE_TYPE_BLUETOOTH:
	case CONNMAN_DEVICE_TYPE_CELLULAR:
		network = get_network(element);
		if (network == NULL)
			return NULL;
		service = __connman_service_lookup_from_network(network);
		break;
	}

	return service;
}

struct connman_device *__connman_element_get_device(struct connman_element *element)
{
	if (element->type == CONNMAN_ELEMENT_TYPE_DEVICE &&
						element->device != NULL)
		return element->device;

	if (element->parent == NULL)
		return NULL;

	return __connman_element_get_device(element->parent);
}

struct find_data {
	enum connman_service_type type;
	struct connman_device *device;
	connman_bool_t error;
};

static gboolean find_device(GNode *node, gpointer user_data)
{
	struct connman_element *element = node->data;
	struct find_data *data = user_data;

	if (element->type != CONNMAN_ELEMENT_TYPE_DEVICE)
		return FALSE;

	if (element->device == NULL)
		return FALSE;

	if (data->type != __connman_device_get_service_type(element->device))
		return FALSE;

	data->device = element->device;

	return TRUE;
}

struct connman_device *__connman_element_find_device(enum connman_service_type type)
{
	struct find_data data = { .type = type, .device = NULL };

	g_node_traverse(element_root, G_PRE_ORDER,
				G_TRAVERSE_ALL, -1, find_device, &data);

	return data.device;
}

static gboolean request_scan(GNode *node, gpointer user_data)
{
	struct connman_element *element = node->data;
	struct find_data *data = user_data;
	enum connman_service_type type;

	if (element->type != CONNMAN_ELEMENT_TYPE_DEVICE)
		return FALSE;

	if (element->device == NULL)
		return FALSE;

	type = __connman_device_get_service_type(element->device);

	switch (type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_ETHERNET:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_VPN:
	case CONNMAN_SERVICE_TYPE_GADGET:
		return FALSE;
	case CONNMAN_SERVICE_TYPE_WIFI:
	case CONNMAN_SERVICE_TYPE_WIMAX:
		if (data->type != CONNMAN_SERVICE_TYPE_UNKNOWN &&
							data->type != type)
			return FALSE;
		break;
	}

	__connman_device_scan(element->device);

	return FALSE;
}

int __connman_element_request_scan(enum connman_service_type type)
{
	struct find_data data = { .type = type, .device = NULL };

	g_node_traverse(element_root, G_PRE_ORDER,
				G_TRAVERSE_ALL, -1, request_scan, &data);

	return 0;
}

static gboolean enable_technology(GNode *node, gpointer user_data)
{
	struct connman_element *element = node->data;
	struct find_data *data = user_data;
	enum connman_service_type type;
	int err;

	if (element->type != CONNMAN_ELEMENT_TYPE_DEVICE)
		return FALSE;

	if (element->device == NULL)
		return FALSE;

	type = __connman_device_get_service_type(element->device);

	switch (type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_VPN:
	case CONNMAN_SERVICE_TYPE_GADGET:
		return FALSE;
	case CONNMAN_SERVICE_TYPE_ETHERNET:
	case CONNMAN_SERVICE_TYPE_WIFI:
	case CONNMAN_SERVICE_TYPE_WIMAX:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		if (data->type != CONNMAN_SERVICE_TYPE_UNKNOWN &&
							data->type != type)
			return FALSE;
		break;
	}

	err = __connman_device_enable_persistent(element->device);
	if (err == 0 || (err < 0 && err == -EINPROGRESS))
		data->error = FALSE;

	return FALSE;
}

int __connman_element_enable_technology(enum connman_service_type type)
{
	struct find_data data = { .type = type, .device = NULL, .error = TRUE };

	g_node_traverse(element_root, G_PRE_ORDER,
				G_TRAVERSE_ALL, -1, enable_technology, &data);

	if (data.error == TRUE)
		return -ENODEV;

	return 0;
}

static gboolean disable_technology(GNode *node, gpointer user_data)
{
	struct connman_element *element = node->data;
	struct find_data *data = user_data;
	enum connman_service_type type;
	int err;

	if (element->type != CONNMAN_ELEMENT_TYPE_DEVICE)
		return FALSE;

	if (element->device == NULL)
		return FALSE;

	type = __connman_device_get_service_type(element->device);

	switch (type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_VPN:
	case CONNMAN_SERVICE_TYPE_GADGET:
		return FALSE;
	case CONNMAN_SERVICE_TYPE_ETHERNET:
	case CONNMAN_SERVICE_TYPE_WIFI:
	case CONNMAN_SERVICE_TYPE_WIMAX:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		if (data->type != CONNMAN_SERVICE_TYPE_UNKNOWN &&
							data->type != type)
			return FALSE;
		break;
	}

	err = __connman_device_disable_persistent(element->device);
	if (err == 0 || (err < 0 && err == -EINPROGRESS))
		data->error = FALSE;

	return FALSE;
}

int __connman_element_disable_technology(enum connman_service_type type)
{
	struct find_data data = { .type = type, .device = NULL, .error = TRUE };

	g_node_traverse(element_root, G_PRE_ORDER,
				G_TRAVERSE_ALL, -1, disable_technology, &data);

	if (data.error == TRUE)
		return -ENODEV;

	return 0;
}

static gint compare_priority(gconstpointer a, gconstpointer b)
{
	const struct connman_driver *driver1 = a;
	const struct connman_driver *driver2 = b;

	return driver2->priority - driver1->priority;
}

static gboolean match_driver(struct connman_element *element,
					struct connman_driver *driver)
{
	if (element->type == CONNMAN_ELEMENT_TYPE_ROOT)
		return FALSE;

	if (element->type == driver->type ||
			driver->type == CONNMAN_ELEMENT_TYPE_UNKNOWN)
		return TRUE;

	return FALSE;
}

static gboolean probe_driver(GNode *node, gpointer data)
{
	struct connman_element *element = node->data;
	struct connman_driver *driver = data;

	DBG("element %p name %s", element, element->name);

	if (!element->driver && match_driver(element, driver) == TRUE) {
		if (driver->probe(element) < 0)
			return FALSE;

		element->driver = driver;
	}

	return FALSE;
}

void __connman_driver_rescan(struct connman_driver *driver)
{
	DBG("driver %p name %s", driver, driver->name);

	if (!driver->probe)
		return;

	if (element_root != NULL)
		g_node_traverse(element_root, G_PRE_ORDER,
				G_TRAVERSE_ALL, -1, probe_driver, driver);
}

/**
 * connman_driver_register:
 * @driver: driver definition
 *
 * Register a new driver
 *
 * Returns: %0 on success
 */
int connman_driver_register(struct connman_driver *driver)
{
	DBG("driver %p name %s", driver, driver->name);

	if (driver->type == CONNMAN_ELEMENT_TYPE_ROOT)
		return -EINVAL;

	if (!driver->probe)
		return -EINVAL;

	driver_list = g_slist_insert_sorted(driver_list, driver,
							compare_priority);

	if (started == FALSE)
		return 0;

	if (element_root != NULL)
		g_node_traverse(element_root, G_PRE_ORDER,
				G_TRAVERSE_ALL, -1, probe_driver, driver);

	return 0;
}

static gboolean remove_driver(GNode *node, gpointer data)
{
	struct connman_element *element = node->data;
	struct connman_driver *driver = data;

	DBG("element %p name %s", element, element->name);

	if (element->driver == driver) {
		if (driver->remove)
			driver->remove(element);

		element->driver = NULL;
	}

	return FALSE;
}

/**
 * connman_driver_unregister:
 * @driver: driver definition
 *
 * Remove a previously registered driver
 */
void connman_driver_unregister(struct connman_driver *driver)
{
	DBG("driver %p name %s", driver, driver->name);

	driver_list = g_slist_remove(driver_list, driver);

	if (element_root != NULL)
		g_node_traverse(element_root, G_POST_ORDER,
				G_TRAVERSE_ALL, -1, remove_driver, driver);
}

static void unregister_property(gpointer data)
{
	struct connman_property *property = data;

	DBG("property %p", property);

	g_free(property->value);
	g_free(property);
}

static void unregister_child(gpointer data)
{
	struct connman_element *element = data;

	DBG("element %p", element);

	connman_element_unref(element);
}

void __connman_element_initialize(struct connman_element *element)
{
	DBG("element %p", element);

	element->refcount = 1;

	element->name    = NULL;
	element->type    = CONNMAN_ELEMENT_TYPE_UNKNOWN;
	element->state   = CONNMAN_ELEMENT_STATE_UNKNOWN;
	element->error   = CONNMAN_ELEMENT_ERROR_UNKNOWN;
	element->index   = -1;
	element->enabled = FALSE;

	element->children = g_hash_table_new_full(g_str_hash, g_str_equal,
						NULL, unregister_child);

	element->properties = g_hash_table_new_full(g_str_hash, g_str_equal,
						g_free, unregister_property);
}

/**
 * connman_element_create:
 * @name: element name
 *
 * Allocate a new element and assign the given #name to it. If the name
 * is #NULL, it will be later on created based on the element type.
 *
 * Returns: a newly-allocated #connman_element structure
 */
struct connman_element *connman_element_create(const char *name)
{
	struct connman_element *element;

	element = g_try_new0(struct connman_element, 1);
	if (element == NULL)
		return NULL;

	DBG("element %p", element);

	__connman_element_initialize(element);

	element->name = g_strdup(name);

	return element;
}

struct connman_element *connman_element_ref(struct connman_element *element)
{
	DBG("element %p name %s refcount %d", element, element->name,
				g_atomic_int_get(&element->refcount) + 1);

	g_atomic_int_inc(&element->refcount);

	return element;
}

static void free_properties(struct connman_element *element)
{
	DBG("element %p name %s", element, element->name);

	g_hash_table_destroy(element->properties);
	element->properties = NULL;
}

static void free_children(struct connman_element *element)
{
	DBG("element %p name %s", element, element->name);

	g_hash_table_destroy(element->children);
	element->children = NULL;
}

void connman_element_unref(struct connman_element *element)
{
	DBG("element %p name %s refcount %d", element, element->name,
				g_atomic_int_get(&element->refcount) - 1);

	if (g_atomic_int_dec_and_test(&element->refcount) == TRUE) {
		if (element->destruct)
			element->destruct(element);
		free_children(element);
		free_properties(element);
		g_free(element->hostname);
		g_free(element->domainname);
		g_free(element->ipv6.address);
		g_free(element->ipv6.network);
		g_free(element->devname);
		g_free(element->path);
		g_free(element->name);
		g_free(element);
	}
}

static int set_static_property(struct connman_element *element,
				const char *name, int type, const void *value)
{
	struct connman_property *property;

	DBG("element %p name %s", element, element->name);

	if (type != DBUS_TYPE_STRING && type != DBUS_TYPE_BYTE)
		return -EINVAL;

	property = g_try_new0(struct connman_property, 1);
	if (property == NULL)
		return -ENOMEM;

	property->id   = CONNMAN_PROPERTY_ID_INVALID;
	property->type = type;

	DBG("name %s type %d value %p", name, type, value);

	switch (type) {
	case DBUS_TYPE_STRING:
		property->value = g_strdup(*((const char **) value));
		break;
	case DBUS_TYPE_BOOLEAN:
	case DBUS_TYPE_BYTE:
		property->value = g_try_malloc(1);
		if (property->value != NULL)
			memcpy(property->value, value, 1);
		break;
	}

	g_hash_table_replace(element->properties, g_strdup(name), property);

	return 0;
}

static int set_static_array_property(struct connman_element *element,
			const char *name, int type, const void *value, int len)
{
	struct connman_property *property;

	DBG("element %p name %s", element, element->name);

	if (type != DBUS_TYPE_BYTE)
		return -EINVAL;

	property = g_try_new0(struct connman_property, 1);
	if (property == NULL)
		return -ENOMEM;

	property->id      = CONNMAN_PROPERTY_ID_INVALID;
	property->type    = DBUS_TYPE_ARRAY;
	property->subtype = type;

	DBG("name %s type %d value %p", name, type, value);

	switch (type) {
	case DBUS_TYPE_BYTE:
		property->value = g_try_malloc(len);
		if (property->value != NULL) {
			memcpy(property->value,
				*((const unsigned char **) value), len);
			property->size = len;
		}
		break;
	}

	g_hash_table_replace(element->properties, g_strdup(name), property);

	return 0;
}

int connman_element_get_value(struct connman_element *element,
				enum connman_property_id id, void *value)
{
	if (element->type == CONNMAN_ELEMENT_TYPE_ROOT)
		return -EINVAL;

	switch (id) {
	case CONNMAN_PROPERTY_ID_HOSTNAME:
		if (element->hostname == NULL)
			return connman_element_get_value(element->parent,
								id, value);
		*((char **) value) = element->hostname;
		break;
	case CONNMAN_PROPERTY_ID_DOMAINNAME:
		if (element->domainname == NULL)
			return connman_element_get_value(element->parent,
								id, value);
		*((char **) value) = element->domainname;
		break;
	case CONNMAN_PROPERTY_ID_IPV6_GATEWAY:
		if (element->ipv6.gateway == NULL)
			return connman_element_get_value(element->parent,
								id, value);
		*((char **) value) = element->ipv6.gateway;
		break;

	default:
		return -EINVAL;
	}

	return 0;
}

static gboolean get_static_property(struct connman_element *element,
						const char *name, void *value)
{
	struct connman_property *property;
	gboolean found = FALSE;

	DBG("element %p name %s", element, element->name);

	property = g_hash_table_lookup(element->properties, name);
	if (property != NULL) {
		switch (property->type) {
		case DBUS_TYPE_STRING:
			*((char **) value) = property->value;
			found = TRUE;
			break;
		case DBUS_TYPE_BOOLEAN:
		case DBUS_TYPE_BYTE:
			memcpy(value, property->value, 1);
			found = TRUE;
			break;
		}
	}

	if (found == FALSE && element->parent != NULL)
		return get_static_property(element->parent, name, value);

	return found;
}

static gboolean get_static_array_property(struct connman_element *element,
			const char *name, void *value, unsigned int *len)
{
	struct connman_property *property;
	gboolean found = FALSE;

	DBG("element %p name %s", element, element->name);

	property = g_hash_table_lookup(element->properties, name);
	if (property != NULL) {
		*((void **) value) = property->value;
		*len = property->size;
		found = TRUE;
	}

	return found;
}

/**
 * connman_element_set_string:
 * @element: element structure
 * @key: unique identifier
 * @value: string value
 *
 * Set string value for specific key
 */
int connman_element_set_string(struct connman_element *element,
					const char *key, const char *value)
{
	return set_static_property(element, key, DBUS_TYPE_STRING, &value);
}

/**
 * connman_element_get_string:
 * @element: element structure
 * @key: unique identifier
 *
 * Get string value for specific key
 */
const char *connman_element_get_string(struct connman_element *element,
							const char *key)
{
	const char *value;

	if (get_static_property(element, key, &value) == FALSE)
		return NULL;

	return value;
}

/**
 * connman_element_set_bool:
 * @element: element structure
 * @key: unique identifier
 * @value: boolean value
 *
 * Set boolean value for specific key
 */
int connman_element_set_bool(struct connman_element *element,
					const char *key, connman_bool_t value)
{
	return set_static_property(element, key, DBUS_TYPE_BOOLEAN, &value);
}

/**
 * connman_element_get_bool:
 * @element: element structure
 * @key: unique identifier
 *
 * Get boolean value for specific key
 */
connman_bool_t connman_element_get_bool(struct connman_element *element,
							const char *key)
{
	connman_bool_t value;

	if (get_static_property(element, key, &value) == FALSE)
		return FALSE;

	return value;
}

/**
 * connman_element_set_uint8:
 * @element: element structure
 * @key: unique identifier
 * @value: integer value
 *
 * Set integer value for specific key
 */
int connman_element_set_uint8(struct connman_element *element,
					const char *key, connman_uint8_t value)
{
	return set_static_property(element, key, DBUS_TYPE_BYTE, &value);
}

/**
 * connman_element_get_uint8:
 * @element: element structure
 * @key: unique identifier
 *
 * Get integer value for specific key
 */
connman_uint8_t connman_element_get_uint8(struct connman_element *element,
							const char *key)
{
	connman_uint8_t value;

	if (get_static_property(element, key, &value) == FALSE)
		return 0;

	return value;
}

/**
 * connman_element_set_blob:
 * @element: element structure
 * @key: unique identifier
 * @data: blob data
 * @size: blob size
 *
 * Set binary blob value for specific key
 */
int connman_element_set_blob(struct connman_element *element,
			const char *key, const void *data, unsigned int size)
{
	return set_static_array_property(element, key,
						DBUS_TYPE_BYTE, &data, size);
}

/**
 * connman_element_get_blob:
 * @element: element structure
 * @key: unique identifier
 * @size: pointer to blob size
 *
 * Get binary blob value for specific key
 */
const void *connman_element_get_blob(struct connman_element *element,
					const char *key, unsigned int *size)
{
	void *value;

	if (get_static_array_property(element, key, &value, size) == FALSE)
		return NULL;

	return value;
}

static void probe_element(struct connman_element *element)
{
	GSList *list;

	DBG("element %p name %s", element, element->name);

	for (list = driver_list; list; list = list->next) {
		struct connman_driver *driver = list->data;

		if (match_driver(element, driver) == FALSE)
			continue;

		DBG("driver %p name %s", driver, driver->name);

		if (driver->probe(element) == 0) {
			element->driver = driver;
			break;
		}
	}
}

static void register_element(gpointer data, gpointer user_data)
{
	struct connman_element *element = data;
	const gchar *basepath;
	GNode *node;

	if (element->parent) {
		node = g_node_find(element_root, G_PRE_ORDER,
					G_TRAVERSE_ALL, element->parent);
		basepath = element->parent->path;
	} else {
		element->parent = element_root->data;

		node = element_root;
		basepath = CONNMAN_PATH "/device";
	}

	element->path = g_strdup_printf("%s/%s", basepath, element->name);

	if (node == NULL) {
		connman_error("Element registration for %s failed",
							element->path);
		return;
	}

	DBG("element %p path %s", element, element->path);

	g_node_append_data(node, element);

	if (started == FALSE)
		return;

	probe_element(element);
}

gboolean __connman_element_device_isfiltered(const char *devname)
{
	char **pattern;

	if (device_filter == NULL)
		goto nodevice;

	for (pattern = device_filter; *pattern; pattern++) {
		if (g_pattern_match_simple(*pattern, devname) == FALSE) {
			DBG("ignoring device %s (match)", devname);
			return TRUE;
		}
	}

nodevice:
	if (nodevice_filter == NULL)
		return FALSE;

	for (pattern = nodevice_filter; *pattern; pattern++) {
		if (g_pattern_match_simple(*pattern, devname) == TRUE) {
			DBG("ignoring device %s (no match)", devname);
			return TRUE;
		}
	}

	return FALSE;
}

/**
 * connman_element_register:
 * @element: the element to register
 * @parent: the parent to register the element with
 *
 * Register an element with the core. It will be register under the given
 * parent of if %NULL is provided under the root element.
 *
 * Returns: %0 on success
 */
int connman_element_register(struct connman_element *element,
					struct connman_element *parent)
{
	DBG("element %p name %s parent %p", element, element->name, parent);

	if (element->devname == NULL)
		element->devname = g_strdup(element->name);

	if (element->type != CONNMAN_ELEMENT_TYPE_DEVICE)
		goto setup;

	if (__connman_element_device_isfiltered(element->devname) == TRUE)
		return -EPERM;

setup:
	if (connman_element_ref(element) == NULL)
		return -EINVAL;

	if (element->name == NULL) {
		element->name = g_strdup(type2string(element->type));
		if (element->name == NULL) {
			return -EINVAL;
		}
	}

	element->parent = parent;

	register_element(element, NULL);

	return 0;
}

static gboolean remove_element(GNode *node, gpointer user_data)
{
	struct connman_element *element = node->data;
	struct connman_element *root = user_data;

	DBG("element %p name %s", element, element->name);

	if (element == root)
		return FALSE;

	g_node_unlink(node);

	if (element->driver) {
		if (element->driver->remove)
			element->driver->remove(element);

		element->driver = NULL;
	}

	g_node_destroy(node);

	connman_element_unref(element);

	return FALSE;
}

struct unregister_type {
	struct connman_element *root;
	enum connman_element_type type;
};

static gboolean remove_element_type(GNode *node, gpointer user_data)
{
	struct unregister_type *children_type = user_data;
	struct connman_element *root = children_type->root;
	struct connman_element *element = node->data;
	enum connman_element_type type = children_type->type;

	DBG("element %p name %s", element, element->name);

	if (element == root)
		return FALSE;

	if(element->type != type)
		return FALSE;

	g_node_unlink(node);

	if (element->driver) {
		if (element->driver->remove)
			element->driver->remove(element);

		element->driver = NULL;
	}

	g_node_destroy(node);

	connman_element_unref(element);

	return FALSE;
}


void connman_element_unregister(struct connman_element *element)
{
	GNode *node;

	DBG("element %p name %s", element, element->name);

	node = g_node_find(element_root, G_PRE_ORDER, G_TRAVERSE_ALL, element);

	if (node != NULL)
		g_node_traverse(node, G_POST_ORDER,
				G_TRAVERSE_ALL, -1, remove_element, NULL);
}

void connman_element_unregister_children(struct connman_element *element)
{
	GNode *node;

	DBG("element %p name %s", element, element->name);

	node = g_node_find(element_root, G_PRE_ORDER, G_TRAVERSE_ALL, element);

	if (node != NULL)
		g_node_traverse(node, G_POST_ORDER,
				G_TRAVERSE_ALL, -1, remove_element, element);
}

void connman_element_unregister_children_type(struct connman_element *element, enum connman_element_type type)
{
	GNode *node;

	DBG("element %p name %s", element, element->name);

	node = g_node_find(element_root, G_PRE_ORDER, G_TRAVERSE_ALL, element);

	if (node != NULL) {
		struct unregister_type children_type;

		children_type.root = element;
		children_type.type = type;
		g_node_traverse(node, G_POST_ORDER,
				G_TRAVERSE_ALL, -1, remove_element_type, &children_type);
	}
}


static gboolean update_element(GNode *node, gpointer user_data)
{
	struct connman_element *element = node->data;

	DBG("element %p name %s", element, element->name);

	if (element->driver && element->driver->update)
		element->driver->update(element);

	return FALSE;
}

void connman_element_update(struct connman_element *element)
{
	GNode *node;

	DBG("element %p name %s", element, element->name);

	node = g_node_find(element_root, G_PRE_ORDER, G_TRAVERSE_ALL, element);

	if (node != NULL)
		g_node_traverse(node, G_PRE_ORDER,
				G_TRAVERSE_ALL, -1, update_element, element);
}

int connman_element_set_enabled(struct connman_element *element,
							gboolean enabled)
{
	if (element->enabled == enabled)
		return 0;

	element->enabled = enabled;

	connman_element_update(element);

	return 0;
}

static enum connman_service_error convert_error(enum connman_element_error error)
{
	switch (error) {
	case CONNMAN_ELEMENT_ERROR_UNKNOWN:
	case CONNMAN_ELEMENT_ERROR_FAILED:
		break;
	case CONNMAN_ELEMENT_ERROR_DHCP_FAILED:
		return CONNMAN_SERVICE_ERROR_DHCP_FAILED;
	case CONNMAN_ELEMENT_ERROR_CONNECT_FAILED:
		return CONNMAN_SERVICE_ERROR_CONNECT_FAILED;
	}

	return CONNMAN_SERVICE_ERROR_UNKNOWN;
}

/**
 * connman_element_set_error:
 * @element: element structure
 * @error: error identifier
 *
 * Set error state and specific error identifier
 */
void connman_element_set_error(struct connman_element *element,
					enum connman_element_error error)
{
	struct connman_service *service;

	DBG("element %p error %d", element, error);

	if (element->type == CONNMAN_ELEMENT_TYPE_ROOT)
		return;

	element->state = CONNMAN_ELEMENT_STATE_ERROR;
	element->error = error;

	if (element->driver && element->driver->change)
		element->driver->change(element);

	service = __connman_element_get_service(element);
	__connman_service_indicate_error(service, convert_error(error));
}

void __connman_element_set_driver(struct connman_element *element)
{
	GSList *list;

	DBG("element %p name %s driver %p", element, element->name,
						element->driver);

	if (element->driver)
		return;

	for (list = driver_list; list; list = list->next) {
		struct connman_driver *driver = list->data;

		if (match_driver(element, driver) == FALSE)
			continue;

		element->driver = driver;

		break;
	}
}

int __connman_element_init(const char *device, const char *nodevice)
{
	struct connman_element *element;

	DBG("");

	connection = connman_dbus_get_connection();
	if (connection == NULL)
		return -EIO;

	if (device)
		device_filter = g_strsplit(device, ",", -1);

	if (nodevice)
		nodevice_filter = g_strsplit(nodevice, ",", -1);

	element = connman_element_create("root");

	element->path = g_strdup("/");
	element->type = CONNMAN_ELEMENT_TYPE_ROOT;

	element_root = g_node_new(element);

	__connman_technology_init();
	__connman_notifier_init();
	__connman_location_init();
	__connman_service_init();
	__connman_provider_init();
	__connman_network_init();
	__connman_device_init();

	return 0;
}

static gboolean probe_node(GNode *node, gpointer data)
{
	struct connman_element *element = node->data;

	DBG("element %p name %s", element, element->name);

	if (element->type == CONNMAN_ELEMENT_TYPE_ROOT)
		return FALSE;

	if (element->driver)
		return FALSE;

	probe_element(element);

	return FALSE;
}

void __connman_element_start(void)
{
	DBG("");

	__connman_storage_init_profile();

	g_node_traverse(element_root, G_PRE_ORDER, G_TRAVERSE_ALL, -1,
							probe_node, NULL);

	started = TRUE;

	__connman_rtnl_start();

	__connman_dhcp_init();
	__connman_wpad_init();
	__connman_wispr_init();

	__connman_rfkill_init();
}

void __connman_element_stop(void)
{
	DBG("");

	__connman_rfkill_cleanup();

	__connman_wispr_cleanup();
	__connman_wpad_cleanup();
	__connman_dhcp_cleanup();
	__connman_provider_cleanup();
}

static gboolean free_driver(GNode *node, gpointer data)
{
	struct connman_element *element = node->data;

	DBG("element %p name %s", element, element->name);

	if (element->driver) {
		if (element->driver->remove)
			element->driver->remove(element);

		element->driver = NULL;
	}

	return FALSE;
}

static gboolean free_node(GNode *node, gpointer data)
{
	struct connman_element *element = node->data;

	DBG("element %p name %s", element, element->name);

	if (g_node_depth(node) > 1)
		connman_element_unregister(element);

	return FALSE;
}

void __connman_element_cleanup(void)
{
	DBG("");

	__connman_device_cleanup();
	__connman_network_cleanup();
	__connman_service_cleanup();
	__connman_location_cleanup();
	__connman_notifier_cleanup();
	__connman_technology_cleanup();

	g_node_traverse(element_root, G_POST_ORDER, G_TRAVERSE_ALL, -1,
							free_driver, NULL);

	g_node_traverse(element_root, G_POST_ORDER, G_TRAVERSE_ALL, -1,
							free_node, NULL);

	connman_element_unref(element_root->data);

	g_node_destroy(element_root);
	element_root = NULL;

	g_strfreev(nodevice_filter);
	g_strfreev(device_filter);

	if (connection == NULL)
		return;

	dbus_connection_unref(connection);
}
