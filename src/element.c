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

static gboolean started = FALSE;

static const char *type2string(enum connman_element_type type)
{
	switch (type) {
	case CONNMAN_ELEMENT_TYPE_UNKNOWN:
		return "unknown";
	case CONNMAN_ELEMENT_TYPE_ROOT:
		return "root";
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
	return -EINVAL;
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

int __connman_element_init()
{
	struct connman_element *element;

	DBG("");

	connection = connman_dbus_get_connection();
	if (connection == NULL)
		return -EIO;
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

	if (connection == NULL)
		return;

	dbus_connection_unref(connection);
}
