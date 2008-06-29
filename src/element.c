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

#include <glib.h>
#include <gdbus.h>

#include "connman.h"

static DBusConnection *connection;

static GStaticMutex driver_mutex = G_STATIC_MUTEX_INIT;
static GSList *driver_list = NULL;
static GThreadPool *driver_thread;

static GStaticMutex element_mutex = G_STATIC_MUTEX_INIT;
static GNode *element_root = NULL;
static GThreadPool *element_thread;

static const char *type2string(enum connman_element_type type)
{
	switch (type) {
	case CONNMAN_ELEMENT_TYPE_UNKNOWN:
		return "unknown";
	case CONNMAN_ELEMENT_TYPE_ROOT:
		return "root";
	case CONNMAN_ELEMENT_TYPE_DEVICE:
		return "device";
	case CONNMAN_ELEMENT_TYPE_NETWORK:
		return "network";
	case CONNMAN_ELEMENT_TYPE_IPV4:
		return "ipv4";
	case CONNMAN_ELEMENT_TYPE_IPV6:
		return "ipv6";
	case CONNMAN_ELEMENT_TYPE_DHCP:
		return "dhcp";
	case CONNMAN_ELEMENT_TYPE_BOOTP:
		return "bootp";
	case CONNMAN_ELEMENT_TYPE_ZEROCONF:
		return "zeroconf";
	case CONNMAN_ELEMENT_TYPE_CONNECTION:
		return "42";
	}

	return NULL;
}

static const char *subtype2string(enum connman_element_subtype type)
{
	switch (type) {
	case CONNMAN_ELEMENT_SUBTYPE_UNKNOWN:
		return "unknown";
	case CONNMAN_ELEMENT_SUBTYPE_ETHERNET:
		return "ethernet";
	case CONNMAN_ELEMENT_SUBTYPE_WIFI:
		return "wifi";
	case CONNMAN_ELEMENT_SUBTYPE_WIMAX:
		return "wimax";
	case CONNMAN_ELEMENT_SUBTYPE_MODEM:
		return "modem";
	case CONNMAN_ELEMENT_SUBTYPE_BLUETOOTH:
		return "bluetooth";
	}

	return NULL;
}

static void append_entry(DBusMessageIter *dict,
				const char *key, int type, void *val)
{
	DBusMessageIter entry, value;
	const char *signature;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
								NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

	switch (type) {
	case DBUS_TYPE_STRING:
		signature = DBUS_TYPE_STRING_AS_STRING;
		break;
	case DBUS_TYPE_UINT16:
		signature = DBUS_TYPE_UINT16_AS_STRING;
		break;
	case DBUS_TYPE_OBJECT_PATH:
		signature = DBUS_TYPE_OBJECT_PATH_AS_STRING;
		break;
	default:
		signature = DBUS_TYPE_VARIANT_AS_STRING;
		break;
	}

	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
							signature, &value);
	dbus_message_iter_append_basic(&value, type, val);
	dbus_message_iter_close_container(&entry, &value);

	dbus_message_iter_close_container(dict, &entry);
}

static void append_property(DBusMessageIter *dict,
				struct connman_property *property)
{
	if (property->flags & CONNMAN_PROPERTY_FLAG_STATIC) {
		append_entry(dict, property->name, property->type,
							&property->value);
		return;
	}
}

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_element *element = data;
	GSList *list;
	DBusMessage *reply;
	DBusMessageIter array, dict;
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

	if (element->parent != NULL)
		append_entry(&dict, "Parent",
				DBUS_TYPE_OBJECT_PATH, &element->parent->path);

	str = type2string(element->type);
	if (str != NULL)
		append_entry(&dict, "Type", DBUS_TYPE_STRING, &str);
	str = subtype2string(element->subtype);
	if (str != NULL)
		append_entry(&dict, "Subtype", DBUS_TYPE_STRING, &str);

	if (element->ipv4.address != NULL)
		append_entry(&dict, "IPv4.Address",
				DBUS_TYPE_STRING, &element->ipv4.address);
	if (element->ipv4.netmask != NULL)
		append_entry(&dict, "IPv4.Netmask",
				DBUS_TYPE_STRING, &element->ipv4.netmask);
	if (element->ipv4.gateway != NULL)
		append_entry(&dict, "IPv4.Gateway",
				DBUS_TYPE_STRING, &element->ipv4.gateway);

	for (list = element->properties; list; list = list->next) {
		struct connman_property *property = list->data;

		append_property(&dict, property);
	}

	dbus_message_iter_close_container(&array, &dict);

	return reply;
}

static GDBusMethodTable element_methods[] = {
	{ "GetProperties", "", "a{sv}", get_properties },
	{ },
};

struct append_filter {
	enum connman_element_type type;
	DBusMessageIter *iter;
};

static gboolean append_path(GNode *node, gpointer data)
{
	struct connman_element *element = node->data;
	struct append_filter *filter = data;

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

void __connman_element_list(enum connman_element_type type,
						DBusMessageIter *iter)
{
	struct append_filter filter = { type, iter };

	DBG("");

	g_static_mutex_lock(&element_mutex);
	g_node_traverse(element_root, G_PRE_ORDER, G_TRAVERSE_ALL, -1,
							append_path, &filter);
	g_static_mutex_unlock(&element_mutex);
}

static gint compare_priority(gconstpointer a, gconstpointer b)
{
	const struct connman_driver *driver1 = a;
	const struct connman_driver *driver2 = b;

	return driver2->priority - driver1->priority;
}

int connman_driver_register(struct connman_driver *driver)
{
	DBG("driver %p name %s", driver, driver->name);

	if (driver->type == CONNMAN_ELEMENT_TYPE_ROOT)
		return -1;

	if (!driver->probe)
		return -EINVAL;

	g_static_mutex_lock(&driver_mutex);
	driver_list = g_slist_insert_sorted(driver_list, driver,
							compare_priority);
	g_static_mutex_unlock(&driver_mutex);

	g_thread_pool_push(driver_thread, driver, NULL);

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

void connman_driver_unregister(struct connman_driver *driver)
{
	DBG("driver %p name %s", driver, driver->name);

	g_static_mutex_lock(&element_mutex);
	g_node_traverse(element_root, G_POST_ORDER, G_TRAVERSE_ALL, -1,
							remove_driver, driver);
	g_static_mutex_unlock(&element_mutex);

	g_static_mutex_lock(&driver_mutex);
	driver_list = g_slist_remove(driver_list, driver);
	g_static_mutex_unlock(&driver_mutex);
}

struct connman_element *connman_element_create(void)
{
	struct connman_element *element;

	element = g_new0(struct connman_element, 1);

	DBG("element %p", element);

	element->refcount = 1;

	element->type    = CONNMAN_ELEMENT_TYPE_UNKNOWN;
	element->subtype = CONNMAN_ELEMENT_SUBTYPE_UNKNOWN;
	element->state   = CONNMAN_ELEMENT_STATE_CLOSED;

	element->netdev.index = -1;

	return element;
}

struct connman_element *connman_element_ref(struct connman_element *element)
{
	DBG("element %p name %s refcount %d", element, element->name,
				g_atomic_int_get(&element->refcount) + 1);

	g_atomic_int_inc(&element->refcount);

	return element;
}

void connman_element_unref(struct connman_element *element)
{
	DBG("element %p name %s refcount %d", element, element->name,
				g_atomic_int_get(&element->refcount) - 1);

	if (g_atomic_int_dec_and_test(&element->refcount) == TRUE) {
		GSList *list;

		for (list = element->properties; list; list = list->next) {
			struct connman_property *property = list->data;
			if ((property->flags & CONNMAN_PROPERTY_FLAG_STATIC) &&
					property->type == DBUS_TYPE_STRING)
				g_free(property->value);
			g_free(property);
			list->data = NULL;
		}
		g_slist_free(element->properties);

		g_free(element->ipv4.address);
		g_free(element->ipv4.netmask);
		g_free(element->ipv4.gateway);
		g_free(element->ipv4.network);
		g_free(element->ipv4.broadcast);
		g_free(element->ipv4.nameserver);
		g_free(element->netdev.name);
		g_free(element->path);
		g_free(element->name);
		g_free(element);
	}
}

int connman_element_add_static_property(struct connman_element *element,
				const char *name, int type, const void *value)
{
	struct connman_property *property;

	DBG("element %p name %s", element, element->name);

	if (type != DBUS_TYPE_STRING)
		return -EINVAL;

	property = g_try_new0(struct connman_property, 1);
	if (property == NULL)
		return -ENOMEM;

	property->flags = CONNMAN_PROPERTY_FLAG_STATIC;

	property->name = g_strdup(name);
	property->type = type;

	DBG("name %s type %d value %p", name, type, value);

	switch (type) {
	case DBUS_TYPE_STRING:
		property->value = g_strdup(*((const char **) value));
		break;
	}

	element->properties = g_slist_append(element->properties, property);

	return 0;
}

int connman_element_set_property(struct connman_element *element,
			enum connman_property_type type, const void *value)
{
	switch (type) {
	case CONNMAN_PROPERTY_TYPE_INVALID:
		return -EINVAL;
	case CONNMAN_PROPERTY_TYPE_IPV4_ADDRESS:
		g_free(element->ipv4.address);
		element->ipv4.address = g_strdup(*((const char **) value));
		break;
	case CONNMAN_PROPERTY_TYPE_IPV4_NETMASK:
		g_free(element->ipv4.netmask);
		element->ipv4.netmask = g_strdup(*((const char **) value));
		break;
	case CONNMAN_PROPERTY_TYPE_IPV4_GATEWAY:
		g_free(element->ipv4.gateway);
		element->ipv4.gateway = g_strdup(*((const char **) value));
		break;
	}

	g_dbus_emit_signal(connection, CONNMAN_MANAGER_PATH,
				CONNMAN_MANAGER_INTERFACE, "ElementUpdated",
				DBUS_TYPE_OBJECT_PATH, &element->path,
							DBUS_TYPE_INVALID);

	return 0;
}

int connman_element_get_value(struct connman_element *element,
				enum connman_property_type type, void *value)
{
	if (element->type == CONNMAN_ELEMENT_TYPE_ROOT)
		return -EINVAL;

	switch (type) {
	case CONNMAN_PROPERTY_TYPE_INVALID:
		return -EINVAL;
	case CONNMAN_PROPERTY_TYPE_IPV4_ADDRESS:
		if (element->ipv4.address == NULL)
			return connman_element_get_value(element->parent,
								type, value);
		*((char **) value) = element->ipv4.address;
		break;
	case CONNMAN_PROPERTY_TYPE_IPV4_NETMASK:
		if (element->ipv4.netmask == NULL)
			return connman_element_get_value(element->parent,
								type, value);
		*((char **) value) = element->ipv4.netmask;
		break;
	case CONNMAN_PROPERTY_TYPE_IPV4_GATEWAY:
		if (element->ipv4.gateway == NULL)
			return connman_element_get_value(element->parent,
								type, value);
		*((char **) value) = element->ipv4.gateway;
		break;
	}

	return 0;
}

int connman_element_register(struct connman_element *element,
					struct connman_element *parent)
{
	GNode *node;
	const gchar *basepath;

	DBG("element %p name %s parent %p", element, element->name, parent);

	if (connman_element_ref(element) == NULL)
		return -1;

	g_static_mutex_lock(&element_mutex);

	if (parent) {
		node = g_node_find(element_root, G_PRE_ORDER,
						G_TRAVERSE_ALL, parent);
		basepath = parent->path;

		if (element->subtype == CONNMAN_ELEMENT_SUBTYPE_UNKNOWN)
			element->subtype = parent->subtype;
	} else {
		node = element_root;
		basepath = "";
	}

	if (element->name == NULL) {
		switch (element->type) {
		case CONNMAN_ELEMENT_TYPE_IPV4:
			element->name = g_strdup("ipv4");
			break;
		case CONNMAN_ELEMENT_TYPE_IPV6:
			element->name = g_strdup("ipv6");
			break;
		case CONNMAN_ELEMENT_TYPE_DHCP:
			element->name = g_strdup("dhcp");
			break;
		case CONNMAN_ELEMENT_TYPE_BOOTP:
			element->name = g_strdup("bootp");
			break;
		case CONNMAN_ELEMENT_TYPE_ZEROCONF:
			element->name = g_strdup("zeroconf");
			break;
		default:
			break;
		}
	}

	element->path = g_strdup_printf("%s/%s", basepath, element->name);
	element->parent = parent;

	DBG("element %p path %s", element, element->path);

	g_node_append_data(node, element);

	g_static_mutex_unlock(&element_mutex);

	g_dbus_register_interface(connection, element->path,
					CONNMAN_ELEMENT_INTERFACE,
					element_methods, NULL, NULL,
							element, NULL);

	g_dbus_emit_signal(connection, CONNMAN_MANAGER_PATH,
				CONNMAN_MANAGER_INTERFACE, "ElementAdded",
				DBUS_TYPE_OBJECT_PATH, &element->path,
							DBUS_TYPE_INVALID);

	if (element->type == CONNMAN_ELEMENT_TYPE_DEVICE)
		g_dbus_emit_signal(connection, CONNMAN_MANAGER_PATH,
				CONNMAN_MANAGER_INTERFACE, "DeviceAdded",
				DBUS_TYPE_OBJECT_PATH, &element->path,
							DBUS_TYPE_INVALID);

	g_thread_pool_push(element_thread, element, NULL);

	return 0;
}

void connman_element_unregister(struct connman_element *element)
{
	GNode *node;

	DBG("element %p name %s", element, element->name);

	if (element->type == CONNMAN_ELEMENT_TYPE_DEVICE)
		g_dbus_emit_signal(connection, CONNMAN_MANAGER_PATH,
				CONNMAN_MANAGER_INTERFACE, "DeviceRemoved",
				DBUS_TYPE_OBJECT_PATH, &element->path,
							DBUS_TYPE_INVALID);

	g_dbus_emit_signal(connection, CONNMAN_MANAGER_PATH,
				CONNMAN_MANAGER_INTERFACE, "ElementRemoved",
				DBUS_TYPE_OBJECT_PATH, &element->path,
							DBUS_TYPE_INVALID);

	g_dbus_unregister_interface(connection, element->path,
						CONNMAN_ELEMENT_INTERFACE);

	g_static_mutex_lock(&element_mutex);

	if (element->driver) {
		if (element->driver->remove)
			element->driver->remove(element);
		element->driver = NULL;
	}

	node = g_node_find(element_root, G_PRE_ORDER, G_TRAVERSE_ALL, element);
	if (node != NULL) {
		g_node_unlink(node);
		g_node_destroy(node);
	}

	g_static_mutex_unlock(&element_mutex);

	connman_element_unref(element);
}

void connman_element_update(struct connman_element *element)
{
	DBG("element %p name %s", element, element->name);

	g_static_mutex_lock(&element_mutex);

	if (element->driver && element->driver->update)
		element->driver->update(element);

	g_static_mutex_unlock(&element_mutex);

	g_dbus_emit_signal(connection, CONNMAN_MANAGER_PATH,
				CONNMAN_MANAGER_INTERFACE, "ElementUpdated",
				DBUS_TYPE_OBJECT_PATH, &element->path,
							DBUS_TYPE_INVALID);
}

static inline void set_driver(struct connman_element *element,
						struct connman_driver *driver)
{
	g_static_mutex_lock(&element_mutex);
	element->driver = driver;
	g_static_mutex_unlock(&element_mutex);
}

static gboolean match_driver(struct connman_element *element,
					struct connman_driver *driver)
{
	if (element->type != driver->type &&
			driver->type != CONNMAN_ELEMENT_TYPE_UNKNOWN)
		return FALSE;

	if (element->subtype == driver->subtype ||
			driver->subtype == CONNMAN_ELEMENT_SUBTYPE_UNKNOWN)
		return TRUE;

	return FALSE;
}

static gboolean probe_driver(GNode *node, gpointer data)
{
	struct connman_element *element = node->data;
	struct connman_driver *driver = data;

	DBG("element %p name %s", element, element->name);

	if (!element->driver && match_driver(element, driver) == TRUE) {
		element->driver = driver;

		if (driver->probe(element) < 0)
			element->driver = NULL;
	}

	return FALSE;
}

static void driver_probe(gpointer data, gpointer user_data)
{
	struct connman_driver *driver = data;

	DBG("driver %p name %s", driver, driver->name);

	g_static_mutex_lock(&element_mutex);
	g_node_traverse(element_root, G_PRE_ORDER, G_TRAVERSE_ALL, -1,
							probe_driver, driver);
	g_static_mutex_unlock(&element_mutex);
}

static void element_probe(gpointer data, gpointer user_data)
{
	struct connman_element *element = data;
	GSList *list;

	DBG("element %p name %s", element, element->name);

	if (connman_element_ref(element) == NULL)
		return;

	g_static_mutex_lock(&driver_mutex);

	for (list = driver_list; list; list = list->next) {
		struct connman_driver *driver = list->data;

		DBG("driver %p name %s", driver, driver->name);

		set_driver(element, driver);

		if (match_driver(element, driver) == TRUE &&
						driver->probe(element) == 0)
			break;

		set_driver(element, NULL);
	}

	g_static_mutex_unlock(&driver_mutex);

	connman_element_unref(element);
}

int __connman_element_init(DBusConnection *conn)
{
	struct connman_element *element;

	DBG("conn %p", conn);

	connection = dbus_connection_ref(conn);
	if (connection == NULL)
		return -EIO;

	g_static_mutex_lock(&element_mutex);

	element = connman_element_create();

	element->name = g_strdup("root");
	element->path = g_strdup("/");
	element->type = CONNMAN_ELEMENT_TYPE_ROOT;

	element_root = g_node_new(element);

	g_static_mutex_unlock(&element_mutex);

	element_thread = g_thread_pool_new(element_probe, NULL, 1, FALSE, NULL);

	driver_thread = g_thread_pool_new(driver_probe, NULL, 1, FALSE, NULL);

	return 0;
}

static gboolean free_node(GNode *node, gpointer data)
{
	struct connman_element *element = node->data;

	DBG("element %p name %s", element, element->name);

	g_dbus_unregister_interface(connection, element->path,
						CONNMAN_ELEMENT_INTERFACE);

	if (element->driver) {
		if (element->driver->remove)
			element->driver->remove(element);
		element->driver = NULL;
	}

	connman_element_unref(element);

	node->data = NULL;

	return FALSE;
}

void __connman_element_cleanup(void)
{
	DBG("");

	g_thread_pool_free(driver_thread, TRUE, TRUE);

	g_thread_pool_free(element_thread, TRUE, TRUE);

	g_static_mutex_lock(&element_mutex);

	g_node_traverse(element_root, G_POST_ORDER, G_TRAVERSE_ALL, -1,
							free_node, NULL);

	g_node_destroy(element_root);
	element_root = NULL;

	g_static_mutex_unlock(&element_mutex);

	dbus_connection_unref(connection);
}
