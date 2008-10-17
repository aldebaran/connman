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
#include <stdarg.h>
#include <string.h>

#include <glib.h>
#include <gdbus.h>

#include "connman.h"

static DBusConnection *connection;

static GStaticRWLock element_lock = G_STATIC_RW_LOCK_INIT;
static GNode *element_root = NULL;

static GSList *driver_list = NULL;

static GThreadPool *thread_register = NULL;
static GThreadPool *thread_unregister = NULL;
static GThreadPool *thread_unregister_children = NULL;

static gchar *device_filter = NULL;

static struct {
	enum connman_property_id id;
	int type;
	const char *name;
	const void *value;
} propid_table[] = {
	{ CONNMAN_PROPERTY_ID_IPV4_METHOD,
		DBUS_TYPE_STRING, "IPv4.Method", "dhcp" },
	{ CONNMAN_PROPERTY_ID_IPV4_ADDRESS,
		DBUS_TYPE_STRING, "IPv4.Address" },
	{ CONNMAN_PROPERTY_ID_IPV4_NETMASK,
		DBUS_TYPE_STRING, "IPv4.Netmask" },
	{ CONNMAN_PROPERTY_ID_IPV4_GATEWAY,
		DBUS_TYPE_STRING, "IPv4.Gateway" },
	{ CONNMAN_PROPERTY_ID_IPV4_NAMESERVER,
		DBUS_TYPE_STRING, "IPv4.Nameserver" },
	{ }
};

static int propid2type(enum connman_property_id id)
{
	int i;

	for (i = 0; propid_table[i].name; i++) {
		if (propid_table[i].id == id)
			return propid_table[i].type;
	}

	return DBUS_TYPE_INVALID;
}

static const char *propid2name(enum connman_property_id id)
{
	int i;

	for (i = 0; propid_table[i].name; i++) {
		if (propid_table[i].id == id)
			return propid_table[i].name;
	}

	return NULL;
}

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
	case CONNMAN_ELEMENT_TYPE_RESOLVER:
		return "resolver";
	case CONNMAN_ELEMENT_TYPE_INTERNET:
		return "internet";
	}

	return NULL;
}

static const char *subtype2string(enum connman_element_subtype type)
{
	switch (type) {
	case CONNMAN_ELEMENT_SUBTYPE_UNKNOWN:
		return "unknown";
	case CONNMAN_ELEMENT_SUBTYPE_FAKE:
		return "fake";
	case CONNMAN_ELEMENT_SUBTYPE_NETWORK:
		return "network";
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

static void append_property(DBusMessageIter *dict,
				struct connman_property *property)
{
	if (property->value == NULL)
		return;

	if (property->type == DBUS_TYPE_ARRAY)
		connman_dbus_dict_append_array(dict, property->name,
			property->subtype, &property->value, property->size);
	else
		connman_dbus_dict_append_variant(dict, property->name,
					property->type, &property->value);
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

	if (element->parent != NULL &&
			element->parent->type != CONNMAN_ELEMENT_TYPE_ROOT) {
		connman_dbus_dict_append_variant(&dict, "Parent",
				DBUS_TYPE_OBJECT_PATH, &element->parent->path);
	}

	str = type2string(element->type);
	if (str != NULL)
		connman_dbus_dict_append_variant(&dict, "Type",
						DBUS_TYPE_STRING, &str);
	str = subtype2string(element->subtype);
	if (str != NULL)
		connman_dbus_dict_append_variant(&dict, "Subtype",
						DBUS_TYPE_STRING, &str);

	connman_dbus_dict_append_variant(&dict, "Enabled",
					DBUS_TYPE_BOOLEAN, &element->enabled);

	if (element->priority > 0)
		connman_dbus_dict_append_variant(&dict, "Priority",
					DBUS_TYPE_UINT16, &element->priority);

	if (element->ipv4.address != NULL)
		connman_dbus_dict_append_variant(&dict, "IPv4.Address",
				DBUS_TYPE_STRING, &element->ipv4.address);
	if (element->ipv4.netmask != NULL)
		connman_dbus_dict_append_variant(&dict, "IPv4.Netmask",
				DBUS_TYPE_STRING, &element->ipv4.netmask);
	if (element->ipv4.gateway != NULL)
		connman_dbus_dict_append_variant(&dict, "IPv4.Gateway",
				DBUS_TYPE_STRING, &element->ipv4.gateway);

	connman_element_lock(element);

	for (list = element->properties; list; list = list->next) {
		struct connman_property *property = list->data;

		append_property(&dict, property);
	}

	connman_element_unlock(element);

	dbus_message_iter_close_container(&array, &dict);

	return reply;
}

static DBusMessage *set_property(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_element *element = data;
	DBusMessageIter iter;
	DBusMessageIter value;
	const char *name;
	GSList *list;

	DBG("conn %p", conn);

	if (dbus_message_iter_init(msg, &iter) == FALSE)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &name);
	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &value);

	if (__connman_security_check_privileges(msg) < 0)
		return __connman_error_permission_denied(msg);

	connman_element_lock(element);

	for (list = element->properties; list; list = list->next) {
		struct connman_property *property = list->data;
		const char *str;

		if (g_str_equal(property->name, name) == FALSE)
			continue;

		if (property->flags & CONNMAN_PROPERTY_FLAG_STATIC)
			continue;

		property->flags &= ~CONNMAN_PROPERTY_FLAG_REFERENCE;

		if (property->type == DBUS_TYPE_STRING) {
			dbus_message_iter_get_basic(&value, &str);
			g_free(property->value);
			property->value = g_strdup(str);
		} else
			property->value = NULL;
	}

	connman_element_unlock(element);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *clear_property(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_element *element = data;
	const char *name;
	GSList *list;

	DBG("conn %p", conn);

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &name,
						DBUS_TYPE_INVALID) == FALSE)
		return __connman_error_invalid_arguments(msg);

	if (__connman_security_check_privileges(msg) < 0)
		return __connman_error_permission_denied(msg);

	connman_element_lock(element);

	for (list = element->properties; list; list = list->next) {
		struct connman_property *property = list->data;

		if (g_str_equal(property->name, name) == FALSE)
			continue;

		if (property->flags & CONNMAN_PROPERTY_FLAG_STATIC)
			continue;

		if (property->flags & CONNMAN_PROPERTY_FLAG_REFERENCE)
			continue;

		property->flags |= CONNMAN_PROPERTY_FLAG_REFERENCE;

		if (property->type == DBUS_TYPE_STRING)
			g_free(property->value);

		property->value = NULL;
	}

	connman_element_unlock(element);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *do_update(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_element *element = data;

	DBG("conn %p", conn);

	if (element->enabled == FALSE)
		return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);

	if (element->driver && element->driver->update) {
		DBG("Calling update callback");
		element->driver->update(element);
	}

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *do_enable(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_element *element = data;

	DBG("conn %p", conn);

	if (element->enabled == TRUE)
		return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);

	if (element->driver && element->driver->enable) {
		DBG("Calling enable callback");
		if (element->driver->enable(element) < 0)
			return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
	}

	element->enabled = TRUE;

	g_dbus_emit_signal(connection, CONNMAN_MANAGER_PATH,
				CONNMAN_MANAGER_INTERFACE, "ElementUpdated",
				DBUS_TYPE_OBJECT_PATH, &element->path,
							DBUS_TYPE_INVALID);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *do_disable(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_element *element = data;

	DBG("conn %p", conn);

	if (element->enabled == FALSE)
		return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);

	if (element->driver && element->driver->disable) {
		DBG("Calling disable callback");
		if (element->driver->disable(element) < 0)
			return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
	}

	element->enabled = FALSE;

	g_dbus_emit_signal(connection, CONNMAN_MANAGER_PATH,
				CONNMAN_MANAGER_INTERFACE, "ElementUpdated",
				DBUS_TYPE_OBJECT_PATH, &element->path,
							DBUS_TYPE_INVALID);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static GDBusMethodTable element_methods[] = {
	{ "GetProperties", "",   "a{sv}", get_properties },
	{ "SetProperty",   "sv", "",      set_property   },
	{ "ClearProperty", "s",  "",      clear_property },
	{ "Update",        "",   "",      do_update      },
	{ "Enable",        "",   "",      do_enable      },
	{ "Disable",       "",   "",      do_disable     },
	{ },
};

static GDBusSignalTable element_signals[] = {
	{ "PropertyChanged", "sv" },
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

	g_static_rw_lock_reader_lock(&element_lock);
	g_node_traverse(element_root, G_PRE_ORDER, G_TRAVERSE_ALL, -1,
							append_path, &filter);
	g_static_rw_lock_reader_unlock(&element_lock);
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
		if (driver->probe(element) < 0)
			return FALSE;

		connman_element_lock(element);
		element->driver = driver;
		connman_element_unlock(element);
	}

	return FALSE;
}

void __connman_driver_rescan(struct connman_driver *driver)
{
	DBG("driver %p name %s", driver, driver->name);

	if (!driver->probe)
		return;

	g_static_rw_lock_writer_lock(&element_lock);

	if (element_root != NULL)
		g_node_traverse(element_root, G_PRE_ORDER,
				G_TRAVERSE_ALL, -1, probe_driver, driver);

	g_static_rw_lock_writer_unlock(&element_lock);
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

	g_static_rw_lock_writer_lock(&element_lock);

	driver_list = g_slist_insert_sorted(driver_list, driver,
							compare_priority);

	if (element_root != NULL)
		g_node_traverse(element_root, G_PRE_ORDER,
				G_TRAVERSE_ALL, -1, probe_driver, driver);

	g_static_rw_lock_writer_unlock(&element_lock);

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

		connman_element_lock(element);
		element->driver = NULL;
		connman_element_unlock(element);
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

	g_static_rw_lock_writer_lock(&element_lock);

	driver_list = g_slist_remove(driver_list, driver);

	if (element_root != NULL)
		g_node_traverse(element_root, G_POST_ORDER,
				G_TRAVERSE_ALL, -1, remove_driver, driver);

	g_static_rw_lock_writer_unlock(&element_lock);
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

	element->refcount = 1;

	g_static_mutex_init(&element->mutex);

	element->name    = g_strdup(name);
	element->type    = CONNMAN_ELEMENT_TYPE_UNKNOWN;
	element->subtype = CONNMAN_ELEMENT_SUBTYPE_UNKNOWN;
	element->state   = CONNMAN_ELEMENT_STATE_CLOSED;
	element->index   = -1;
	element->enabled = FALSE;

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
	GSList *list;

	DBG("element %p name %s", element, element->name);

	connman_element_lock(element);

	for (list = element->properties; list; list = list->next) {
		struct connman_property *property = list->data;

		if (!(property->flags & CONNMAN_PROPERTY_FLAG_REFERENCE)) {
			if (property->type == DBUS_TYPE_STRING)
				g_free(property->value);
			if (property->type == DBUS_TYPE_ARRAY &&
					property->subtype == DBUS_TYPE_BYTE)
				g_free(property->value);
		}

		g_free(property);
	}

	g_slist_free(element->properties);

	element->properties = NULL;

	connman_element_unlock(element);
}

void connman_element_unref(struct connman_element *element)
{
	DBG("element %p name %s refcount %d", element, element->name,
				g_atomic_int_get(&element->refcount) - 1);

	if (g_atomic_int_dec_and_test(&element->refcount) == TRUE) {
		free_properties(element);
		g_free(element->ipv4.address);
		g_free(element->ipv4.netmask);
		g_free(element->ipv4.gateway);
		g_free(element->ipv4.network);
		g_free(element->ipv4.broadcast);
		g_free(element->ipv4.nameserver);
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
	property->id    = CONNMAN_PROPERTY_ID_INVALID;
	property->name  = g_strdup(name);
	property->type  = type;

	DBG("name %s type %d value %p", name, type, value);

	switch (type) {
	case DBUS_TYPE_STRING:
		property->value = g_strdup(*((const char **) value));
		break;
	}

	connman_element_lock(element);
	element->properties = g_slist_append(element->properties, property);
	connman_element_unlock(element);

	return 0;
}

int connman_element_add_static_array_property(struct connman_element *element,
			const char *name, int type, const void *value, int len)
{
	struct connman_property *property;

	DBG("element %p name %s", element, element->name);

	if (type != DBUS_TYPE_BYTE)
		return -EINVAL;

	property = g_try_new0(struct connman_property, 1);
	if (property == NULL)
		return -ENOMEM;

	property->flags   = CONNMAN_PROPERTY_FLAG_STATIC;
	property->id      = CONNMAN_PROPERTY_ID_INVALID;
	property->name    = g_strdup(name);
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

	connman_element_lock(element);
	element->properties = g_slist_append(element->properties, property);
	connman_element_unlock(element);

	return 0;
}

static void *get_reference_value(struct connman_element *element,
						enum connman_property_id id)
{
	GSList *list;

	DBG("element %p name %s", element, element->name);

	for (list = element->properties; list; list = list->next) {
		struct connman_property *property = list->data;

		if (property->id != id)
			continue;

		if (!(property->flags & CONNMAN_PROPERTY_FLAG_REFERENCE))
			return property->value;
	}

	if (element->parent == NULL)
		return NULL;

	return get_reference_value(element->parent, id);
}

static void set_reference_properties(struct connman_element *element)
{
	GSList *list;

	DBG("element %p name %s", element, element->name);

	for (list = element->properties; list; list = list->next) {
		struct connman_property *property = list->data;

		if (!(property->flags & CONNMAN_PROPERTY_FLAG_REFERENCE))
			continue;

		property->value = get_reference_value(element->parent,
								property->id);
	}
}

static struct connman_property *create_property(struct connman_element *element,
						enum connman_property_id id)
{
	struct connman_property *property;
	GSList *list;

	DBG("element %p name %s", element, element->name);

	connman_element_lock(element);

	for (list = element->properties; list; list = list->next) {
		property = list->data;

		if (property->id == id)
			goto unlock;
	}

	property = g_try_new0(struct connman_property, 1);
	if (property == NULL)
		goto unlock;

	property->flags = CONNMAN_PROPERTY_FLAG_REFERENCE;
	property->id    = id;
	property->name  = g_strdup(propid2name(id));
	property->type  = propid2type(id);

	if (property->name == NULL) {
		g_free(property);
		property = NULL;
		goto unlock;
	}

	element->properties = g_slist_append(element->properties, property);

unlock:
	connman_element_unlock(element);

	return property;
}

static void create_default_properties(struct connman_element *element)
{
	struct connman_property *property;
	int i;

	DBG("element %p name %s", element, element->name);

	for (i = 0; propid_table[i].name; i++) {
		DBG("property %s", propid_table[i].name);

		property = create_property(element, propid_table[i].id);

		property->flags &= ~CONNMAN_PROPERTY_FLAG_REFERENCE;

		if (propid_table[i].type != DBUS_TYPE_STRING)
			continue;

		if (propid_table[i].value)
			property->value = g_strdup(propid_table[i].value);
		else
			property->value = g_strdup("");
	}
}

static int define_properties_valist(struct connman_element *element,
								va_list args)
{
	enum connman_property_id id;

	DBG("element %p name %s", element, element->name);

	id = va_arg(args, enum connman_property_id);

	while (id != CONNMAN_PROPERTY_ID_INVALID) {

		DBG("property %d", id);

		create_property(element, id);

		id = va_arg(args, enum connman_property_id);
	}

	return 0;
}

/**
 * connman_element_define_properties:
 * @element: an element
 * @varargs: list of property identifiers
 *
 * Define the valid properties for an element.
 *
 * Returns: %0 on success
 */
int connman_element_define_properties(struct connman_element *element, ...)
{
	va_list args;
	int err;

	DBG("element %p name %s", element, element->name);

	va_start(args, element);

	err = define_properties_valist(element, args);

	va_end(args);

	return err;
}

int connman_element_create_property(struct connman_element *element,
						const char *name, int type)
{
	return -EIO;
}

int connman_element_set_property(struct connman_element *element,
				enum connman_property_id id, const void *value)
{
	switch (id) {
	case CONNMAN_PROPERTY_ID_IPV4_ADDRESS:
		connman_element_lock(element);
		g_free(element->ipv4.address);
		element->ipv4.address = g_strdup(*((const char **) value));
		connman_element_unlock(element);
		break;
	case CONNMAN_PROPERTY_ID_IPV4_NETMASK:
		connman_element_lock(element);
		g_free(element->ipv4.netmask);
		element->ipv4.netmask = g_strdup(*((const char **) value));
		connman_element_unlock(element);
		break;
	case CONNMAN_PROPERTY_ID_IPV4_GATEWAY:
		connman_element_lock(element);
		g_free(element->ipv4.gateway);
		element->ipv4.gateway = g_strdup(*((const char **) value));
		connman_element_unlock(element);
		break;
	case CONNMAN_PROPERTY_ID_IPV4_NAMESERVER:
		connman_element_lock(element);
		g_free(element->ipv4.nameserver);
		element->ipv4.nameserver = g_strdup(*((const char **) value));
		connman_element_unlock(element);
		break;
	default:
		return -EINVAL;
	}

	g_dbus_emit_signal(connection, CONNMAN_MANAGER_PATH,
				CONNMAN_MANAGER_INTERFACE, "ElementUpdated",
				DBUS_TYPE_OBJECT_PATH, &element->path,
							DBUS_TYPE_INVALID);

	return 0;
}

int connman_element_get_value(struct connman_element *element,
				enum connman_property_id id, void *value)
{
	if (element->type == CONNMAN_ELEMENT_TYPE_ROOT)
		return -EINVAL;

	switch (id) {
	case CONNMAN_PROPERTY_ID_IPV4_ADDRESS:
		if (element->ipv4.address == NULL)
			return connman_element_get_value(element->parent,
								id, value);
		connman_element_lock(element);
		*((char **) value) = element->ipv4.address;
		connman_element_unlock(element);
		break;
	case CONNMAN_PROPERTY_ID_IPV4_NETMASK:
		if (element->ipv4.netmask == NULL)
			return connman_element_get_value(element->parent,
								id, value);
		connman_element_lock(element);
		*((char **) value) = element->ipv4.netmask;
		connman_element_unlock(element);
		break;
	case CONNMAN_PROPERTY_ID_IPV4_GATEWAY:
		if (element->ipv4.gateway == NULL)
			return connman_element_get_value(element->parent,
								id, value);
		connman_element_lock(element);
		*((char **) value) = element->ipv4.gateway;
		connman_element_unlock(element);
		break;
	case CONNMAN_PROPERTY_ID_IPV4_NAMESERVER:
		if (element->ipv4.nameserver == NULL)
			return connman_element_get_value(element->parent,
								id, value);
		connman_element_lock(element);
		*((char **) value) = element->ipv4.nameserver;
		connman_element_unlock(element);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

gboolean connman_element_get_static_property(struct connman_element *element,
						const char *name, void *value)
{
	GSList *list;
	gboolean found = FALSE;

	DBG("element %p name %s", element, element->name);

	connman_element_lock(element);

	for (list = element->properties; list; list = list->next) {
		struct connman_property *property = list->data;

		if (!(property->flags & CONNMAN_PROPERTY_FLAG_STATIC))
			continue;

		if (g_str_equal(property->name, name) == TRUE) {
			*((char **) value) = property->value;
			found = TRUE;
			break;
		}
	}

	connman_element_unlock(element);

	return found;
}

gboolean connman_element_get_static_array_property(struct connman_element *element,
					const char *name, void *value, int *len)
{
	GSList *list;
	gboolean found = FALSE;

	DBG("element %p name %s", element, element->name);

	connman_element_lock(element);

	for (list = element->properties; list; list = list->next) {
		struct connman_property *property = list->data;

		if (!(property->flags & CONNMAN_PROPERTY_FLAG_STATIC))
			continue;

		if (g_str_equal(property->name, name) == TRUE) {
			*((char **) value) = property->value;
			*len = property->size;
			found = TRUE;
			break;
		}
	}

	connman_element_unlock(element);

	return found;
}

gboolean connman_element_match_static_property(struct connman_element *element,
					const char *name, const void *value)
{
	GSList *list;
	gboolean result = FALSE;

	DBG("element %p name %s", element, element->name);

	connman_element_lock(element);

	for (list = element->properties; list; list = list->next) {
		struct connman_property *property = list->data;

		if (!(property->flags & CONNMAN_PROPERTY_FLAG_STATIC))
			continue;

		if (g_str_equal(property->name, name) == FALSE)
			continue;

		if (property->type == DBUS_TYPE_STRING)
			result = g_str_equal(property->value,
						*((const char **) value));

		if (result == TRUE)
			break;
	}

	connman_element_unlock(element);

	return result;
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

	if (device_filter && element->type == CONNMAN_ELEMENT_TYPE_DEVICE) {
		if (g_pattern_match_simple(device_filter,
						element->name) == FALSE) {
			DBG("ignoring %s device", element->name);
			return -EPERM;
		}
	}

	if (connman_element_ref(element) == NULL)
		return -EINVAL;

	connman_element_lock(element);

	__connman_element_load(element);

	if (element->name == NULL) {
		element->name = g_strdup(type2string(element->type));
		if (element->name == NULL) {
			connman_element_unlock(element);
			return -EINVAL;
		}
	}

	element->parent = parent;

	connman_element_unlock(element);

	if (thread_register != NULL)
		g_thread_pool_push(thread_register, element, NULL);

	return 0;
}

void connman_element_unregister(struct connman_element *element)
{
	DBG("element %p name %s", element, element->name);

	if (thread_unregister != NULL)
		g_thread_pool_push(thread_unregister, element, NULL);
}

void connman_element_unregister_children(struct connman_element *element)
{
	DBG("element %p name %s", element, element->name);

	if (thread_unregister_children != NULL)
		g_thread_pool_push(thread_unregister_children, element, NULL);
}

static gboolean update_element(GNode *node, gpointer user_data)
{
	struct connman_element *element = node->data;

	DBG("element %p name %s", element, element->name);

	if (element->driver && element->driver->update)
		element->driver->update(element);

	g_dbus_emit_signal(connection, CONNMAN_MANAGER_PATH,
				CONNMAN_MANAGER_INTERFACE, "ElementUpdated",
				DBUS_TYPE_OBJECT_PATH, &element->path,
							DBUS_TYPE_INVALID);

	return FALSE;
}

void connman_element_update(struct connman_element *element)
{
	GNode *node;

	DBG("element %p name %s", element, element->name);

	g_static_rw_lock_reader_lock(&element_lock);

	node = g_node_find(element_root, G_PRE_ORDER, G_TRAVERSE_ALL, element);

	if (node != NULL)
		g_node_traverse(node, G_PRE_ORDER,
				G_TRAVERSE_ALL, -1, update_element, NULL);

	g_static_rw_lock_reader_unlock(&element_lock);
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

static void register_element(gpointer data, gpointer user_data)
{
	struct connman_element *element = data;
	const gchar *basepath;
	GSList *list;
	GNode *node;

	g_static_rw_lock_writer_lock(&element_lock);

	connman_element_lock(element);

	if (element->parent) {
		node = g_node_find(element_root, G_PRE_ORDER,
					G_TRAVERSE_ALL, element->parent);
		basepath = element->parent->path;

		if (element->subtype == CONNMAN_ELEMENT_SUBTYPE_UNKNOWN)
			element->subtype = element->parent->subtype;
	} else {
		element->parent = element_root->data;

		node = element_root;
		basepath = "";
	}

	element->path = g_strdup_printf("%s/%s", basepath, element->name);

	set_reference_properties(element);

	connman_element_unlock(element);

	DBG("element %p path %s", element, element->path);

	g_node_append_data(node, element);

	if (g_dbus_register_interface(connection, element->path,
					CONNMAN_ELEMENT_INTERFACE,
					element_methods, element_signals,
					NULL, element, NULL) == FALSE)
		connman_error("Failed to register %s", element->path);

	g_dbus_emit_signal(connection, CONNMAN_MANAGER_PATH,
				CONNMAN_MANAGER_INTERFACE, "ElementAdded",
				DBUS_TYPE_OBJECT_PATH, &element->path,
							DBUS_TYPE_INVALID);

	g_static_rw_lock_writer_unlock(&element_lock);

	__connman_element_store(element);

	g_static_rw_lock_writer_lock(&element_lock);

	for (list = driver_list; list; list = list->next) {
		struct connman_driver *driver = list->data;

		if (match_driver(element, driver) == FALSE)
			continue;

		DBG("driver %p name %s", driver, driver->name);

		if (driver->probe(element) == 0) {
			connman_element_lock(element);
			element->driver = driver;
			connman_element_unlock(element);
			break;
		}
	}

	g_static_rw_lock_writer_unlock(&element_lock);
}

static gboolean remove_element(GNode *node, gpointer user_data)
{
	struct connman_element *element = node->data;
	struct connman_element *root = user_data;

	DBG("element %p name %s", element, element->name);

	if (element == root)
		return FALSE;

	if (element->driver) {
		if (element->driver->remove)
			element->driver->remove(element);

		connman_element_lock(element);
		element->driver = NULL;
		connman_element_unlock(element);
	}

	if (node != NULL) {
		g_node_unlink(node);
		g_node_destroy(node);
	}

	g_dbus_emit_signal(connection, CONNMAN_MANAGER_PATH,
				CONNMAN_MANAGER_INTERFACE, "ElementRemoved",
				DBUS_TYPE_OBJECT_PATH, &element->path,
							DBUS_TYPE_INVALID);

	g_dbus_unregister_interface(connection, element->path,
						CONNMAN_ELEMENT_INTERFACE);

	connman_element_unref(element);

	return FALSE;
}

static void unregister_element(gpointer data, gpointer user_data)
{
	struct connman_element *element = data;
	GNode *node;

	DBG("element %p name %s", element, element->name);

	g_static_rw_lock_writer_lock(&element_lock);

	node = g_node_find(element_root, G_PRE_ORDER, G_TRAVERSE_ALL, element);

	if (node != NULL)
		g_node_traverse(node, G_POST_ORDER,
				G_TRAVERSE_ALL, -1, remove_element, NULL);

	g_static_rw_lock_writer_unlock(&element_lock);
}

static void unregister_children(gpointer data, gpointer user_data)
{
	struct connman_element *element = data;
	GNode *node;

	DBG("element %p name %s", element, element->name);

	g_static_rw_lock_writer_lock(&element_lock);

	node = g_node_find(element_root, G_PRE_ORDER, G_TRAVERSE_ALL, element);

	if (node != NULL)
		g_node_traverse(node, G_POST_ORDER,
				G_TRAVERSE_ALL, -1, remove_element, element);

	g_static_rw_lock_writer_unlock(&element_lock);
}

int __connman_element_init(DBusConnection *conn, const char *device)
{
	struct connman_element *element;

	DBG("conn %p", conn);

	connection = dbus_connection_ref(conn);
	if (connection == NULL)
		return -EIO;

	device_filter = g_strdup(device);

	g_static_rw_lock_writer_lock(&element_lock);

	element = connman_element_create("root");

	element->path = g_strdup("/");
	element->type = CONNMAN_ELEMENT_TYPE_ROOT;

	create_default_properties(element);

	element_root = g_node_new(element);

	g_static_rw_lock_writer_unlock(&element_lock);

	thread_register = g_thread_pool_new(register_element,
							NULL, 1, FALSE, NULL);
	thread_unregister = g_thread_pool_new(unregister_element,
							NULL, 1, FALSE, NULL);
	thread_unregister_children = g_thread_pool_new(unregister_children,
							NULL, 1, FALSE, NULL);

	__connman_device_init();

	return 0;
}

static gboolean free_driver(GNode *node, gpointer data)
{
	struct connman_element *element = node->data;

	DBG("element %p name %s", element, element->name);

	if (element->driver) {
		if (element->driver->remove)
			element->driver->remove(element);

		connman_element_lock(element);
		element->driver = NULL;
		connman_element_unlock(element);
	}

	return FALSE;
}

static gboolean free_node(GNode *node, gpointer data)
{
	struct connman_element *element = node->data;

	DBG("element %p name %s", element, element->name);

	if (g_node_depth(node) > 1)
		g_thread_pool_push(thread_unregister, element, NULL);

	return FALSE;
}

void __connman_element_cleanup(void)
{
	DBG("");

	__connman_device_cleanup();

	g_thread_pool_free(thread_register, TRUE, TRUE);
	thread_register = NULL;

	g_static_rw_lock_writer_lock(&element_lock);
	g_node_traverse(element_root, G_POST_ORDER, G_TRAVERSE_ALL, -1,
							free_driver, NULL);
	g_static_rw_lock_writer_unlock(&element_lock);

	g_static_rw_lock_writer_lock(&element_lock);
	g_node_traverse(element_root, G_POST_ORDER, G_TRAVERSE_ALL, -1,
							free_node, NULL);
	g_static_rw_lock_writer_unlock(&element_lock);

	g_thread_pool_free(thread_unregister, FALSE, TRUE);
	thread_unregister = NULL;

	g_thread_pool_free(thread_unregister_children, FALSE, TRUE);
	thread_unregister_children = NULL;

	g_static_rw_lock_writer_lock(&element_lock);
	g_node_destroy(element_root);
	element_root = NULL;
	g_static_rw_lock_writer_unlock(&element_lock);

	g_free(device_filter);

	dbus_connection_unref(connection);
}
