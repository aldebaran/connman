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

#include <gdbus.h>

#include "connman.h"

struct connman_network {
	struct connman_element element;
	enum connman_network_type type;
	char *identifier;
	char *path;

	struct connman_network_driver *driver;
	void *driver_data;

	struct connman_device *device;
};

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_network *network = data;
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

	if (network->identifier != NULL)
		connman_dbus_dict_append_variant(&dict, "Name",
				DBUS_TYPE_STRING, &network->identifier);

	dbus_message_iter_close_container(&array, &dict);

	return reply;
}

static DBusMessage *set_property(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
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

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *do_connect(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_network *network = data;
	int err;

	DBG("conn %p", conn);

	if (network->driver && network->driver->connect) {
		err = network->driver->connect(network);
		if (err < 0 && err != -EINPROGRESS)
			return __connman_error_failed(msg);
	}

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *do_disconnect(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_network *network = data;
	int err;

	DBG("conn %p", conn);

	if (network->driver && network->driver->disconnect) {
		err = network->driver->disconnect(network);
		if (err < 0 && err != -EINPROGRESS)
			return __connman_error_failed(msg);
	}

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static GDBusMethodTable network_methods[] = {
	{ "GetProperties", "",   "a{sv}", get_properties },
	{ "SetProperty",   "sv", "",      set_property   },
	{ "Connect",       "",   "",      do_connect     },
	{ "Disconnect",    "",   "",      do_disconnect  },
	{ },
};

static GDBusSignalTable network_signals[] = {
	{ "PropertyChanged", "sv" },
	{ },
};

static DBusConnection *connection;

static void emit_networks_signal(void)
{
}

static int register_interface(struct connman_element *element)
{
	struct connman_network *network = element->network;

	DBG("element %p name %s", element, element->name);

	g_dbus_unregister_interface(connection, element->path,
						CONNMAN_NETWORK_INTERFACE);

	if (g_dbus_register_interface(connection, element->path,
					CONNMAN_NETWORK_INTERFACE,
					network_methods, network_signals,
					NULL, network, NULL) == FALSE) {
		connman_error("Failed to register %s network", element->path);
		return -EIO;
	}

	emit_networks_signal();

	return 0;
}

static void unregister_interface(struct connman_element *element)
{
	DBG("element %p name %s", element, element->name);

	emit_networks_signal();

	g_dbus_unregister_interface(connection, element->path,
						CONNMAN_NETWORK_INTERFACE);
}

static GSList *driver_list = NULL;

static gint compare_priority(gconstpointer a, gconstpointer b)
{
	const struct connman_network_driver *driver1 = a;
	const struct connman_network_driver *driver2 = b;

	return driver2->priority - driver1->priority;
}

/**
 * connman_network_driver_register:
 * @driver: network driver definition
 *
 * Register a new network driver
 *
 * Returns: %0 on success
 */
int connman_network_driver_register(struct connman_network_driver *driver)
{
	DBG("driver %p name %s", driver, driver->name);

	driver_list = g_slist_insert_sorted(driver_list, driver,
							compare_priority);

	return 0;
}

/**
 * connman_network_driver_unregister:
 * @driver: network driver definition
 *
 * Remove a previously registered network driver
 */
void connman_network_driver_unregister(struct connman_network_driver *driver)
{
	DBG("driver %p name %s", driver, driver->name);

	driver_list = g_slist_remove(driver_list, driver);
}

static void network_destruct(struct connman_element *element)
{
	struct connman_network *network = element->network;

	DBG("element %p name %s", element, element->name);

	g_free(network->path);
	g_free(network->identifier);
}

/**
 * connman_network_create:
 * @identifier: network identifier (for example an unqiue name)
 *
 * Allocate a new network and assign the #identifier to it.
 *
 * Returns: a newly-allocated #connman_network structure
 */
struct connman_network *connman_network_create(const char *identifier,
						enum connman_network_type type)
{
	struct connman_network *network;

	DBG("identifier %s type %d", identifier, type);

	network = g_try_new0(struct connman_network, 1);
	if (network == NULL)
		return NULL;

	DBG("network %p", network);

	network->element.refcount = 1;

	network->element.name = g_strdup(identifier);
	network->element.type = CONNMAN_ELEMENT_TYPE_NETWORK;
	network->element.index = -1;

	network->element.network = network;
	network->element.destruct = network_destruct;

	network->type = type;
	network->identifier = g_strdup(identifier);

	return network;
}

/**
 * connman_network_ref:
 * @network: network structure
 *
 * Increase reference counter of  network
 */
struct connman_network *connman_network_ref(struct connman_network *network)
{
	if (connman_element_ref(&network->element) == NULL)
		return NULL;

	return network;
}

/**
 * connman_network_unref:
 * @network: network structure
 *
 * Decrease reference counter of network
 */
void connman_network_unref(struct connman_network *network)
{
	connman_element_unref(&network->element);
}

/**
 * connman_network_get_identifier:
 * @network: network structure
 *
 * Get identifier of network
 */
const char *connman_network_get_identifier(struct connman_network *network)
{
	return network->identifier;
}

/**
 * connman_network_set_path:
 * @network: network structure
 * @path: path name
 *
 * Set path name of network
 */
void connman_network_set_path(struct connman_network *network, const char *path)
{
	g_free(network->element.devpath);
	network->element.devpath = g_strdup(path);

	g_free(network->path);
	network->path = g_strdup(path);
}

/**
 * connman_network_get_path:
 * @network: network structure
 *
 * Get path name of network
 */
const char *connman_network_get_path(struct connman_network *network)
{
	return network->path;
}

void __connman_network_set_device(struct connman_network *network,
					struct connman_device *device)
{
	network->device = device;
}

/**
 * connman_network_get_device:
 * @network: network structure
 *
 * Get parent device of network
 */
struct connman_device *connman_network_get_device(struct connman_network *network)
{
	return network->device;
}

/**
 * connman_network_get_data:
 * @network: network structure
 *
 * Get private network data pointer
 */
void *connman_network_get_data(struct connman_network *network)
{
	return network->driver_data;
}

/**
 * connman_network_set_data:
 * @network: network structure
 * @data: data pointer
 *
 * Set private network data pointer
 */
void connman_network_set_data(struct connman_network *network, void *data)
{
	network->driver_data = data;
}

static gboolean match_driver(struct connman_network *network,
					struct connman_network_driver *driver)
{
	if (network->type == driver->type ||
			driver->type == CONNMAN_NETWORK_TYPE_UNKNOWN)
		return TRUE;

	return FALSE;
}

static int network_probe(struct connman_element *element)
{
	struct connman_network *network = element->network;
	GSList *list;
	int err;

	DBG("element %p name %s", element, element->name);

	if (network == NULL)
		return -ENODEV;

	for (list = driver_list; list; list = list->next) {
		struct connman_network_driver *driver = list->data;

		if (match_driver(network, driver) == FALSE)
			continue;

		DBG("driver %p name %s", driver, driver->name);

		if (driver->probe(network) == 0) {
			network->driver = driver;
			break;
		}
	}

	if (network->driver == NULL)
		return -ENODEV;

	err = register_interface(element);
	if (err < 0) {
		if (network->driver->remove)
			network->driver->remove(network);
		return err;
	}

	return 0;
}

static void network_remove(struct connman_element *element)
{
	struct connman_network *network = element->network;

	DBG("element %p name %s", element, element->name);

	if (network == NULL)
		return;

	if (network->driver == NULL)
		return;

	unregister_interface(element);

	if (network->driver->remove)
		network->driver->remove(network);
}

static struct connman_driver network_driver = {
	.name		= "network",
	.type		= CONNMAN_ELEMENT_TYPE_NETWORK,
	.priority	= CONNMAN_DRIVER_PRIORITY_LOW,
	.probe		= network_probe,
	.remove		= network_remove,
};

int __connman_network_init(void)
{
	DBG("");

	connection = connman_dbus_get_connection();

	return connman_driver_register(&network_driver);
}

void __connman_network_cleanup(void)
{
	DBG("");

	connman_driver_unregister(&network_driver);

	dbus_connection_unref(connection);
}
