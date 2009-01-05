/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2009  Intel Corporation. All rights reserved.
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

#include <string.h>

#include <gdbus.h>

#include "connman.h"

struct connman_network {
	struct connman_element element;
	enum connman_network_type type;
	enum connman_network_protocol protocol;
	connman_bool_t connected;
	connman_bool_t remember;
	connman_uint8_t strength;
	char *identifier;
	char *name;
	char *node;

	struct connman_network_driver *driver;
	void *driver_data;

	connman_bool_t registered;

	struct connman_device *device;

	struct {
		void *ssid;
		int ssid_len;
		char *mode;
		char *security;
		char *passphrase;
	} wifi;
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

	if (network->device) {
		const char *path = connman_device_get_path(network->device);
		if (path != NULL)
			connman_dbus_dict_append_variant(&dict, "Device",
						DBUS_TYPE_OBJECT_PATH, &path);
	}

	if (network->name != NULL)
		connman_dbus_dict_append_variant(&dict, "Name",
					DBUS_TYPE_STRING, &network->name);

	connman_dbus_dict_append_variant(&dict, "Connected",
				DBUS_TYPE_BOOLEAN, &network->connected);

	connman_dbus_dict_append_variant(&dict, "Remember",
				DBUS_TYPE_BOOLEAN, &network->remember);

	if (network->strength > 0)
		connman_dbus_dict_append_variant(&dict, "Strength",
					DBUS_TYPE_BYTE, &network->strength);

	if (network->wifi.ssid != NULL && network->wifi.ssid_len > 0)
		connman_dbus_dict_append_array(&dict, "WiFi.SSID",
				DBUS_TYPE_BYTE, &network->wifi.ssid,
						network->wifi.ssid_len);

	if (network->wifi.mode != NULL)
		connman_dbus_dict_append_variant(&dict, "WiFi.Mode",
				DBUS_TYPE_STRING, &network->wifi.mode);

	if (network->wifi.security != NULL)
		connman_dbus_dict_append_variant(&dict, "WiFi.Security",
				DBUS_TYPE_STRING, &network->wifi.security);

	if (network->wifi.passphrase != NULL)
		connman_dbus_dict_append_variant(&dict, "WiFi.Passphrase",
				DBUS_TYPE_STRING, &network->wifi.passphrase);

	dbus_message_iter_close_container(&array, &dict);

	return reply;
}

static DBusMessage *set_property(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_network *network = data;
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

	if (g_str_equal(name, "Remember") == TRUE) {
		connman_bool_t remember;

		dbus_message_iter_get_basic(&value, &remember);

		if (network->remember == remember)
			return __connman_error_invalid_arguments(msg);
	} else if (g_str_equal(name, "WiFi.Passphrase") == TRUE) {
		const char *passphrase;

		dbus_message_iter_get_basic(&value, &passphrase);

		g_free(network->wifi.passphrase);
		network->wifi.passphrase = g_strdup(passphrase);
	}

	__connman_storage_save_network(network);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *do_connect(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_network *network = data;
	int err;

	DBG("conn %p", conn);

	if (network->connected == TRUE)
		return __connman_error_failed(msg);

	if (network->driver && network->driver->connect) {
		err = network->driver->connect(network);
		if (err < 0 && err != -EINPROGRESS)
			return __connman_error_failed(msg);
	} else
		network->connected = TRUE;

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *do_disconnect(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_network *network = data;
	int err;

	DBG("conn %p", conn);

	if (network->connected == FALSE)
		return __connman_error_failed(msg);

	connman_element_unregister_children(&network->element);

	if (network->driver && network->driver->disconnect) {
		err = network->driver->disconnect(network);
		if (err < 0 && err != -EINPROGRESS)
			return __connman_error_failed(msg);
	} else
		network->connected = FALSE;

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

	if (g_dbus_register_interface(connection, element->path,
					CONNMAN_NETWORK_INTERFACE,
					network_methods, network_signals,
					NULL, network, NULL) == FALSE) {
		connman_error("Failed to register %s network", element->path);
		return -EIO;
	}

	network->registered = TRUE;

	emit_networks_signal();

	return 0;
}

static void unregister_interface(struct connman_element *element)
{
	struct connman_network * network = element->network;

	DBG("element %p name %s", element, element->name);

	network->registered = FALSE;

	emit_networks_signal();

	g_dbus_unregister_interface(connection, element->path,
						CONNMAN_NETWORK_INTERFACE);
}

connman_bool_t __connman_network_has_driver(struct connman_network *network)
{
	if (network == NULL || network->driver == NULL)
		return FALSE;

	return network->registered;
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

	g_free(network->wifi.ssid);
	g_free(network->wifi.mode);
	g_free(network->wifi.security);
	g_free(network->wifi.passphrase);

	g_free(network->node);
	g_free(network->name);
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

	switch (type) {
	case CONNMAN_NETWORK_TYPE_UNKNOWN:
	case CONNMAN_NETWORK_TYPE_VENDOR:
		network->element.subtype = CONNMAN_ELEMENT_SUBTYPE_UNKNOWN;
		break;
	case CONNMAN_NETWORK_TYPE_WIFI:
		network->element.subtype = CONNMAN_ELEMENT_SUBTYPE_WIFI;
		break;
	case CONNMAN_NETWORK_TYPE_BLUETOOTH_PAN:
	case CONNMAN_NETWORK_TYPE_BLUETOOTH_DUN:
		network->element.subtype = CONNMAN_ELEMENT_SUBTYPE_BLUETOOTH;
		break;
	case CONNMAN_NETWORK_TYPE_HSO:
		network->element.subtype = CONNMAN_ELEMENT_SUBTYPE_CELLULAR;
		break;
	}

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
 * connman_network_get_path:
 * @network: network structure
 *
 * Get path name of network
 */
const char *connman_network_get_path(struct connman_network *network)
{
	return network->element.path;
}

/**
 * connman_network_set_index:
 * @network: network structure
 * @index: index number
 *
 * Set index number of network
 */
void connman_network_set_index(struct connman_network *network, int index)
{
	network->element.index = index;
}

/**
 * connman_network_get_index:
 * @network: network structure
 *
 * Get index number of network
 */
int connman_network_get_index(struct connman_network *network)
{
	return network->element.index;
}

/**
 * connman_network_set_protocol:
 * @network: network structure
 * @protocol: network protocol
 *
 * Change protocol of network
 */
void connman_network_set_protocol(struct connman_network *network,
					enum connman_network_protocol protocol)
{
	network->protocol = protocol;
}

/**
 * connman_network_set_connected:
 * @network: network structure
 * @connected: connected state
 *
 * Change connected state of network
 */
int connman_network_set_connected(struct connman_network *network,
						connman_bool_t connected)
{
	DBG("network %p connected %d", network, connected);

	if (network->connected == connected)
		return -EALREADY;

	network->connected = connected;

	if (connected == TRUE) {
		struct connman_element *element;
		enum connman_element_type type = CONNMAN_ELEMENT_TYPE_UNKNOWN;

		switch (network->protocol) {
		case CONNMAN_NETWORK_PROTOCOL_UNKNOWN:
			return 0;
		case CONNMAN_NETWORK_PROTOCOL_IP:
			type = CONNMAN_ELEMENT_TYPE_DHCP;
			break;
		case CONNMAN_NETWORK_PROTOCOL_PPP:
			type = CONNMAN_ELEMENT_TYPE_PPP;
			break;
		}

		element = connman_element_create(NULL);
		if (element != NULL) {
			element->type    = type;
			element->subtype = network->element.subtype;
			element->index   = network->element.index;

			if (connman_element_register(element,
							&network->element) < 0)
				connman_element_unref(element);
		}
	} else
		connman_element_unregister_children(&network->element);

	return 0;
}

/**
 * connman_network_set_string:
 * @network: network structure
 * @key: unique identifier
 * @value: string value
 *
 * Set string value for specific key
 */
int connman_network_set_string(struct connman_network *network,
					const char *key, const char *value)
{
	DBG("network %p key %s value %s", network, key, value);

	if (g_str_equal(key, "Name") == TRUE) {
		g_free(network->name);
		network->name = g_strdup(value);
	} else if (g_str_equal(key, "Node") == TRUE) {
		g_free(network->node);
		network->node = g_strdup(value);
	} else if (g_str_equal(key, "WiFi.Mode") == TRUE) {
		g_free(network->wifi.mode);
		network->wifi.mode = g_strdup(value);
	} else if (g_str_equal(key, "WiFi.Security") == TRUE) {
		g_free(network->wifi.security);
		network->wifi.security = g_strdup(value);
	} else if (g_str_equal(key, "WiFi.Passphrase") == TRUE) {
		g_free(network->wifi.passphrase);
		network->wifi.passphrase = g_strdup(value);
	}

	return 0;
}

/**
 * connman_network_get_string:
 * @network: network structure
 * @key: unique identifier
 *
 * Get string value for specific key
 */
const char *connman_network_get_string(struct connman_network *network,
							const char *key)
{
	DBG("network %p key %s", network, key);

	if (g_str_equal(key, "Name") == TRUE)
		return network->name;
	else if (g_str_equal(key, "Node") == TRUE)
		return network->node;
	else if (g_str_equal(key, "WiFi.Mode") == TRUE)
		return network->wifi.mode;
	else if (g_str_equal(key, "WiFi.Security") == TRUE)
		return network->wifi.security;
	else if (g_str_equal(key, "WiFi.Passphrase") == TRUE)
		return network->wifi.passphrase;

	return NULL;
}

/**
 * connman_network_set_uint8:
 * @network: network structure
 * @key: unique identifier
 * @value: integer value
 *
 * Set integer value for specific key
 */
int connman_network_set_uint8(struct connman_network *network,
					const char *key, connman_uint8_t value)
{
	DBG("network %p key %s value %d", network, key, value);

	if (g_str_equal(key, "Strength") == TRUE)
		network->strength = value;

	return 0;
}

/**
 * connman_network_set_blob:
 * @network: network structure
 * @key: unique identifier
 * @data: blob data
 * @size: blob size
 *
 * Set binary blob value for specific key
 */
int connman_network_set_blob(struct connman_network *network,
			const char *key, const void *data, unsigned int size)
{
	DBG("network %p key %s size %d", network, key, size);

	if (g_str_equal(key, "WiFi.SSID") == TRUE) {
		g_free(network->wifi.ssid);
		network->wifi.ssid = g_try_malloc(size);
		if (network->wifi.ssid != NULL) {
			memcpy(network->wifi.ssid, data, size);
			network->wifi.ssid_len = size;
		} else
			network->wifi.ssid_len = 0;
	}

	return 0;
}

/**
 * connman_network_get_blob:
 * @network: network structure
 * @key: unique identifier
 * @size: pointer to blob size
 *
 * Get binary blob value for specific key
 */
const void *connman_network_get_blob(struct connman_network *network,
					const char *key, unsigned int *size)
{
	DBG("network %p key %s", network, key);

	if (g_str_equal(key, "WiFi.SSID") == TRUE) {
		if (size != NULL)
			*size = network->wifi.ssid_len;
		return network->wifi.ssid;
	}

	return NULL;
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

static int network_load(struct connman_network *network)
{
	GKeyFile *keyfile;
	gchar *pathname, *data = NULL;
	gsize length;
	const char *name;

	DBG("network %p", network);

	name = connman_device_get_name(network->device);
	if (name == NULL)
		return -EINVAL;

	pathname = g_strdup_printf("%s/%s.conf", STORAGEDIR, name);
	if (pathname == NULL)
		return -ENOMEM;

	keyfile = g_key_file_new();

	if (g_file_get_contents(pathname, &data, &length, NULL) == FALSE) {
		g_free(pathname);
		return -ENOENT;
	}

	g_free(pathname);

	if (g_key_file_load_from_data(keyfile, data, length,
							0, NULL) == FALSE) {
		g_free(data);
		return -EILSEQ;
	}

	g_free(data);

	network->remember = g_key_file_get_boolean(keyfile,
					network->identifier, "Remember", NULL);

	g_free(network->wifi.security);
	network->wifi.security = g_key_file_get_string(keyfile,
				network->identifier, "WiFi.Security", NULL);

	g_free(network->wifi.passphrase);
	network->wifi.passphrase = g_key_file_get_string(keyfile,
				network->identifier, "WiFi.Passphrase", NULL);

	g_key_file_free(keyfile);

	return 0;
}

static int network_save(struct connman_network *network)
{
	GKeyFile *keyfile;
	gchar *pathname, *data = NULL;
	gsize length;
	const char *name;

	DBG("network %p", network);

	name = connman_device_get_name(network->device);
	if (name == NULL)
		return -EINVAL;

	pathname = g_strdup_printf("%s/%s.conf", STORAGEDIR, name);
	if (pathname == NULL)
		return -ENOMEM;

	keyfile = g_key_file_new();

	if (g_file_get_contents(pathname, &data, &length, NULL) == FALSE)
		goto update;

	if (length > 0) {
		if (g_key_file_load_from_data(keyfile, data, length,
							0, NULL) == FALSE)
			goto done;
	}

	g_free(data);

update:
	g_key_file_set_boolean(keyfile, network->identifier,
					"Remember", network->remember);

	if (network->wifi.security != NULL)
		g_key_file_set_string(keyfile, network->identifier,
				"WiFi.Security", network->wifi.security);

	if (network->wifi.passphrase != NULL)
		g_key_file_set_string(keyfile, network->identifier,
				"WiFi.Passphrase", network->wifi.passphrase);

	data = g_key_file_to_data(keyfile, &length, NULL);

	g_file_set_contents(pathname, data, length, NULL);

done:
	g_free(data);

	g_key_file_free(keyfile);

	g_free(pathname);

	return 0;
}

static struct connman_storage network_storage = {
	.name		= "network",
	.priority	= CONNMAN_STORAGE_PRIORITY_LOW,
	.network_load	= network_load,
	.network_save	= network_save,
};

int __connman_network_init(void)
{
	DBG("");

	connection = connman_dbus_get_connection();

	if (connman_storage_register(&network_storage) < 0)
		connman_error("Failed to register network storage");

	return connman_driver_register(&network_driver);
}

void __connman_network_cleanup(void)
{
	DBG("");

	connman_driver_unregister(&network_driver);

	connman_storage_unregister(&network_storage);

	dbus_connection_unref(connection);
}
