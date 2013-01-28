/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2013  Intel Corporation. All rights reserved.
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

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/dbus.h>
#include <connman/technology.h>
#include <connman/device.h>
#include <gdbus.h>

#define BLUEZ_SERVICE                   "org.bluez"
#define BLUEZ_PATH                      "/org/bluez"

#define BLUETOOTH_ADDR_LEN              6

static DBusConnection *connection;
static GDBusClient *client;
static GHashTable *devices;

static void address2ident(const char *address, char *ident)
{
	int i;

	for (i = 0; i < BLUETOOTH_ADDR_LEN; i++) {
		ident[i * 2] = address[i * 3];
		ident[i * 2 + 1] = address[i * 3 + 1];
	}
	ident[BLUETOOTH_ADDR_LEN * 2] = '\0';
}

static const char *proxy_get_string(GDBusProxy *proxy, const char *property)
{
	DBusMessageIter iter;
	const char *str;

	if (g_dbus_proxy_get_property(proxy, property, &iter) == FALSE)
		return NULL;
	dbus_message_iter_get_basic(&iter, &str);
	return str;
}

static connman_bool_t proxy_get_bool(GDBusProxy *proxy, const char *property)
{
	DBusMessageIter iter;
	connman_bool_t value;

	if (g_dbus_proxy_get_property(proxy, property, &iter) == FALSE)
		return FALSE;
	dbus_message_iter_get_basic(&iter, &value);
	return value;
}

static void device_enable_cb(const DBusError *error, void *user_data)
{
	char *path = user_data;
	struct connman_device *device;

	device = g_hash_table_lookup(devices, path);
	if (device == NULL) {
		DBG("device already removed");
		goto out;
	}

	if (dbus_error_is_set(error) == TRUE) {
		connman_warn("Bluetooth device %s not enabled %s",
				path, error->message);
		goto out;
	}

	DBG("device %p", device);
	connman_device_set_powered(device, TRUE);

out:
	g_free(path);
}

static int bluetooth_device_enable(struct connman_device *device)
{
	GDBusProxy *proxy = connman_device_get_data(device);
	connman_bool_t device_powered = TRUE;
	const char *path;

	if (proxy == NULL)
		return 0;

	path = g_dbus_proxy_get_path(proxy);

	if (proxy_get_bool(proxy, "Powered") == TRUE) {
		DBG("already enabled %p %s", device, path);
		return -EALREADY;
	}

	DBG("device %p %s", device, path);

	g_dbus_proxy_set_property_basic(proxy, "Powered",
			DBUS_TYPE_BOOLEAN, &device_powered,
			device_enable_cb, g_strdup(path), NULL);

	return -EINPROGRESS;
}

static void device_disable_cb(const DBusError *error, void *user_data)
{
	char *path = user_data;
	struct connman_device *device;

	device = g_hash_table_lookup(devices, path);
	if (device == NULL) {
		DBG("device already removed");
		goto out;
	}

	if (dbus_error_is_set(error) == TRUE) {
		connman_warn("Bluetooth device %s not disabled: %s",
				path, error->message);
		goto out;
	}

	DBG("device %p", device);
	connman_device_set_powered(device, FALSE);

out:
	g_free(path);
}

static int bluetooth_device_disable(struct connman_device *device)
{
	GDBusProxy *proxy = connman_device_get_data(device);
	connman_bool_t device_powered = FALSE;
	const char *path;

	if (proxy == NULL)
		return 0;

	path = g_dbus_proxy_get_path(proxy);

	if (proxy_get_bool(proxy, "Powered") == FALSE) {
		DBG("already disabled %p %s", device, path);
		return -EALREADY;
	}

	DBG("device %p %s", device, path);

	g_dbus_proxy_set_property_basic(proxy, "Powered",
			DBUS_TYPE_BOOLEAN, &device_powered,
			device_disable_cb, g_strdup(path), NULL);

	return -EINPROGRESS;
}

static void adapter_property_change(GDBusProxy *proxy, const char *name,
		DBusMessageIter *iter, void *user_data)
{
	struct connman_device *device;
	const char *path;
	connman_bool_t adapter_powered, device_powered;

	if (strcmp(name, "Powered") != 0)
		return;

	path = g_dbus_proxy_get_path(proxy);
	device = g_hash_table_lookup(devices, path);

	adapter_powered = proxy_get_bool(proxy, "Powered");
	device_powered = connman_device_get_powered(device);

	DBG("device %p %s device powered %d adapter powered %d", device, path,
			device_powered, adapter_powered);

	if (device_powered != adapter_powered) {
		if (device_powered == TRUE)
			bluetooth_device_enable(device);
		else
			bluetooth_device_disable(device);
	}
}

static void device_free(gpointer data)
{
	struct connman_device *device = data;
	GDBusProxy *proxy = connman_device_get_data(device);

	connman_device_set_data(device, NULL);
	if (proxy != NULL)
		g_dbus_proxy_unref(proxy);

	connman_device_unregister(device);
	connman_device_unref(device);
}

static void device_create(GDBusProxy *proxy)
{
	struct connman_device *device = NULL;
	const char *path = g_dbus_proxy_get_path(proxy);
	const char *address;
	char ident[BLUETOOTH_ADDR_LEN * 2 + 1];
	connman_bool_t powered;

	address = proxy_get_string(proxy, "Address");
	if (address == NULL)
		return;

	address2ident(address, ident);

	device = connman_device_create("bluetooth",
			CONNMAN_DEVICE_TYPE_BLUETOOTH);
	if (device == NULL)
		return;

	connman_device_set_data(device, g_dbus_proxy_ref(proxy));
	connman_device_set_ident(device, ident);

	g_hash_table_replace(devices, g_strdup(path), device);

	DBG("device %p %s device powered %d adapter powered %d", device,
			path, connman_device_get_powered(device),
			proxy_get_bool(proxy, "Powered"));

	if (connman_device_register(device) < 0) {
		g_hash_table_remove(devices, device);
		return;
	}

	g_dbus_proxy_set_property_watch(proxy, adapter_property_change, NULL);

	powered = proxy_get_bool(proxy, "Powered");
	connman_device_set_powered(device, powered);
}

static void object_added(GDBusProxy *proxy, void *user_data)
{
	const char *interface;

	interface = g_dbus_proxy_get_interface(proxy);

	if (strcmp(interface, "org.bluez.Adapter1") == 0) {
		DBG("%s %s", interface, g_dbus_proxy_get_path(proxy));
		device_create(proxy);
		return;
	}

}

static void object_removed(GDBusProxy *proxy, void *user_data)
{
	const char *interface, *path;

	interface = g_dbus_proxy_get_interface(proxy);

	if (strcmp(interface, "org.bluez.Adapter1") == 0) {
		path = g_dbus_proxy_get_path(proxy);
		DBG("%s %s", interface, path);

		g_hash_table_remove(devices, path);
	}
}

static int bluetooth_device_probe(struct connman_device *device)
{
	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init(&iter, devices);

	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		struct connman_device *known = value;

		if (device == known)
			return 0;
	}

	return -EOPNOTSUPP;
}

static void bluetooth_device_remove(struct connman_device *device)
{
	DBG("%p", device);
}

static struct connman_device_driver device_driver = {
	.name		= "bluetooth",
	.type		= CONNMAN_DEVICE_TYPE_BLUETOOTH,
	.probe          = bluetooth_device_probe,
	.remove         = bluetooth_device_remove,
	.enable         = bluetooth_device_enable,
	.disable        = bluetooth_device_disable,
};

static int bluetooth_tech_probe(struct connman_technology *technology)
{
	return 0;
}

static void bluetooth_tech_remove(struct connman_technology *technology)
{

}

static struct connman_technology_driver tech_driver = {
	.name		= "bluetooth",
	.type		= CONNMAN_SERVICE_TYPE_BLUETOOTH,
	.probe          = bluetooth_tech_probe,
	.remove         = bluetooth_tech_remove,
};

static int bluetooth_init(void)
{
	connection = connman_dbus_get_connection();
	if (connection == NULL)
		goto out;

	if (connman_technology_driver_register(&tech_driver) < 0) {
		connman_warn("Failed to initialize technology for Bluez 5");
		goto out;
	}

	devices = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
			device_free);

	if (connman_device_driver_register(&device_driver) < 0) {
		connman_warn("Failed to initialize device driver for "
				BLUEZ_SERVICE);
		connman_technology_driver_unregister(&tech_driver);
		goto out;
	}

	client = g_dbus_client_new(connection, BLUEZ_SERVICE, BLUEZ_PATH);
	if (client == NULL) {
		connman_warn("Failed to initialize D-Bus client for "
				BLUEZ_SERVICE);
		goto out;
	}

	g_dbus_client_set_proxy_handlers(client, object_added, object_removed,
			NULL, NULL);

	return 0;

out:
	if (devices != NULL)
		g_hash_table_destroy(devices);

	if (client != NULL)
		g_dbus_client_unref(client);

	if (connection != NULL)
		dbus_connection_unref(connection);

	return -EIO;
}

static void bluetooth_exit(void)
{
	connman_device_driver_unregister(&device_driver);
	g_hash_table_destroy(devices);

	connman_technology_driver_unregister(&tech_driver);
	dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE(bluetooth, "Bluetooth technology plugin", VERSION,
                CONNMAN_PLUGIN_PRIORITY_DEFAULT, bluetooth_init, bluetooth_exit)
