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

#include <connman/plugin.h>
#include <connman/device.h>
#include <connman/log.h>

#define BLUEZ_SERVICE "org.bluez"

#define TIMEOUT 5000

static int bluetooth_probe(struct connman_device *device)
{
	DBG("device %p", device);

	return 0;
}

static void bluetooth_remove(struct connman_device *device)
{
	DBG("device %p", device);
}

static struct connman_device_driver bluetooth_driver = {
	.name	= "bluetooth",
	.type	= CONNMAN_DEVICE_TYPE_BLUETOOTH,
	.probe	= bluetooth_probe,
	.remove	= bluetooth_remove,
};

static GSList *device_list = NULL;

static void adapters_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply;
	DBusError error;
	char **adapters;
	int i, num_adapters;

	DBG("");

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&error);

	if (dbus_message_get_args(reply, &error,
				DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH,
						&adapters, &num_adapters,
						DBUS_TYPE_INVALID) == FALSE) {
		if (dbus_error_is_set(&error) == TRUE) {
			connman_error("%s", error.message);
			dbus_error_free(&error);
		} else
			connman_error("Wrong arguments for adapter list");
		goto done;
	}

	for (i = 0; i < num_adapters; i++) {
		struct connman_element *device;

		device = connman_element_create(NULL);
		device->type = CONNMAN_ELEMENT_TYPE_DEVICE;
		device->subtype = CONNMAN_ELEMENT_SUBTYPE_BLUETOOTH;

		device->name = g_path_get_basename(adapters[i]);

		connman_element_register(device, NULL);
		device_list = g_slist_append(device_list, device);
	}

	g_strfreev(adapters);

done:
	dbus_message_unref(reply);
}

static void bluetooth_connect(DBusConnection *connection, void *user_data)
{
	DBusMessage *message;
	DBusPendingCall *call;

	DBG("connection %p", connection);

	message = dbus_message_new_method_call(BLUEZ_SERVICE, "/",
					"org.bluez.Manager", "ListAdapters");
	if (message == NULL)
		return;

	if (dbus_connection_send_with_reply(connection, message,
						&call, TIMEOUT) == FALSE) {
		connman_error("Failed to get Bluetooth adapters");
		dbus_message_unref(message);
		return;
	}

	dbus_pending_call_set_notify(call, adapters_reply, NULL, NULL);

	dbus_message_unref(message);
}

static void bluetooth_disconnect(DBusConnection *connection, void *user_data)
{
	GSList *list;

	DBG("connection %p", connection);

	for (list = device_list; list; list = list->next) {
		struct connman_element *device = list->data;

		connman_element_unregister(device);
		connman_element_unref(device);
	}

	g_slist_free(device_list);
	device_list = NULL;
}

static DBusConnection *connection;
static guint watch;

static int bluetooth_init(void)
{
	int err;

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (connection == NULL)
		return -EIO;

	err = connman_device_driver_register(&bluetooth_driver);
	if (err < 0) {
		dbus_connection_unref(connection);
		return -EIO;
	}

	watch = g_dbus_add_service_watch(connection, BLUEZ_SERVICE,
			bluetooth_connect, bluetooth_disconnect, NULL, NULL);
	if (watch == 0) {
		connman_device_driver_unregister(&bluetooth_driver);
		dbus_connection_unref(connection);
		return -EIO;
	}

	if (g_dbus_check_service(connection, BLUEZ_SERVICE) == TRUE)
		bluetooth_connect(connection, NULL);

	return 0;
}

static void bluetooth_exit(void)
{
	g_dbus_remove_watch(connection, watch);

	connman_device_driver_unregister(&bluetooth_driver);

	dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE(bluetooth, "Bluetooth technology plugin", VERSION,
						bluetooth_init, bluetooth_exit)
