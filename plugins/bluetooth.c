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

#include <connman/plugin.h>
#include <connman/driver.h>
#include <connman/log.h>

#define BLUEZ_SERVICE "org.bluez"

#define MANAGER_INTERFACE "org.bluez.Manager"
#define MANAGER_PATH "/"

static GStaticMutex element_mutex = G_STATIC_MUTEX_INIT;
static GSList *element_list = NULL;

static void create_element(DBusConnection *conn, const char *path)
{
	struct connman_element *element;

	DBG("conn %p path %s", conn, path);

	element = connman_element_create();

	element->name = g_path_get_basename(path);
	element->type = CONNMAN_ELEMENT_TYPE_DEVICE;
	element->subtype = CONNMAN_ELEMENT_SUBTYPE_BLUETOOTH;

	g_static_mutex_lock(&element_mutex);

	connman_element_register(element, NULL);

	element_list = g_slist_append(element_list, element);

	g_static_mutex_unlock(&element_mutex);
}

static gboolean bluetooth_signal(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *sender, *interface, *member;

	DBG("conn %p msg %p", conn, msg);

	sender = dbus_message_get_sender(msg);
	interface = dbus_message_get_interface(msg);
	member = dbus_message_get_member(msg);

	DBG("sender %s name %s.%s", sender, interface, member);

	return TRUE;
}

static void list_adapters(DBusConnection *conn)
{
	DBusMessage *msg, *reply;
	char **paths = NULL;
	int i, num = 0;

	DBG("conn %p");

	msg = dbus_message_new_method_call(BLUEZ_SERVICE, MANAGER_PATH,
					MANAGER_INTERFACE, "ListAdapters");
	if (!msg) {
		connman_error("ListAdpaters message alloction failed");
		return;
	}

	reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, NULL);

	dbus_message_unref(msg);

	if (!reply) {
		connman_error("ListAdapters method call failed");
		return;
	}

	dbus_message_get_args(reply, NULL, DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH,
						&paths, &num, DBUS_TYPE_INVALID);

	for (i = 0; i < num; i++)
		create_element(conn, paths[i]);

	g_strfreev(paths);

	dbus_message_unref(reply);
}

static int bluetooth_probe(struct connman_element *element)
{
	DBG("element %p name %s", element, element->name);

	return 0;
}

static void bluetooth_remove(struct connman_element *element)
{
	DBG("element %p name %s", element, element->name);
}

static struct connman_driver bluetooth_driver = {
	.name		= "bluetooth",
	.type		= CONNMAN_ELEMENT_TYPE_DEVICE,
	.subtype	= CONNMAN_ELEMENT_SUBTYPE_BLUETOOTH,
	.probe		= bluetooth_probe,
	.remove		= bluetooth_remove,
};

static DBusConnection *connection;
static guint signal;

static int bluetooth_init(void)
{
	int err;

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (connection == NULL)
		return -EIO;

	signal = g_dbus_add_signal_watch(connection, "sender=org.bluez",
						bluetooth_signal, NULL, NULL);

	err = connman_driver_register(&bluetooth_driver);
	if (err < 0) {
		dbus_connection_unref(connection);
		return err;
	}

	list_adapters(connection);

	return 0;
}

static void bluetooth_exit(void)
{
	connman_driver_unregister(&bluetooth_driver);

	g_dbus_remove_watch(connection, signal);

	dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE("bluetooth", "Bluetooth technology plugin", VERSION,
						bluetooth_init, bluetooth_exit)
