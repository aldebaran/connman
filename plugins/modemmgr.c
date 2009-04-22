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

#include <errno.h>

#include <gdbus.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/dbus.h>
#include <connman/log.h>

#define MODEMMGR_SERVICE	"org.freedesktop.ModemManager"
#define MODEMMGR_INTERFACE	MODEMMGR_SERVICE

#define ENUMERATE_DEVICES	"EnumerateDevices"

#define TIMEOUT 5000

static void enumerate_devices_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply;

	DBG("");

	reply = dbus_pending_call_steal_reply(call);

	dbus_message_unref(reply);
}

static void modemmgr_connect(DBusConnection *connection, void *user_data)
{
	DBusMessage *message;
	DBusPendingCall *call;

	DBG("connection %p", connection);

	message = dbus_message_new_method_call(MODEMMGR_SERVICE, "/",
				MODEMMGR_INTERFACE, ENUMERATE_DEVICES);
	if (message == NULL)
		return;

	if (dbus_connection_send_with_reply(connection, message,
						&call, TIMEOUT) == FALSE) {
		connman_error("Failed to get modem devices");
		goto done;
	}

	if (call == NULL) {
		connman_error("D-Bus connection not available");
		goto done;
	}

	dbus_pending_call_set_notify(call, enumerate_devices_reply,
							NULL, NULL);

done:
	dbus_message_unref(message);
}

static void modemmgr_disconnect(DBusConnection *connection, void *user_data)
{
	DBG("connection %p", connection);
}

static DBusConnection *connection;
static guint watch;

static int modemmgr_init(void)
{
	connection = connman_dbus_get_connection();
	if (connection == NULL)
		return -EIO;

	watch = g_dbus_add_service_watch(connection, MODEMMGR_SERVICE,
			modemmgr_connect, modemmgr_disconnect, NULL, NULL);
	if (watch == 0) {
		dbus_connection_unref(connection);
		return -EIO;
	}

	return 0;
}

static void modemmgr_exit(void)
{
	g_dbus_remove_watch(connection, watch);

	dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE(modemmgr, "Modem Manager plugin", VERSION,
		CONNMAN_PLUGIN_PRIORITY_DEFAULT, modemmgr_init, modemmgr_exit)
