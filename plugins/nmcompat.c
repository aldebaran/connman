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

#include <gdbus.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/log.h>
#include <connman/notifier.h>
#include <connman/dbus.h>

enum {
	NM_STATE_UNKNOWN = 0,
	NM_STATE_ASLEEP,
	NM_STATE_CONNECTING,
	NM_STATE_CONNECTED,
	NM_STATE_DISCONNECTED
};

#define NM_SERVICE    "org.freedesktop.NetworkManager"
#define NM_PATH       "/org/freedesktop/NetworkManager"
#define NM_INTERFACE  NM_SERVICE

static DBusConnection *connection = NULL;
static dbus_uint32_t state = NM_STATE_UNKNOWN;


static void nm_send_signal(const char *name, dbus_uint32_t state)
{
	DBusMessage *signal;

	signal = dbus_message_new_signal(NM_PATH, NM_INTERFACE, name);
	if (signal == NULL)
		return;

	dbus_message_append_args(signal, DBUS_TYPE_UINT32, &state,
				DBUS_TYPE_INVALID);

	g_dbus_send_message(connection, signal);
}

static void default_changed(struct connman_service *service)
{
	if (service != NULL)
		state = NM_STATE_CONNECTED;
	else
		state = NM_STATE_DISCONNECTED;

	DBG("%p %d", service, state);

	/* older deprecated signal, in case applications still use this */
	nm_send_signal("StateChange", state);

	/* the preferred current signal */
	nm_send_signal("StateChanged", state);
}

static struct connman_notifier notifier = {
	.name		= "nmcompat",
	.priority	= CONNMAN_NOTIFIER_PRIORITY_DEFAULT,
	.default_changed= default_changed,
};

static DBusMessage *nm_sleep(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *nm_wake(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *nm_state(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_UINT32, &state,
							DBUS_TYPE_INVALID);

	return reply;
}

static GDBusMethodTable nm_methods[] = {
	{ "sleep", "",  "",   nm_sleep        },
	{ "wake",  "",  "",   nm_wake         },
	{ "state", "",  "u",  nm_state        },
	{ },
};

static int nmcompat_init(void)
{
	gboolean ret;

	DBG("");

	connection = connman_dbus_get_connection();
	if (connection == NULL)
		return -1;

	if (g_dbus_request_name(connection, NM_SERVICE, NULL) == FALSE) {
		connman_error("nmcompat: can't register nm service\n");
		return -1;
	}

	if (connman_notifier_register(&notifier) < 0) {
		connman_error("nmcompat: failed to register notifier");
		return -1;
	}

	ret = g_dbus_register_interface(connection, NM_PATH, NM_INTERFACE,
					nm_methods, NULL, NULL, NULL, NULL);
	if (ret == FALSE) {
		connman_error("nmcompat: can't register " NM_INTERFACE);
		return -1;
	}

	return 0;
}

static void nmcompat_exit(void)
{
	DBG("");

	connman_notifier_unregister(&notifier);

	if (connection == NULL)
		return;

	g_dbus_unregister_interface(connection, NM_PATH, NM_INTERFACE);

	dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE(nmcompat, "NetworkManager compatibility interfaces",
			VERSION, CONNMAN_PLUGIN_PRIORITY_DEFAULT,
			nmcompat_init, nmcompat_exit)
