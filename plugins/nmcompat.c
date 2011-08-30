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
	NM_STATE_UNKNOWN          = 0,
	NM_STATE_ASLEEP           = 10,
	NM_STATE_DISCONNECTED     = 20,
	NM_STATE_DISCONNECTING    = 30,
	NM_STATE_CONNECTING       = 40,
	NM_STATE_CONNECTED_LOCAL  = 50,
	NM_STATE_CONNECTED_SITE   = 60,
	NM_STATE_CONNECTED_GLOBAL = 70
};

#define NM_STATE_CONNECTED NM_STATE_CONNECTED_GLOBAL

#define NM_SERVICE    "org.freedesktop.NetworkManager"
#define NM_PATH       "/org/freedesktop/NetworkManager"
#define NM_INTERFACE  NM_SERVICE

#define DBUS_PROPERTIES_INTERFACE	"org.freedesktop.DBus.Properties"

static DBusConnection *connection = NULL;
static dbus_uint32_t state = NM_STATE_UNKNOWN;

static void state_changed(dbus_uint32_t state)
{
	DBusMessage *signal;

	signal = dbus_message_new_signal(NM_PATH, NM_INTERFACE,
						"StateChanged");
	if (signal == NULL)
		return;

	dbus_message_append_args(signal, DBUS_TYPE_UINT32, &state,
				DBUS_TYPE_INVALID);

	g_dbus_send_message(connection, signal);
}

static void properties_changed(dbus_uint32_t state)
{
	const char *key = "State";
	DBusMessageIter iter, dict, dict_entry, dict_val;
	DBusMessage *signal;

	signal = dbus_message_new_signal(NM_PATH, NM_INTERFACE,
						"PropertiesChanged");
	if (signal == NULL)
		return;

	dbus_message_iter_init_append(signal, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
					DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					DBUS_TYPE_STRING_AS_STRING
					DBUS_TYPE_VARIANT_AS_STRING
					DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
					&dict);

	dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY,
							NULL, &dict_entry);

	dbus_message_iter_append_basic(&dict_entry, DBUS_TYPE_STRING, &key);

	dbus_message_iter_open_container(&dict_entry, DBUS_TYPE_VARIANT,
					DBUS_TYPE_UINT32_AS_STRING, &dict_val);

	dbus_message_iter_append_basic(&dict_val, DBUS_TYPE_UINT32, &state);

	dbus_message_iter_close_container(&dict_entry, &dict_val);
	dbus_message_iter_close_container(&dict, &dict_entry);
	dbus_message_iter_close_container(&iter, &dict);

	g_dbus_send_message(connection, signal);
}

static void default_changed(struct connman_service *service)
{
	if (service != NULL)
		state = NM_STATE_CONNECTED;
	else
		state = NM_STATE_DISCONNECTED;

	DBG("%p %d", service, state);

	state_changed(state);

	properties_changed(state);
}

static struct connman_notifier notifier = {
	.name		= "nmcompat",
	.priority	= CONNMAN_NOTIFIER_PRIORITY_DEFAULT,
	.default_changed= default_changed,
};

static DBusMessage *property_get(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *interface, *key;

	DBG("conn %p", conn);

	dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &interface,
				DBUS_TYPE_STRING, &key,
				DBUS_TYPE_INVALID);

	DBG("interface %s property %s", interface, key);

	if (g_strcmp0(key, "State") == 0) {
		DBusMessage *reply;
		DBusMessageIter iter, value;

		reply = dbus_message_new_method_return(msg);
		if (reply == NULL)
			return NULL;

		dbus_message_iter_init_append(reply, &iter);

		dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
						DBUS_TYPE_UINT32_AS_STRING,
						&value);
		dbus_message_iter_append_basic(&value, DBUS_TYPE_UINT32,
						&state);
		dbus_message_iter_close_container(&iter, &value);

		return reply;
	}

	return dbus_message_new_error(msg, DBUS_ERROR_FAILED,
						"Unsupported property");
}

static GDBusMethodTable methods[] = {
	{ "Get", "ss",  "v",   property_get	},
	{ },
};

static GDBusSignalTable signals[] = {
	{ "PropertiesChanged",	"a{sv}"	},
	{ "StateChanged",	"u"	},
	{ },
};

static int nmcompat_init(void)
{
	DBG("");

	connection = connman_dbus_get_connection();
	if (connection == NULL)
		return -1;

	if (g_dbus_request_name(connection, NM_SERVICE, NULL) == FALSE) {
		connman_error("nmcompat: failed register service\n");
		return -1;
	}

	if (connman_notifier_register(&notifier) < 0) {
		connman_error("nmcompat: failed to register notifier");
		return -1;
	}

	if (g_dbus_register_interface(connection, NM_PATH,
				DBUS_PROPERTIES_INTERFACE,
				methods, signals, NULL, NULL, NULL) == FALSE) {
		connman_error("nmcompat: failed to register "
						DBUS_PROPERTIES_INTERFACE);
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

	g_dbus_unregister_interface(connection, NM_PATH,
					DBUS_PROPERTIES_INTERFACE);

	dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE(nmcompat, "NetworkManager compatibility interfaces",
			VERSION, CONNMAN_PLUGIN_PRIORITY_DEFAULT,
			nmcompat_init, nmcompat_exit)
