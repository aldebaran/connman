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
#include <syslog.h>

#include <gdbus.h>

#include "supplicant.h"

#define DBG(fmt, arg...) do { \
	syslog(LOG_DEBUG, "%s() " fmt, __FUNCTION__ , ## arg); \
} while (0)

#define SUPPLICANT_SERVICE	"fi.w1.wpa_supplicant1"
#define SUPPLICANT_INTERFACE	"fi.w1.wpa_supplicant1"
#define SUPPLICANT_PATH		"/fi/w1/wpa_supplicant1"

#define TIMEOUT 5000

static DBusConnection *connection;

static void show_property(const char *key, DBusMessageIter *iter)
{
	DBusMessageIter array;
	const char *str;
	unsigned char byte;

	switch (dbus_message_iter_get_arg_type(iter)) {
	case DBUS_TYPE_STRING:
		dbus_message_iter_get_basic(iter, &str);
		DBG("%s = %s", key, str);
		break;
	case DBUS_TYPE_BYTE:
		dbus_message_iter_get_basic(iter, &byte);
		DBG("%s = %u", key, byte);
		break;
	case DBUS_TYPE_ARRAY:
		DBG("%s = {array}", key);
		dbus_message_iter_recurse(iter, &array);
		while (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_INVALID) {
			dbus_message_iter_get_basic(&array, &str);
			DBG("  %s", str);
			dbus_message_iter_next(&array);
		}
		break;
	default:
		DBG("%s = ...", key);
		break;
	}
}

static void properties_decode(DBusMessageIter *iter)
{
	DBusMessageIter dict;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY) {
		syslog(LOG_ERR, "Invalid message type");
		return;
	}

	dbus_message_iter_recurse(iter, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;

		dbus_message_iter_recurse(&dict, &entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			return;

		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_VARIANT)
			return;

		dbus_message_iter_recurse(&entry, &value);

		show_property(key, &value);

		dbus_message_iter_next(&dict);
	}
}

static void properties_get_all_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply;
	DBusMessageIter iter;

	DBG("call %p", call);

	reply = dbus_pending_call_steal_reply(call);
	if (reply == NULL)
		return;

	if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR)
		goto failed;

	if (dbus_message_iter_init(reply, &iter) == FALSE)
		goto failed;

	DBG("success");

	properties_decode(&iter);

	dbus_message_unref(reply);

	return;

failed:
	dbus_message_unref(reply);
}

static int properties_get_all(const char *path, const char *interface)
{
	DBusMessage *message;
	DBusPendingCall *call;

	DBG("");

	message = dbus_message_new_method_call(SUPPLICANT_SERVICE, path,
					DBUS_INTERFACE_PROPERTIES, "GetAll");
	if (message == NULL)
		return -ENOMEM;

	dbus_message_set_auto_start(message, FALSE);

	dbus_message_append_args(message, DBUS_TYPE_STRING, &interface, NULL);

	if (dbus_connection_send_with_reply(connection, message,
						&call, TIMEOUT) == FALSE) {
		syslog(LOG_ERR, "Failed to add interface");
		dbus_message_unref(message);
		return -EIO;
	}

	if (call == NULL) {
		syslog(LOG_ERR, "D-Bus connection not available");
		dbus_message_unref(message);
		return -EIO;
	}

	DBG("call %p", call);

	dbus_pending_call_set_notify(call, properties_get_all_reply,
								NULL, NULL);

	dbus_message_unref(message);

	return 0;
}

int supplicant_init(void)
{
	DBG("");

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (connection == NULL)
		return -EIO;

	properties_get_all(SUPPLICANT_PATH, SUPPLICANT_INTERFACE);

	return 0;
}

void supplicant_exit(void)
{
	DBG("");

	if (connection != NULL)
		dbus_connection_unref(connection);
}
