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
#include <string.h>
#include <syslog.h>

#include <glib.h>
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

static const struct supplicant_callbacks *callbacks_pointer;

static void show_property(const char *key, DBusMessageIter *iter)
{
	DBusMessageIter array;
	const char *str;
	unsigned char byte;

	switch (dbus_message_iter_get_arg_type(iter)) {
	case DBUS_TYPE_STRING:
	case DBUS_TYPE_OBJECT_PATH:
		dbus_message_iter_get_basic(iter, &str);
		DBG("%s = %s", key, str);
		break;
	case DBUS_TYPE_BYTE:
	case DBUS_TYPE_BOOLEAN:
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

static DBusHandlerResult supplicant_filter(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	int prefixlen = strlen(SUPPLICANT_INTERFACE);
	const char *interface, *member, *path;

	interface = dbus_message_get_interface(msg);
	if (interface == NULL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (g_str_has_prefix(interface, SUPPLICANT_INTERFACE) == FALSE)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	member = dbus_message_get_member(msg);
	if (member == NULL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	path = dbus_message_get_path(msg);

	syslog(LOG_DEBUG, "[ %s ]%s.%s", path, interface + prefixlen, member);

	if (g_str_equal(member, "PropertiesChanged") == TRUE) {
		DBusMessageIter iter;

		if (dbus_message_iter_init(msg, &iter) == TRUE)
			properties_decode(&iter);
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static const char *supplicant_rule1 = "type=signal,"
			"interface=" SUPPLICANT_INTERFACE;
static const char *supplicant_rule2 = "type=signal,"
			"interface=" SUPPLICANT_INTERFACE ".Interface";
static const char *supplicant_rule3 = "type=signal,"
			"interface=" SUPPLICANT_INTERFACE ".Interface.WPS";
static const char *supplicant_rule4 = "type=signal,"
			"interface=" SUPPLICANT_INTERFACE ".Interface.BSS";
static const char *supplicant_rule5 = "type=signal,"
			"interface=" SUPPLICANT_INTERFACE ".Interface.Network";
static const char *supplicant_rule6 = "type=signal,"
			"interface=" SUPPLICANT_INTERFACE ".Interface.Blob";

int supplicant_register(const struct supplicant_callbacks *callbacks)
{
	DBG("");

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (connection == NULL)
		return -EIO;

	if (dbus_connection_add_filter(connection,
				supplicant_filter, NULL, NULL) == FALSE) {
		dbus_connection_unref(connection);
		connection = NULL;
		return -EIO;
	}

	callbacks_pointer = callbacks;

	dbus_bus_add_match(connection, supplicant_rule1, NULL);
	dbus_bus_add_match(connection, supplicant_rule2, NULL);
	dbus_bus_add_match(connection, supplicant_rule3, NULL);
	dbus_bus_add_match(connection, supplicant_rule4, NULL);
	dbus_bus_add_match(connection, supplicant_rule5, NULL);
	dbus_bus_add_match(connection, supplicant_rule6, NULL);
	dbus_connection_flush(connection);

	properties_get_all(SUPPLICANT_PATH, SUPPLICANT_INTERFACE);

	return 0;
}

void supplicant_unregister(const struct supplicant_callbacks *callbacks)
{
	DBG("");

	if (connection != NULL) {
		dbus_bus_remove_match(connection, supplicant_rule6, NULL);
		dbus_bus_remove_match(connection, supplicant_rule5, NULL);
		dbus_bus_remove_match(connection, supplicant_rule4, NULL);
		dbus_bus_remove_match(connection, supplicant_rule3, NULL);
		dbus_bus_remove_match(connection, supplicant_rule2, NULL);
		dbus_bus_remove_match(connection, supplicant_rule1, NULL);
		dbus_connection_flush(connection);

		dbus_connection_remove_filter(connection,
						supplicant_filter, NULL);

		dbus_connection_unref(connection);
		connection = NULL;
	}

	callbacks_pointer = NULL;
}
