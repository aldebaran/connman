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

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <gdbus.h>

#include "connman.h"

static DBusConnection *connection = NULL;
static guint agent_watch = 0;
static gchar *agent_path = NULL;
static gchar *agent_sender = NULL;

static void agent_free(void)
{
	agent_watch = 0;

	g_free(agent_sender);
	agent_sender = NULL;

	g_free(agent_path);
	agent_path = NULL;
}

static void agent_disconnect(DBusConnection *connection, void *data)
{
	DBG("data %p", data);

	agent_free();
}

int __connman_agent_register(const char *sender, const char *path)
{
	DBG("sender %s path %s", sender, path);

	if (agent_path != NULL)
		return -EEXIST;

	agent_sender = g_strdup(sender);
	agent_path = g_strdup(path);

	agent_watch = g_dbus_add_disconnect_watch(connection, sender,
						agent_disconnect, NULL, NULL);

	return 0;
}

int __connman_agent_unregister(const char *sender, const char *path)
{
	DBG("sender %s path %s", sender, path);

	if (agent_path == NULL)
		return -ESRCH;

	if (agent_watch > 0)
		g_dbus_remove_watch(connection, agent_watch);

	agent_free();

	return 0;
}

struct request_input_reply {
	struct connman_service *service;
	passphrase_cb_t callback;
	void *user_data;
};

static void request_input_passphrase_reply(DBusPendingCall *call, void *user_data)
{
	struct request_input_reply *passphrase_reply = user_data;
	char *passphrase = NULL;
	char *key;
	DBusMessageIter iter, dict;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);

	if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR)
		goto done;

	dbus_message_iter_init(reply, &iter);
	dbus_message_iter_recurse(&iter, &dict);
	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;

		dbus_message_iter_recurse(&dict, &entry);
		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			break;

		dbus_message_iter_get_basic(&entry, &key);
		if (g_str_equal(key, "Passphrase")) {
			dbus_message_iter_next(&entry);
			if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_VARIANT)
				break;
			dbus_message_iter_recurse(&entry, &value);
			dbus_message_iter_get_basic(&value, &passphrase);
			break;
		}
		dbus_message_iter_next(&dict);
	}

done:
	passphrase_reply->callback(passphrase_reply->service,
				passphrase, passphrase_reply->user_data);
	connman_service_unref(passphrase_reply->service);
	dbus_message_unref(reply);
	g_free(passphrase_reply);
}

static void request_input_append_passphrase(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;
	char *value;

	switch (__connman_service_get_security(service)) {
	case CONNMAN_SERVICE_SECURITY_WEP:
		value = "wep";
		break;
	case CONNMAN_SERVICE_SECURITY_PSK:
		value = "psk";
		break;
	default:
		value = "string";
		break;
	}
	connman_dbus_dict_append_basic(iter, "Type",
				DBUS_TYPE_STRING, &value);
	value = "Mandatory";
	connman_dbus_dict_append_basic(iter, "Requirement",
				DBUS_TYPE_STRING, &value);
}

int __connman_agent_request_input(struct connman_service *service,
				passphrase_cb_t callback, void *user_data)
{
	DBusMessage *message;
	const char *path;
	DBusMessageIter iter;
	DBusMessageIter dict;
	DBusPendingCall *call;
	struct request_input_reply *passphrase_reply;

	if (service == NULL || agent_path == NULL || callback == NULL)
		return -ESRCH;

	message = dbus_message_new_method_call(agent_sender, agent_path,
					CONNMAN_AGENT_INTERFACE,
					"RequestInput");
	if (message == NULL)
		return -ENOMEM;

	dbus_message_iter_init_append(message, &iter);

	path = __connman_service_get_path(service);
	dbus_message_iter_append_basic(&iter,
				DBUS_TYPE_OBJECT_PATH, &path);

	connman_dbus_dict_open(&iter, &dict);
	connman_dbus_dict_append_dict(&dict, "Passphrase",
				request_input_append_passphrase, service);
	connman_dbus_dict_close(&iter, &dict);

	passphrase_reply = g_try_new0(struct request_input_reply, 1);
	if (passphrase_reply == NULL) {
		dbus_message_unref(message);
		return -ENOMEM;
	}

	if (dbus_connection_send_with_reply(connection, message,
						&call, -1) == FALSE) {
		dbus_message_unref(message);
		g_free(passphrase_reply);
		return -ESRCH;
	}

	if (call == NULL) {
		dbus_message_unref(message);
		g_free(passphrase_reply);
		return -ESRCH;
	}

	passphrase_reply->service = connman_service_ref(service);
	passphrase_reply->callback = callback;
	passphrase_reply->user_data = user_data;

	dbus_pending_call_set_notify(call, request_input_passphrase_reply,
				passphrase_reply, NULL);

	dbus_message_unref(message);

	return -EIO;
}

int __connman_agent_init(void)
{
	DBG("");

	connection = connman_dbus_get_connection();
	if (connection == NULL)
		return -1;

	return 0;
}

void __connman_agent_cleanup(void)
{
	DBusMessage *message;

	DBG("");

	if (connection == NULL)
		return;

	if (agent_watch > 0)
		g_dbus_remove_watch(connection, agent_watch);

	if (agent_path == NULL)
		return;

	message = dbus_message_new_method_call(agent_sender, agent_path,
					CONNMAN_AGENT_INTERFACE, "Release");
	if (message == NULL)
		return;

	dbus_message_set_no_reply(message, TRUE);

	g_dbus_send_message(connection, message);

	agent_free();

	dbus_connection_unref(connection);
}
