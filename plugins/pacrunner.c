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

#include <gdbus.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/notifier.h>
#include <connman/dbus.h>
#include <connman/log.h>

#define PACRUNNER_SERVICE	"org.pacrunner"
#define PACRUNNER_INTERFACE	"org.pacrunner.Manager"
#define PACRUNNER_PATH		"/org/pacrunner/manager"

#define DBUS_TIMEOUT	5000

static DBusConnection *connection;

static struct connman_service *default_service = NULL;
static char *current_config = NULL;

static void create_config_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	const char *path;

	DBG("");

	if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR) {
		connman_error("Failed to create proxy configuration");
		goto done;
	}

	if (dbus_message_get_args(reply, NULL, DBUS_TYPE_OBJECT_PATH, &path,
						DBUS_TYPE_INVALID) == FALSE)
		goto done;

	g_free(current_config);
	current_config = g_strdup(path);

done:
	dbus_message_unref(reply);
}

static void add_string_entry(DBusMessageIter *iter,
					const char *key, const char *str)
{
	DBusMessageIter value;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &key);

	dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT,
					DBUS_TYPE_STRING_AS_STRING, &value);
	dbus_message_iter_append_basic(&value, DBUS_TYPE_STRING, &str);
	dbus_message_iter_close_container(iter, &value);
}

static void create_proxy_configuration(const char *interface, const char *url)
{
	DBusMessage *msg;
	DBusMessageIter iter, dict, entry;
	DBusPendingCall *call;
	dbus_bool_t result;

	if (url == NULL)
		return;

	DBG("interface %s url %s", interface, url);

	msg = dbus_message_new_method_call(PACRUNNER_SERVICE, PACRUNNER_PATH,
			PACRUNNER_INTERFACE, "CreateProxyConfiguration");
	if (msg == NULL)
		return;

	dbus_message_set_auto_start(msg, FALSE);

	dbus_message_iter_init_append(msg, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);
        dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY,
								NULL, &entry);

	if (interface != NULL)
		add_string_entry(&entry, "Interface", interface);

	add_string_entry(&entry, "URL", url);

	dbus_message_iter_close_container(&dict, &entry);
	dbus_message_iter_close_container(&iter, &dict);

	result = dbus_connection_send_with_reply(connection, msg,
							&call, DBUS_TIMEOUT);

	dbus_message_unref(msg);

	if (result == FALSE || call == NULL)
		return;

	dbus_pending_call_set_notify(call, create_config_reply, NULL, NULL);

	dbus_pending_call_unref(call);
}

static void destroy_config_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);

	DBG("");

	if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR)
		connman_error("Failed to destoy proxy configuration");

	dbus_message_unref(reply);
}

static void destroy_proxy_configuration(void)
{
	DBusMessage *msg;
	DBusPendingCall *call;
	dbus_bool_t result;

	if (current_config == NULL)
		return;

	DBG("");

	msg = dbus_message_new_method_call(PACRUNNER_SERVICE, PACRUNNER_PATH,
			PACRUNNER_INTERFACE, "DestroyProxyConfiguration");
	if (msg == NULL)
		return;

	dbus_message_set_auto_start(msg, FALSE);

	dbus_message_append_args(msg, DBUS_TYPE_OBJECT_PATH, &current_config,
							DBUS_TYPE_INVALID);

	result = dbus_connection_send_with_reply(connection, msg,
							&call, DBUS_TIMEOUT);

	dbus_message_unref(msg);

	if (result == FALSE || call == NULL)
		return;

	dbus_pending_call_set_notify(call, destroy_config_reply, NULL, NULL);

	dbus_pending_call_unref(call);

	g_free(current_config);
	current_config = NULL;
}

static void default_service_changed(struct connman_service *service)
{
	char *interface;
	const char *url;

	DBG("service %p", service);

	if (service == default_service)
		return;

	default_service = service;

	destroy_proxy_configuration();

	interface = connman_service_get_interface(service);

	url = connman_service_get_proxy_autoconfig(service);
	create_proxy_configuration(interface, url);

	g_free(interface);
}

static struct connman_notifier pacrunner_notifier = {
	.name			= "pacrunner",
	.default_changed	= default_service_changed,
};

static void pacrunner_connect(DBusConnection *conn, void *user_data)
{
	char *interface;
	const char *url;

	DBG("");

	interface = connman_service_get_interface(default_service);

	url = connman_service_get_proxy_autoconfig(default_service);
	create_proxy_configuration(interface, url);

	g_free(interface);
}

static void pacrunner_disconnect(DBusConnection *conn, void *user_data)
{
	DBG("");

	g_free(current_config);
	current_config = NULL;
}

static guint pacrunner_watch;

static int pacrunner_init(void)
{
	connection = connman_dbus_get_connection();
	if (connection == NULL)
		return -EIO;

	pacrunner_watch = g_dbus_add_service_watch(connection,
					PACRUNNER_SERVICE, pacrunner_connect,
					pacrunner_disconnect, NULL, NULL);
	if (pacrunner_watch == 0) {
		dbus_connection_unref(connection);
		return -EIO;
	}

	connman_notifier_register(&pacrunner_notifier);

	return 0;
}

static void pacrunner_exit(void)
{
	connman_notifier_unregister(&pacrunner_notifier);

	g_dbus_remove_watch(connection, pacrunner_watch);

	destroy_proxy_configuration();

	dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE(pacrunner, "PAC runner proxy plugin", VERSION,
		CONNMAN_PLUGIN_PRIORITY_DEFAULT, pacrunner_init, pacrunner_exit)
