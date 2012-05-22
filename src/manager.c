/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2012  Intel Corporation. All rights reserved.
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

#include "connman.h"

static connman_bool_t connman_state_idle;
static DBusMessage *session_mode_pending = NULL;

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	DBusMessageIter array, dict;
	connman_bool_t offlinemode, sessionmode;
	const char *str;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &array);

	connman_dbus_dict_open(&array, &dict);

	str = __connman_notifier_get_state();
	connman_dbus_dict_append_basic(&dict, "State",
						DBUS_TYPE_STRING, &str);

	offlinemode = __connman_technology_get_offlinemode();
	connman_dbus_dict_append_basic(&dict, "OfflineMode",
					DBUS_TYPE_BOOLEAN, &offlinemode);

	sessionmode = __connman_session_mode();
	connman_dbus_dict_append_basic(&dict, "SessionMode",
					DBUS_TYPE_BOOLEAN,
					&sessionmode);

	connman_dbus_dict_close(&array, &dict);

	return reply;
}

static DBusMessage *set_property(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessageIter iter, value;
	const char *name;
	int type;

	DBG("conn %p", conn);

	if (dbus_message_iter_init(msg, &iter) == FALSE)
		return __connman_error_invalid_arguments(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &name);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_recurse(&iter, &value);

	type = dbus_message_iter_get_arg_type(&value);

	if (g_str_equal(name, "OfflineMode") == TRUE) {
		connman_bool_t offlinemode;

		if (type != DBUS_TYPE_BOOLEAN)
			return __connman_error_invalid_arguments(msg);

		dbus_message_iter_get_basic(&value, &offlinemode);

		__connman_technology_set_offlinemode(offlinemode);
	} else if (g_str_equal(name, "SessionMode") == TRUE) {
		connman_bool_t sessionmode;

		if (type != DBUS_TYPE_BOOLEAN)
			return __connman_error_invalid_arguments(msg);

		dbus_message_iter_get_basic(&value, &sessionmode);

		if (session_mode_pending != NULL)
			return __connman_error_in_progress(msg);

		__connman_session_set_mode(sessionmode);

		if (sessionmode == TRUE && connman_state_idle == FALSE) {
			session_mode_pending = msg;
			return NULL;
		}

	} else
		return __connman_error_invalid_property(msg);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static void append_technology_structs(DBusMessageIter *iter, void *user_data)
{
	__connman_technology_list_struct(iter);
}

static DBusMessage *get_technologies(DBusConnection *conn,
		DBusMessage *msg, void *data)
{
	DBusMessage *reply;

	DBG("");

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	__connman_dbus_append_objpath_dict_array(reply,
			append_technology_structs, NULL);

	return reply;
}

static DBusMessage *remove_provider(DBusConnection *conn,
				    DBusMessage *msg, void *data)
{
	const char *path;
	int err;

	DBG("conn %p", conn);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID);

	err = __connman_provider_remove(path);
	if (err < 0)
		return __connman_error_failed(msg, -err);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusConnection *connection = NULL;

static void session_mode_notify(void)
{
	DBusMessage *reply;

	reply = g_dbus_create_reply(session_mode_pending, DBUS_TYPE_INVALID);
	g_dbus_send_message(connection, reply);

	dbus_message_unref(session_mode_pending);
	session_mode_pending = NULL;
}

static void idle_state(connman_bool_t idle)
{

	DBG("idle %d", idle);

	connman_state_idle = idle;

	if (connman_state_idle == FALSE || session_mode_pending == NULL)
		return;

	session_mode_notify();
}

static struct connman_notifier technology_notifier = {
	.name		= "manager",
	.priority	= CONNMAN_NOTIFIER_PRIORITY_HIGH,
	.idle_state	= idle_state,
};

static void append_service_structs(DBusMessageIter *iter, void *user_data)
{
	__connman_service_list_struct(iter);
}

static DBusMessage *get_services(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	__connman_dbus_append_objpath_dict_array(reply,
			append_service_structs, NULL);

	return reply;
}

static DBusMessage *connect_provider(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	int err;

	DBG("conn %p", conn);

	if (__connman_session_mode() == TRUE) {
		connman_info("Session mode enabled: "
				"direct provider connect disabled");

		return __connman_error_failed(msg, -EINVAL);
	}

	err = __connman_provider_create_and_connect(msg);
	if (err < 0) {
		if (err == -EINPROGRESS) {
			connman_error("Invalid return code from connect");
			err = -EINVAL;
		}

		return __connman_error_failed(msg, -err);
	}

	return NULL;
}

static DBusMessage *register_agent(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *sender, *path;
	int err;

	DBG("conn %p", conn);

	sender = dbus_message_get_sender(msg);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID);

	err = __connman_agent_register(sender, path);
	if (err < 0)
		return __connman_error_failed(msg, -err);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *unregister_agent(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *sender, *path;
	int err;

	DBG("conn %p", conn);

	sender = dbus_message_get_sender(msg);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID);

	err = __connman_agent_unregister(sender, path);
	if (err < 0)
		return __connman_error_failed(msg, -err);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *register_counter(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *sender, *path;
	unsigned int accuracy, period;
	int err;

	DBG("conn %p", conn);

	sender = dbus_message_get_sender(msg);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
						DBUS_TYPE_UINT32, &accuracy,
						DBUS_TYPE_UINT32, &period,
							DBUS_TYPE_INVALID);

	/* FIXME: add handling of accuracy parameter */

	err = __connman_counter_register(sender, path, period);
	if (err < 0)
		return __connman_error_failed(msg, -err);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *unregister_counter(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *sender, *path;
	int err;

	DBG("conn %p", conn);

	sender = dbus_message_get_sender(msg);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID);

	err = __connman_counter_unregister(sender, path);
	if (err < 0)
		return __connman_error_failed(msg, -err);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *create_session(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	int err;

	DBG("conn %p", conn);

	err = __connman_session_create(msg);
	if (err < 0)
		return __connman_error_failed(msg, -err);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *destroy_session(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	int err;

	DBG("conn %p", conn);

	err = __connman_session_destroy(msg);
	if (err < 0)
		return __connman_error_failed(msg, -err);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *request_private_network(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *sender;
	int  err;

	DBG("conn %p", conn);

	sender = dbus_message_get_sender(msg);

	err = __connman_private_network_request(msg, sender);
	if (err < 0)
		return __connman_error_failed(msg, -err);

	return NULL;
}

static DBusMessage *release_private_network(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *path;
	int err;

	DBG("conn %p", conn);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID);

	err = __connman_private_network_release(path);
	if (err < 0)
		return __connman_error_failed(msg, -err);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static const GDBusMethodTable manager_methods[] = {
	{ GDBUS_METHOD("GetProperties",
			NULL, GDBUS_ARGS({ "properties", "a{sv}" }),
			get_properties) },
	{ GDBUS_ASYNC_METHOD("SetProperty",
			GDBUS_ARGS({ "name", "s" }, { "value", "v" }),
			NULL, set_property) },
	{ GDBUS_METHOD("GetTechnologies",
			NULL, GDBUS_ARGS({ "technologies", "a(oa{sv})" }),
			get_technologies) },
	{ GDBUS_METHOD("RemoveProvider",
			GDBUS_ARGS({ "provider", "o" }), NULL,
			remove_provider) },
	{ GDBUS_METHOD("GetServices",
			NULL, GDBUS_ARGS({ "services", "a(oa{sv})" }),
			get_services) },
	{ GDBUS_ASYNC_METHOD("ConnectProvider",
			      GDBUS_ARGS({ "provider", "a{sv}" }),
			      GDBUS_ARGS({ "path", "o" }),
			      connect_provider) },
	{ GDBUS_METHOD("RegisterAgent",
			GDBUS_ARGS({ "path", "o" }), NULL,
			register_agent) },
	{ GDBUS_METHOD("UnregisterAgent",
			GDBUS_ARGS({ "path", "o" }), NULL,
			unregister_agent) },
	{ GDBUS_METHOD("RegisterCounter",
			GDBUS_ARGS({ "path", "o" }, { "accuracy", "u" },
					{ "period", "u" }),
			NULL, register_counter) },
	{ GDBUS_METHOD("UnregisterCounter",
			GDBUS_ARGS({ "path", "o" }), NULL,
			unregister_counter) },
	{ GDBUS_METHOD("CreateSession",
			GDBUS_ARGS({ "settings", "a{sv}" },
						{ "notifier", "o" }),
			GDBUS_ARGS({ "session", "o" }),
			create_session) },
	{ GDBUS_METHOD("DestroySession",
			GDBUS_ARGS({ "session", "o" }), NULL,
			destroy_session) },
	{ GDBUS_ASYNC_METHOD("RequestPrivateNetwork",
			      NULL, GDBUS_ARGS({ "path", "o" },
					       { "settings", "a{sv}" },
					       { "socket", "h" }),
			      request_private_network) },
	{ GDBUS_METHOD("ReleasePrivateNetwork",
			GDBUS_ARGS({ "path", "o" }), NULL,
			release_private_network) },
	{ },
};

static const GDBusSignalTable manager_signals[] = {
	{ GDBUS_SIGNAL("PropertyChanged",
			GDBUS_ARGS({ "name", "s" }, { "value", "v" })) },
	{ GDBUS_SIGNAL("TechnologyAdded",
			GDBUS_ARGS({ "path", "o" },
				   { "properties", "a{sv}" })) },
	{ GDBUS_SIGNAL("TechnologyRemoved",
			GDBUS_ARGS({ "path", "o" })) },
	{ GDBUS_SIGNAL("ServicesChanged",
			GDBUS_ARGS({ "changed", "a(oa{sv})" },
					{ "removed", "ao" })) },
	{ },
};

int __connman_manager_init(void)
{
	DBG("");

	connection = connman_dbus_get_connection();
	if (connection == NULL)
		return -1;

	if (connman_notifier_register(&technology_notifier) < 0)
		connman_error("Failed to register technology notifier");

	g_dbus_register_interface(connection, CONNMAN_MANAGER_PATH,
					CONNMAN_MANAGER_INTERFACE,
					manager_methods,
					manager_signals, NULL, NULL, NULL);

	connman_state_idle = TRUE;

	return 0;
}

void __connman_manager_cleanup(void)
{
	DBG("");

	if (connection == NULL)
		return;

	connman_notifier_unregister(&technology_notifier);

	g_dbus_unregister_interface(connection, CONNMAN_MANAGER_PATH,
						CONNMAN_MANAGER_INTERFACE);

	dbus_connection_unref(connection);
}
