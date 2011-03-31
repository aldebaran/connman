/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2010  Intel Corporation. All rights reserved.
 *  Copyright (C) 2011  BWM CarIT GmbH. All rights reserved.
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

#include "connman.h"

static DBusConnection *connection;
static GHashTable *session_hash;
static connman_bool_t sessionmode;

struct connman_session {
	char *owner;
	char *session_path;
	char *notify_path;
	guint notify_watch;
};

static gboolean session_notify_all(gpointer user_data)
{
	struct connman_session *session = user_data;
	DBusMessage *msg;
	DBusMessageIter array, dict;

	DBG("session %p owner %s notify_path %s", session,
		session->owner, session->notify_path);

	msg = dbus_message_new_method_call(session->owner, session->notify_path,
						CONNMAN_NOTIFICATION_INTERFACE,
						"Update");
	if (msg == NULL) {
		connman_error("Could not create notification message");
		return FALSE;
	}

	dbus_message_iter_init_append(msg, &array);

	connman_dbus_dict_open(&array, &dict);

	/* append settings */

	connman_dbus_dict_close(&array, &dict);

	g_dbus_send_message(connection, msg);

	return FALSE;
}

static void cleanup_session(gpointer user_data)
{
	struct connman_session *session = user_data;

	DBG("remove %s", session->session_path);

	g_free(session->owner);
	g_free(session->session_path);
	g_free(session->notify_path);

	g_free(session);
}

static void release_session(gpointer key, gpointer value, gpointer user_data)
{
	struct connman_session *session = value;
	DBusMessage *message;

	DBG("owner %s path %s", session->owner, session->notify_path);

	if (session->notify_watch > 0)
		g_dbus_remove_watch(connection, session->notify_watch);

	g_dbus_unregister_interface(connection, session->session_path,
						CONNMAN_SESSION_INTERFACE);

	message = dbus_message_new_method_call(session->owner,
						session->notify_path,
						CONNMAN_NOTIFICATION_INTERFACE,
						"Release");
	if (message == NULL)
		return;

	dbus_message_set_no_reply(message, TRUE);

	g_dbus_send_message(connection, message);
}

static int session_disconnect(struct connman_session *session)
{
	DBG("session %p, %s", session, session->owner);

	if (session->notify_watch > 0)
		g_dbus_remove_watch(connection, session->notify_watch);

	g_dbus_unregister_interface(connection, session->session_path,
						CONNMAN_SESSION_INTERFACE);

	g_hash_table_remove(session_hash, session->session_path);

	return 0;
}

static void owner_disconnect(DBusConnection *conn, void *user_data)
{
	struct connman_session *session = user_data;

	DBG("session %p, %s died", session, session->owner);

	session_disconnect(session);
}

static DBusMessage *destroy_session(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_session *session = user_data;

	DBG("session %p", session);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *connect_session(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_session *session = user_data;

	DBG("session %p", session);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *disconnect_session(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_session *session = user_data;

	DBG("session %p", session);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *change_session(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_session *session = user_data;

	DBG("session %p", session);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static GDBusMethodTable session_methods[] = {
	{ "Destroy",    "",   "", destroy_session    },
	{ "Connect",    "",   "", connect_session    },
	{ "Disconnect", "",   "", disconnect_session },
	{ "Change",     "sv", "", change_session     },
	{ },
};

int __connman_session_create(DBusMessage *msg)
{
	const char *owner, *notify_path;
	char *session_path;
	DBusMessageIter iter, array;
	struct connman_session *session;
	int err;

	owner = dbus_message_get_sender(msg);

	DBG("owner %s", owner);

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_recurse(&iter, &array);

	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_DICT_ENTRY)
		dbus_message_iter_next(&array);

	dbus_message_iter_next(&iter);
	dbus_message_iter_get_basic(&iter, &notify_path);

	if (notify_path == NULL) {
		session_path = NULL;
		err = -EINVAL;
		goto err;
	}

	session_path = g_strdup_printf("/sessions%s", notify_path);
	if (session_path == NULL) {
		err = -ENOMEM;
		goto err;
	}

	session = g_hash_table_lookup(session_hash, session_path);
	if (session != NULL) {
		err = -EEXIST;
		goto err;
	}

	session = g_try_new0(struct connman_session, 1);
	if (session == NULL) {
		err = -ENOMEM;
		goto err;
	}

	session->owner = g_strdup(owner);
	session->session_path = session_path;
	session->notify_path = g_strdup(notify_path);
	session->notify_watch =
		g_dbus_add_disconnect_watch(connection, session->owner,
					owner_disconnect, session, NULL);

	g_hash_table_replace(session_hash, session->session_path, session);

	DBG("add %s", session->session_path);

	if (g_dbus_register_interface(connection, session->session_path,
					CONNMAN_SESSION_INTERFACE,
					session_methods, NULL,
					NULL, session, NULL) == FALSE) {
		connman_error("Failed to register %s", session->session_path);
		g_hash_table_remove(session_hash, session->session_path);
		session = NULL;

		err = -EINVAL;
		goto err;
	}

	g_dbus_send_reply(connection, msg,
				DBUS_TYPE_OBJECT_PATH, &session->session_path,
				DBUS_TYPE_INVALID);

	g_timeout_add_seconds(0, session_notify_all, session);

	return 0;

err:
	connman_error("Failed to create session");
	g_free(session_path);

	return err;
}

int __connman_session_destroy(DBusMessage *msg)
{
	const char *owner, *session_path;
	struct connman_session *session;

	owner = dbus_message_get_sender(msg);

	DBG("owner %s", owner);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &session_path,
							DBUS_TYPE_INVALID);
	if (session_path == NULL)
		return -EINVAL;

	session = g_hash_table_lookup(session_hash, session_path);
	if (session == NULL)
		return -EINVAL;

	if (g_strcmp0(owner, session->owner) != 0)
		return -EACCES;

	session_disconnect(session);

	return 0;
}

connman_bool_t __connman_session_mode()
{
	return sessionmode;
}

void __connman_session_set_mode(connman_bool_t enable)
{
	DBG("enable %d", enable);

	if (sessionmode == enable)
		return;

	sessionmode = enable;

	if (sessionmode == TRUE)
		__connman_service_disconnect_all();
}

int __connman_session_init(void)
{
	DBG("");

	connection = connman_dbus_get_connection();
	if (connection == NULL)
		return -1;

	session_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						NULL, cleanup_session);

	sessionmode = FALSE;
	return 0;
}

void __connman_session_cleanup(void)
{
	DBG("");

	if (connection == NULL)
		return;

	g_hash_table_foreach(session_hash, release_session, NULL);
	g_hash_table_destroy(session_hash);

	dbus_connection_unref(connection);
}
