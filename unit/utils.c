/*
 *
 *  Connection Manager
 *
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

#include <stdlib.h>

#include "gdbus/gdbus.h"

#include "test-connman.h"

#define ENABLE_WRAPPER 1
#define PROPERTY_CHANGED		"PropertyChanged"

gboolean util_quit_loop(gpointer data)
{
	struct test_fix *fix = data;

	g_main_loop_quit(fix->main_loop);

	return FALSE;
}

guint util_idle_call(struct test_fix *fix, GSourceFunc func,
			GDestroyNotify notify)
{
	GSource *source;
	guint id;

	source = g_idle_source_new();
	g_source_set_callback(source, func, fix, notify);
	id = g_source_attach(source, g_main_loop_get_context(fix->main_loop));
	g_source_unref(source);

	return id;
}

static void connman_died(DBusConnection *connection, void *user_data)
{
	g_assert(FALSE);
}

static void manager_changed(struct test_fix *fix,
					DBusMessageIter *entry)
{
	DBusMessageIter iter;
	const char *key;
	const char *value;
	int type;

	dbus_message_iter_get_basic(entry, &key);

	LOG("key %s", key);

	dbus_message_iter_next(entry);

	dbus_message_iter_recurse(entry, &iter);

	type = dbus_message_iter_get_arg_type(&iter);

	if (type != DBUS_TYPE_STRING)
		return;

	dbus_message_iter_get_basic(&iter, &value);

	if (g_str_equal(key, "State") == TRUE) {
		LOG("State %s", value);

		if (fix->manager.state != NULL)
			g_free(fix->manager.state);

		fix->manager.state = g_strdup(value);
	}

	if (fix->manager_changed != NULL)
		fix->manager_changed(fix);
}

static gboolean handle_manager_changed(DBusConnection *connection,
				DBusMessage *message,
				void *user_data)
{
	struct test_fix *fix = user_data;

	DBusMessageIter iter;

	if (dbus_message_iter_init(message, &iter))
		manager_changed(fix, &iter);

	return TRUE;
}

guint util_call(struct test_fix *fix, GSourceFunc func,
		GDestroyNotify notify)
{
	GSource *source;
	guint id;

	source = g_timeout_source_new(0);
	g_source_set_callback(source, func, fix, notify);
	id = g_source_attach(source, g_main_loop_get_context(fix->main_loop));
	g_source_unref(source);

	return id;
}

void util_setup(struct test_fix *fix, gconstpointer data)
{
	DBusMessage *msg;

	fix->main_loop = g_main_loop_new(NULL, FALSE);
	fix->main_connection = g_dbus_setup_private(DBUS_BUS_SYSTEM,
							NULL, NULL);
	fix->watch = g_dbus_add_service_watch(fix->main_connection,
						CONNMAN_SERVICE,
						NULL,
						connman_died,
						NULL, NULL);
	fix->manager_watch = g_dbus_add_signal_watch(fix->main_connection,
						CONNMAN_SERVICE, NULL,
						CONNMAN_MANAGER_INTERFACE,
						PROPERTY_CHANGED,
						handle_manager_changed,
						fix, NULL);

	msg = manager_get_properties(fix->main_connection);
	manager_parse_properties(msg, &fix->manager);
	dbus_message_unref(msg);
}

void util_teardown(struct test_fix *fix, gconstpointer data)
{
	g_dbus_remove_watch(fix->main_connection, fix->watch);
	g_dbus_remove_watch(fix->main_connection, fix->manager_watch);
	dbus_connection_close(fix->main_connection);
	dbus_connection_unref(fix->main_connection);

	g_main_loop_unref(fix->main_loop);
}

static void util_wrapper(struct test_fix *fix, gconstpointer data)
{
	GSourceFunc func = data;
#if ENABLE_WRAPPER
	if (g_test_trap_fork(60 * 1000 * 1000, 0) == TRUE) {
		util_call(fix, func, NULL);
		g_main_loop_run(fix->main_loop);
		exit(0);
	}

	g_test_trap_assert_passed();
#else
	util_call(fix, func, NULL);
	g_main_loop_run(fix->main_loop);
#endif
}

void util_test_add(const char *test_name, GSourceFunc test_func,
			util_test_setup_cb setup_cb,
			util_test_teardown_cb teardown_cb)
{
	g_test_add(test_name, struct test_fix, test_func,
		setup_cb, util_wrapper, teardown_cb);
}

void util_session_create(struct test_fix *fix, unsigned int max_sessions)
{
	unsigned int i;

	fix->max_sessions = max_sessions;
	fix->session = g_try_new0(struct test_session, max_sessions);

	for (i = 0; i < max_sessions; i++) {
		fix->session[i].fix = fix;
		fix->session[i].info = g_try_new0(struct test_session_info, 1);
		fix->session[i].connection = g_dbus_setup_private(
						DBUS_BUS_SYSTEM, NULL, NULL);
	}
}

void util_session_destroy(gpointer data)
{
	struct test_fix *fix = data;

	unsigned int i;

	for (i = 0; i < fix->max_sessions; i++) {
		dbus_connection_close(fix->session[i].connection);
		g_free(fix->session[i].info);
	}

	g_free(fix->session);
}

void util_session_init(struct test_session *session)
{
	DBusMessage *msg;
	DBusMessageIter iter;
	const char *path;
	int err;

	err = session_notify_register(session, session->notify_path);
	g_assert(err == 0);

	msg = manager_create_session(session->connection,
					session->info,
					session->notify_path);
	g_assert(msg != NULL);
	dbus_message_iter_init(msg, &iter);

	dbus_message_iter_get_basic(&iter, &path);
	session->session_path = g_strdup(path);

	dbus_message_unref(msg);
}

void util_session_cleanup(struct test_session *session)
{
	DBusMessage *msg;
	int err;

	msg = manager_destroy_session(session->connection,
					session->session_path);
	g_assert(msg != NULL);
	dbus_message_unref(msg);

	err = session_notify_unregister(session,
					session->notify_path);
	g_assert(err == 0);

	g_free(session->info->bearer);
	g_free(session->info->name);
	g_free(session->info->interface);
	g_slist_foreach(session->info->allowed_bearers,
			bearer_info_cleanup, NULL);
	g_slist_free(session->info->allowed_bearers);

	session->notify = NULL;
	g_free(session->notify_path);
	g_free(session->session_path);
}
