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

#include <stdio.h>

#include "gdbus/gdbus.h"

#include "test-connman.h"

static connman_bool_t is_connman_running(DBusConnection *connection)
{
	DBusError error;
	connman_bool_t running;

	dbus_error_init(&error);

	running = dbus_bus_name_has_owner(connection, CONNMAN_SERVICE, &error);

	if (dbus_error_is_set(&error) == TRUE) {
		fprintf(stderr, "%s\n", error.message);
		dbus_error_free(&error);

		return FALSE;
	}

	return running;
}

static gboolean test_session_create_no_notify(gpointer data)
{
	struct test_fix *fix = data;
	DBusMessage *msg;

	util_session_create(fix, 1);

	msg = manager_create_session(fix->session->connection,
					fix->session->info, "/foo");
	g_assert(msg != NULL);
	g_assert(dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_ERROR);

	dbus_message_unref(msg);

	g_assert(is_connman_running(fix->session->connection) == TRUE);
	util_idle_call(fix, util_quit_loop, util_session_destroy);

	return FALSE;
}

static gboolean test_session_destroy_no_notify(gpointer data)
{
	struct test_fix *fix = data;
	DBusMessage *msg;

	util_session_create(fix, 1);

	msg = manager_destroy_session(fix->session->connection, "/foo");
	g_assert(msg == NULL);

	g_assert(is_connman_running(fix->session->connection) == TRUE);
	util_idle_call(fix, util_quit_loop, util_session_destroy);

	return FALSE;
}

static void test_session_create_notify(struct test_session *session)
{
	LOG("session %p", session);

	g_assert(is_connman_running(session->connection) == TRUE);
	util_idle_call(session->fix, util_quit_loop, util_session_destroy);
}

static gboolean test_session_create(gpointer data)
{
	struct test_fix *fix = data;
	struct test_session *session;
	DBusMessage *msg;
	int err;

	util_session_create(fix, 1);
	session = fix->session;

	session->notify_path = "/foo";
	session->notify = test_session_create_notify;

	err = session_notify_register(session, session->notify_path);
	g_assert(err == 0);

	msg = manager_create_session(session->connection,
					session->info,
					session->notify_path);
	g_assert(msg != NULL);
	g_assert(dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_ERROR);

	dbus_message_unref(msg);

	return FALSE;
}

static void set_session_mode(struct test_fix *fix,
					connman_bool_t enable)
{
	DBusMessage *msg;

	msg = manager_set_session_mode(fix->main_connection, enable);
	g_assert(msg != NULL);
	g_assert(dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_ERROR);

	dbus_message_unref(msg);

	util_idle_call(fix, util_quit_loop, NULL);
}

static gboolean enable_session_mode(gpointer data)
{
	struct test_fix *fix = data;

	set_session_mode(fix, TRUE);

	return FALSE;
}

static gboolean disable_session_mode(gpointer data)
{
	struct test_fix *fix = data;

	set_session_mode(fix, FALSE);

	return FALSE;
}

static void setup_cb(struct test_fix *fix, gconstpointer data)
{
	util_setup(fix, data);

	util_call(fix, enable_session_mode, NULL);
	g_main_loop_run(fix->main_loop);
}

static void teardown_cb(struct test_fix *fix, gconstpointer data)
{
	util_call(fix, disable_session_mode, NULL);
	g_main_loop_run(fix->main_loop);

	util_teardown(fix, data);
}

int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);

	util_test_add("/manager/session create no notify",
		test_session_create_no_notify, setup_cb, teardown_cb);
	util_test_add("/manager/session destroy no notify",
		test_session_destroy_no_notify, setup_cb, teardown_cb);
	util_test_add("/manager/session create",
		test_session_create, setup_cb, teardown_cb);

	return g_test_run();
}
