/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2015  Intel Corporation. All rights reserved.
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
#include <string.h>
#include <glib.h>
#include <errno.h>
#include <stdbool.h>
#include <dbus/dbus.h>

#include <gdbus.h>
#include <connman/dbus.h>

static DBusConnection *connection;
static GMainLoop *main_loop;

static gboolean option_version = FALSE;

static GOptionEntry options[] = {
	{ "version", 'v', 0, G_OPTION_ARG_NONE, &option_version,
	  "Show version information and exit" },
	{ NULL },
};

static bool state_online(DBusMessageIter *iter)
{
	char *str;
	DBusMessageIter variant;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_STRING)
		return false;

	dbus_message_iter_get_basic(iter, &str);
	if (strcmp(str, "State"))
		return false;

	dbus_message_iter_next(iter);

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_VARIANT)
		return false;

	dbus_message_iter_recurse(iter, &variant);

	if (dbus_message_iter_get_arg_type(&variant) != DBUS_TYPE_STRING)
		return false;

	dbus_message_iter_get_basic(&variant, &str);
	if (strcmp(str, "ready") && strcmp(str, "online"))
		return false;

	return true;
}

static void manager_properties_online(DBusMessageIter *iter)
{
	DBusMessageIter array, dict_entry;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
		return;

	for (dbus_message_iter_recurse(iter, &array);
	     dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_DICT_ENTRY;
	     dbus_message_iter_next(&array)) {

		dbus_message_iter_recurse(&array, &dict_entry);

		if (state_online(&dict_entry)) {
			g_main_loop_quit(main_loop);
			break;
		}
	}
}

static void manager_get_properties_return(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply;
	DBusMessageIter iter;

	reply = dbus_pending_call_steal_reply(call);
	if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR)
                goto fail;

        if (!dbus_message_iter_init(reply, &iter))
                goto fail;

	manager_properties_online(&iter);

fail:
	dbus_message_unref(reply);
	dbus_pending_call_unref(call);
}

static void manager_get_properties(void)
{
	DBusMessage *message;
	DBusPendingCall *call;

	message = dbus_message_new_method_call(CONNMAN_SERVICE,
					CONNMAN_MANAGER_PATH,
					CONNMAN_MANAGER_INTERFACE,
					"GetProperties");
	if (!message)
		return;

	if (!dbus_connection_send_with_reply(connection, message, &call, -1))
                goto fail;

        if (!call)
                goto fail;

	dbus_pending_call_set_notify(call, manager_get_properties_return,
				NULL, NULL);

fail:
        dbus_message_unref(message);
}

static DBusHandlerResult manager_property_changed(DBusConnection *connection,
                DBusMessage *message, void *user_data)
{
	DBusMessageIter iter;

	if (dbus_message_is_signal(message, CONNMAN_MANAGER_INTERFACE,
					"PropertyChanged")) {
		dbus_message_iter_init(message, &iter);

		if (state_online(&iter))
			g_main_loop_quit(main_loop);
	}

	return DBUS_HANDLER_RESULT_HANDLED;
}

int main(int argc, char *argv[])
{
	const char *filter = "type='signal',interface='"
		CONNMAN_MANAGER_INTERFACE "'";
	int err = 0;
	GError *g_err = NULL;
	DBusError dbus_err;
	GOptionContext *context;

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);

	if (!g_option_context_parse(context, &argc, &argv, &g_err)) {
		if (g_err) {
			fprintf(stderr, "%s\n", g_err->message);
			g_error_free(g_err);
		} else
			fprintf(stderr, "An unknown error occurred\n");

		return EOPNOTSUPP;
	}

        g_option_context_free(context);

        if (option_version) {
		fprintf(stdout, "%s\n", VERSION);
		return 0;
	}

	dbus_error_init(&dbus_err);
	connection = g_dbus_setup_bus(DBUS_BUS_SYSTEM, NULL, &dbus_err);

	if (dbus_error_is_set(&dbus_err)) {
		fprintf(stderr, "Error: %s\n", dbus_err.message);

		err = -ENOPROTOOPT;
		goto fail;
	}

	main_loop = g_main_loop_new(NULL, FALSE);

	dbus_connection_add_filter(connection, manager_property_changed,
				NULL, NULL);

	dbus_bus_add_match(connection, filter, &dbus_err);

	if (dbus_error_is_set(&dbus_err)) {
		fprintf(stderr, "Error: %s\n", dbus_err.message);

		err = -ENOPROTOOPT;
		goto cleanup;
	}

	manager_get_properties();

	g_main_loop_run(main_loop);

cleanup:
	dbus_bus_remove_match(connection, filter, NULL);
	dbus_connection_remove_filter(connection, manager_property_changed,
				NULL);

	dbus_connection_unref(connection);
	g_main_loop_unref(main_loop);

fail:
	dbus_error_free(&dbus_err);

	return -err;
}
