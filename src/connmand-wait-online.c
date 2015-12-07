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
static int timeout = 0;
static int exit_value = 0;

static gboolean option_version = FALSE;
static gchar *option_interface = NULL;
static gchar *option_ignore = NULL;
static gint option_timeout = 120;

struct devices {
	char **interface;
	char **ignore;
};

static GOptionEntry options[] = {
	{ "interface", 'i', 0, G_OPTION_ARG_STRING, &option_interface,
	  "Specify networking device or interface", "DEV" },
	{ "ignore", 'I', 0, G_OPTION_ARG_STRING, &option_ignore,
	  "Specify networking device or interface to ignore", "DEV" },
	{ "timeout", 0, 0, G_OPTION_ARG_INT, &option_timeout,
	  "Time to wait for network going online. Default is 120 seconds.",
	  "seconds" },
	{ "version", 'v', 0, G_OPTION_ARG_NONE, &option_version,
	  "Show version information and exit" },
	{ NULL },
};

static bool compare_interface(const char *interface, struct devices *devices)
{
	int i;

	if (!interface || !devices)
		return false;

	for (i = 0; devices->ignore && devices->ignore[i]; i++)
		if (!strcmp(interface, devices->ignore[i]))
			return false;

	if (!devices->interface)
		return true;

	for (i = 0; devices->interface[i]; i++)
		if (!strcmp(interface, devices->interface[i]))
			return true;

	return false;
}

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

static bool service_properties_online(DBusMessageIter *array_entry,
				struct devices *devices)
{
	bool interface = !devices;
	bool state = false;
	DBusMessageIter dict, dict_entry, variant, eth_array, eth_dict,
		eth_variant;
	char *str;

	for (dbus_message_iter_recurse(array_entry, &dict);
	     dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY;
	     dbus_message_iter_next(&dict)) {

		dbus_message_iter_recurse(&dict, &dict_entry);
		if (dbus_message_iter_get_arg_type(&dict_entry)
				!= DBUS_TYPE_STRING)
			continue;

		if (state_online(&dict_entry)) {
			state = true;
			continue;
		}

		dbus_message_iter_recurse(&dict, &dict_entry);

		dbus_message_iter_get_basic(&dict_entry, &str);

		if (devices && !strcmp(str, "Ethernet")) {
			dbus_message_iter_next(&dict_entry);

			if (dbus_message_iter_get_arg_type(&dict_entry)
					!= DBUS_TYPE_VARIANT)
				break;

			dbus_message_iter_recurse(&dict_entry, &variant);
			if (dbus_message_iter_get_arg_type(&variant)
					!= DBUS_TYPE_ARRAY)
				break;

			for (dbus_message_iter_recurse(&variant, &eth_array);
			     dbus_message_iter_get_arg_type(&eth_array)
				     == DBUS_TYPE_DICT_ENTRY;
			     dbus_message_iter_next(&eth_array)) {

				dbus_message_iter_recurse(&eth_array, &eth_dict);

				if (dbus_message_iter_get_arg_type(&eth_dict)
						!= DBUS_TYPE_STRING)
					continue;

				dbus_message_iter_get_basic(&eth_dict, &str);
				if (!strcmp(str, "Interface")) {

					dbus_message_iter_next(&eth_dict);
					if (dbus_message_iter_get_arg_type(&eth_dict)
							!= DBUS_TYPE_VARIANT)
						break;

					dbus_message_iter_recurse(&eth_dict,
								&eth_variant);
					if (dbus_message_iter_get_arg_type(&eth_variant)
							!= DBUS_TYPE_STRING)
						break;

					dbus_message_iter_get_basic(&eth_variant,
								&str);
					interface = compare_interface(str,
								devices);

					break;
				}
			}
		}

		if (state && interface) {
			g_main_loop_quit(main_loop);
			return true;
		}
	}

	return false;
}

static void services_dict_online(DBusMessageIter *iter, struct devices *devices)
{
	DBusMessageIter array, array_entry;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
		return;

	for (dbus_message_iter_recurse(iter, &array);
	     dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_STRUCT;
	     dbus_message_iter_next(&array)) {

		dbus_message_iter_recurse(&array, &array_entry);

		if (dbus_message_iter_get_arg_type(&array_entry) !=
				DBUS_TYPE_OBJECT_PATH)
			break;

		dbus_message_iter_next(&array_entry);

		if (dbus_message_iter_get_arg_type(&array_entry) !=
				DBUS_TYPE_ARRAY)
			continue;

		if (service_properties_online(&array_entry, devices))
			break;
	}
}

static void manager_get_services_return(DBusPendingCall *call,
					void *user_data)
{
	struct devices *devices = user_data;
	DBusMessage *reply;
	DBusMessageIter iter;

	reply = dbus_pending_call_steal_reply(call);
	if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR)
                goto fail;

        if (!dbus_message_iter_init(reply, &iter))
                goto fail;

	services_dict_online(&iter, devices);

fail:
	dbus_message_unref(reply);
	dbus_pending_call_unref(call);
}

static void manager_get_services(struct devices *devices)
{
	DBusMessage *message;
	DBusPendingCall *call;

	message = dbus_message_new_method_call(CONNMAN_SERVICE,
					CONNMAN_MANAGER_PATH,
					CONNMAN_MANAGER_INTERFACE,
					"GetServices");
	if (!message)
		return;

	if (!dbus_connection_send_with_reply(connection, message, &call, -1))
                goto fail;

        if (!call)
                goto fail;

	dbus_pending_call_set_notify(call, manager_get_services_return,
				devices, NULL);

fail:
        dbus_message_unref(message);
}

static void manager_properties_online(DBusMessageIter *iter,
				struct devices *devices)
{
	DBusMessageIter array, dict_entry;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
		return;

	for (dbus_message_iter_recurse(iter, &array);
	     dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_DICT_ENTRY;
	     dbus_message_iter_next(&array)) {

		dbus_message_iter_recurse(&array, &dict_entry);

		if (state_online(&dict_entry)) {
			if (devices)
				manager_get_services(devices);
			else
				g_main_loop_quit(main_loop);

			break;
		}
	}
}

static void manager_get_properties_return(DBusPendingCall *call, void *user_data)
{
	struct devices *devices = user_data;
	DBusMessage *reply;
	DBusMessageIter iter;

	reply = dbus_pending_call_steal_reply(call);
	if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR)
                goto fail;

        if (!dbus_message_iter_init(reply, &iter))
                goto fail;

	manager_properties_online(&iter, devices);

fail:
	dbus_message_unref(reply);
	dbus_pending_call_unref(call);
}

static void manager_get_properties(struct devices *devices)
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
				devices, NULL);

fail:
        dbus_message_unref(message);
}

static DBusHandlerResult manager_property_changed(DBusConnection *connection,
                DBusMessage *message, void *user_data)
{
	struct devices *devices = user_data;
	DBusMessageIter iter;

	if (dbus_message_is_signal(message, CONNMAN_MANAGER_INTERFACE,
					"PropertyChanged")) {
		dbus_message_iter_init(message, &iter);

		if (state_online(&iter)) {
			if (devices)
				manager_get_services(devices);
			else
				g_main_loop_quit(main_loop);
		}
	}

	return DBUS_HANDLER_RESULT_HANDLED;
}

static gboolean timeout_triggered(gpointer user_data)
{
	exit_value = -ETIMEDOUT;
	g_main_loop_quit(main_loop);
	timeout = 0;

	return FALSE;
}

int main(int argc, char *argv[])
{
	const char *filter = "type='signal',interface='"
		CONNMAN_MANAGER_INTERFACE "'";
	int err = 0;
	GError *g_err = NULL;
	struct devices devices = { NULL, NULL };
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

	if (option_interface) {
		devices.interface = g_strsplit(option_interface, ",", -1);
		g_free(option_interface);
	}

	if (option_ignore) {
		devices.ignore = g_strsplit(option_ignore, ",", -1);
		g_free(option_ignore);
	}

        if (option_version) {
		fprintf(stdout, "%s\n", VERSION);
		goto free;
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
				&devices, NULL);

	dbus_bus_add_match(connection, filter, &dbus_err);

	if (dbus_error_is_set(&dbus_err)) {
		fprintf(stderr, "Error: %s\n", dbus_err.message);

		err = -ENOPROTOOPT;
		goto cleanup;
	}

	if (option_timeout)
		timeout = g_timeout_add_seconds(option_timeout,
						timeout_triggered, NULL);

	manager_get_properties(&devices);

	g_main_loop_run(main_loop);
	err = exit_value;

cleanup:
	dbus_bus_remove_match(connection, filter, NULL);
	dbus_connection_remove_filter(connection, manager_property_changed,
				&devices);

	dbus_connection_unref(connection);
	g_main_loop_unref(main_loop);

fail:
	dbus_error_free(&dbus_err);
free:
	g_strfreev(devices.interface);
	g_strfreev(devices.ignore);
	if (timeout)
		g_source_remove(timeout);

	return -err;
}
