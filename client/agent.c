/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2013  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
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
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>

#include <gdbus.h>

#include "input.h"
#include "dbus_helpers.h"
#include "agent.h"

static bool agent_registered = false;
static DBusMessage *agent_message = NULL;
static struct {
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;
} agent_reply = { };

#define AGENT_INTERFACE      "net.connman.Agent"

static void request_input_ssid_return(char *input);
static void request_input_passphrase_return(char *input);
static void request_input_string_return(char *input);

static int confirm_input(char *input)
{
	int i;

	if (input == NULL)
		return -1;

	for (i = 0; input[i] != '\0'; i++)
		if (isspace(input[i]) == 0)
			break;

	if (strcasecmp(&input[i], "yes") == 0 ||
			strcasecmp(&input[i], "y") == 0)
		return 1;

	if (strcasecmp(&input[i], "no") == 0 ||
			strcasecmp(&input[i], "n") == 0)
		return 0;

	return -1;
}

static char *strip_path(char *path)
{
	char *name = strrchr(path, '/');
	if (name != NULL)
		name++;
	else
		name = path;

	return name;
}

static char *agent_path(void)
{
	static char *path = NULL;

	if (path == NULL)
		path = g_strdup_printf("/net/connman/connmanctl%d", getpid());

	return path;
}

static void pending_message_remove()
{
	if (agent_message != NULL) {
		dbus_message_unref(agent_message);
		agent_message = NULL;
	}

	if (agent_reply.reply != NULL) {
		dbus_message_unref(agent_reply.reply);
		agent_reply.reply = NULL;
	}
}

static void pending_command_complete(char *message)
{
	__connmanctl_save_rl();

	fprintf(stdout, "%s", message);

	__connmanctl_redraw_rl();

	if (__connmanctl_is_interactive() == true)
		__connmanctl_command_mode();
	else
		__connmanctl_agent_mode("", NULL);
}

static DBusMessage *agent_release(DBusConnection *connection,
		DBusMessage *message, void *user_data)
{
	g_dbus_unregister_interface(connection, agent_path(), AGENT_INTERFACE);
	agent_registered = false;

	pending_message_remove();
	pending_command_complete("Agent unregistered by ConnMan\n");

	if (__connmanctl_is_interactive() == false)
		__connmanctl_quit();

	return dbus_message_new_method_return(message);
}

static DBusMessage *agent_cancel(DBusConnection *connection,
		DBusMessage *message, void *user_data)
{
	pending_message_remove();
	pending_command_complete("Agent request cancelled by ConnMan\n");

	return dbus_message_new_method_return(message);
}

static DBusConnection *agent_connection = NULL;

static void request_browser_return(char *input)
{
	switch (confirm_input(input)) {
	case 1:
		g_dbus_send_reply(agent_connection, agent_message,
				DBUS_TYPE_INVALID);
		break;
	case 0:
		g_dbus_send_error(agent_connection, agent_message,
				"net.connman.Agent.Error.Canceled", NULL);
		break;
	default:
		return;
	}

	pending_message_remove();
	pending_command_complete("");
}

static DBusMessage *agent_request_browser(DBusConnection *connection,
		DBusMessage *message, void *user_data)
{
	DBusMessageIter iter;
	char *service, *url;

	dbus_message_iter_init(message, &iter);

	dbus_message_iter_get_basic(&iter, &service);
	dbus_message_iter_next(&iter);
	dbus_message_iter_get_basic(&iter, &url);

	__connmanctl_save_rl();
	fprintf(stdout, "Agent RequestBrowser %s\n", strip_path(service));
	fprintf(stdout, "  %s\n", url);
	__connmanctl_redraw_rl();

	agent_connection = connection;
	agent_message = dbus_message_ref(message);
	__connmanctl_agent_mode("Connected (yes/no)? ",
			request_browser_return);

	return NULL;
}

static void report_error_return(char *input)
{
	switch (confirm_input(input)) {
	case 1:
		g_dbus_send_error(agent_connection, agent_message,
				"net.connman.Agent.Error.Retry", NULL);
		break;
	case 0:
		g_dbus_send_reply(agent_connection, agent_message,
				DBUS_TYPE_INVALID);
		break;
	default:
		return;
	}

	pending_message_remove();
	pending_command_complete("");
}

static DBusMessage *agent_report_error(DBusConnection *connection,
		DBusMessage *message, void *user_data)
{
	DBusMessageIter iter;
	char *path, *service, *error;

	dbus_message_iter_init(message, &iter);

	dbus_message_iter_get_basic(&iter, &path);
	service = strip_path(path);

	dbus_message_iter_next(&iter);
	dbus_message_iter_get_basic(&iter, &error);

	__connmanctl_save_rl();
	fprintf(stdout, "Agent ReportError %s\n", service);
	fprintf(stdout, "  %s\n", error);
	__connmanctl_redraw_rl();

	agent_connection = connection;
	agent_message = dbus_message_ref(message);
	__connmanctl_agent_mode("Retry (yes/no)? ", report_error_return);

	return NULL;
}

enum requestinput {
	SSID                    = 0,
	IDENTITY                = 1,
	PASSPHRASE              = 2,
	WPS                     = 3,
	WISPR_USERNAME          = 4,
	WISPR_PASSPHRASE        = 5,
	REQUEST_INPUT_MAX       = 6,
};

static struct {
	const char *attribute;
	bool requested;
	char *prompt;
	connmanctl_input_func_t *func;
} agent_input[] = {
	{ "Name", false, "Hidden SSID name? ", request_input_ssid_return },
	{ "Identity", false, "EAP username? ", request_input_string_return },
	{ "Passphrase", false, "Passphrase? ",
	  request_input_passphrase_return },
	{ "WPS", false, "WPS PIN (empty line for pushbutton)? " ,
	  request_input_string_return },
	{ "Username", false, "WISPr username? ", request_input_string_return },
	{ "Password", false, "WISPr password? ", request_input_string_return },
	{ },
};

static void request_input_next(void)
{
	int i;

	for (i = 0; agent_input[i].attribute != NULL; i++) {
		if (agent_input[i].requested == true) {
			if(agent_input[i].func != NULL)
				__connmanctl_agent_mode(agent_input[i].prompt,
						agent_input[i].func);
			else
				agent_input[i].requested = false;
			return;
		}
	}

	dbus_message_iter_close_container(&agent_reply.iter,
			&agent_reply.dict);

	g_dbus_send_message(agent_connection, agent_reply.reply);
	agent_reply.reply = NULL;

	pending_message_remove();
	pending_command_complete("");
}

static void request_input_append(const char *attribute, char *value)
{
	__connmanctl_dbus_append_dict_entry(&agent_reply.dict, attribute,
			DBUS_TYPE_STRING, &value);
}

static void request_input_ssid_return(char *input)
{
	int len = 0;

	if (input != NULL)
		len = strlen(input);

	if (len > 0 && len <= 32) {
		agent_input[SSID].requested = false;
		request_input_append(agent_input[SSID].attribute, input);

		request_input_next();
	}
}

static void request_input_passphrase_return(char *input)
{
	/* TBD passphrase length checking */

	if (input != NULL && strlen(input) > 0) {
		agent_input[PASSPHRASE].requested = false;
		request_input_append(agent_input[PASSPHRASE].attribute, input);

		agent_input[WPS].requested = false;

		request_input_next();
	}
}

static void request_input_string_return(char *input)
{
	int i;

	for (i = 0; agent_input[i].attribute != NULL; i++) {
		if (agent_input[i].requested == true) {
			request_input_append(agent_input[i].attribute, input);
			agent_input[i].requested = false;
			break;
		}
	}

	request_input_next();
}

static DBusMessage *agent_request_input(DBusConnection *connection,
		DBusMessage *message, void *user_data)
{
	DBusMessageIter iter, dict, entry, variant;
	char *service, *str, *field;
	DBusMessageIter dict_entry, field_entry, field_value;
	char *argument, *value, *attr_type;

	int i;

	dbus_message_iter_init(message, &iter);

	dbus_message_iter_get_basic(&iter, &str);
	service = strip_path(str);

	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &dict);

	__connmanctl_save_rl();
	fprintf(stdout, "Agent RequestInput %s\n", service);
	__connmanctl_dbus_print(&dict, "  ", " = ", "\n");
	fprintf(stdout, "\n");
	__connmanctl_redraw_rl();

	dbus_message_iter_recurse(&iter, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {

		dbus_message_iter_recurse(&dict, &entry);

		dbus_message_iter_get_basic(&entry, &field);

		dbus_message_iter_next(&entry);

		dbus_message_iter_recurse(&entry, &variant);
		dbus_message_iter_recurse(&variant, &dict_entry);

		while (dbus_message_iter_get_arg_type(&dict_entry)
				== DBUS_TYPE_DICT_ENTRY) {
			dbus_message_iter_recurse(&dict_entry, &field_entry);

			dbus_message_iter_get_basic(&field_entry, &argument);

			dbus_message_iter_next(&field_entry);

			dbus_message_iter_recurse(&field_entry, &field_value);

			dbus_message_iter_get_basic(&field_value, &value);

			if (strcmp(argument, "Type") == 0)
				attr_type = g_strdup(value);

			dbus_message_iter_next(&dict_entry);
		}

		for (i = 0; agent_input[i].attribute != NULL; i++) {
			if (strcmp(field, agent_input[i].attribute) == 0) {
				agent_input[i].requested = true;
				break;
			}
		}

		g_free(attr_type);
		attr_type = NULL;

		dbus_message_iter_next(&dict);
	}

	agent_connection = connection;
	agent_reply.reply = dbus_message_new_method_return(message);
	dbus_message_iter_init_append(agent_reply.reply, &agent_reply.iter);

	dbus_message_iter_open_container(&agent_reply.iter, DBUS_TYPE_ARRAY,
                        DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
                        DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
                        DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &agent_reply.dict);

	request_input_next();

	return NULL;
}

static const GDBusMethodTable agent_methods[] = {
	{ GDBUS_METHOD("Release", NULL, NULL, agent_release) },
	{ GDBUS_METHOD("Cancel", NULL, NULL, agent_cancel) },
	{ GDBUS_ASYNC_METHOD("RequestBrowser",
				GDBUS_ARGS({ "service", "o" },
					{ "url", "s" }),
				NULL, agent_request_browser) },
	{ GDBUS_ASYNC_METHOD("ReportError",
				GDBUS_ARGS({ "service", "o" },
					{ "error", "s" }),
				NULL, agent_report_error) },
	{ GDBUS_ASYNC_METHOD("RequestInput",
				GDBUS_ARGS({ "service", "o" },
					{ "fields", "a{sv}" }),
				GDBUS_ARGS({ "fields", "a{sv}" }),
				agent_request_input) },
	{ },
};

static int agent_register_return(DBusMessageIter *iter, const char *error,
		void *user_data)
{
	DBusConnection *connection = user_data;

	if (error != NULL) {
		g_dbus_unregister_interface(connection, agent_path(),
				AGENT_INTERFACE);
		fprintf(stderr, "Error registering Agent: %s\n", error);
		return 0;
	}

	agent_registered = true;
	fprintf(stdout, "Agent registered\n");

	return -EINPROGRESS;
}

int __connmanctl_agent_register(DBusConnection *connection)
{
	char *path = agent_path();
	int result;

	if (agent_registered == true) {
		fprintf(stderr, "Agent already registered\n");
		return -EALREADY;
	}

	if (g_dbus_register_interface(connection, path,
					AGENT_INTERFACE, agent_methods,
					NULL, NULL, connection,
					NULL) == FALSE) {
		fprintf(stderr, "Error: Failed to register Agent callbacks\n");
		return 0;
	}

	result = __connmanctl_dbus_method_call(connection, "/",
			"net.connman.Manager", "RegisterAgent",
			agent_register_return, connection,
			DBUS_TYPE_OBJECT_PATH, &path, DBUS_TYPE_INVALID);

	if (result != -EINPROGRESS) {
		g_dbus_unregister_interface(connection, agent_path(),
				AGENT_INTERFACE);

		fprintf(stderr, "Error: Failed to register Agent\n");
	}

	return result;
}

static int agent_unregister_return(DBusMessageIter *iter, const char *error,
		void *user_data)
{
	if (error != NULL) {
		fprintf(stderr, "Error unregistering Agent: %s\n", error);
		return 0;
	}

	agent_registered = false;
	fprintf(stdout, "Agent unregistered\n");

	return 0;
}

int __connmanctl_agent_unregister(DBusConnection *connection)
{
	char *path = agent_path();
	int result;

	if (agent_registered == false) {
		fprintf(stderr, "Agent not registered\n");
		return -EALREADY;
	}

	g_dbus_unregister_interface(connection, agent_path(), AGENT_INTERFACE);

	result = __connmanctl_dbus_method_call(connection, "/",
			"net.connman.Manager", "UnregisterAgent",
			agent_unregister_return, NULL,
			DBUS_TYPE_OBJECT_PATH, &path, DBUS_TYPE_INVALID);

	if (result != -EINPROGRESS)
		fprintf(stderr, "Error: Failed to unregister Agent\n");

	return result;
}
