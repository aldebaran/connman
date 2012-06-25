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

static connman_bool_t check_reply_has_dict(DBusMessage *reply)
{
	const char *signature = DBUS_TYPE_ARRAY_AS_STRING
		DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
		DBUS_TYPE_STRING_AS_STRING
		DBUS_TYPE_VARIANT_AS_STRING
		DBUS_DICT_ENTRY_END_CHAR_AS_STRING;

	if (dbus_message_has_signature(reply, signature) == TRUE)
		return TRUE;

	connman_warn("Reply %s to %s from %s has wrong signature %s",
			signature,
			dbus_message_get_interface(reply),
			dbus_message_get_sender(reply),
			dbus_message_get_signature(reply));

	return FALSE;
}

struct request_input_reply {
	struct connman_service *service;
	authentication_cb_t callback;
	void *user_data;
};

static void request_input_passphrase_reply(DBusPendingCall *call, void *user_data)
{
	struct request_input_reply *passphrase_reply = user_data;
	connman_bool_t values_received = FALSE;
	connman_bool_t wps = FALSE;
	const char *error = NULL;
	char *identity = NULL;
	char *passphrase = NULL;
	char *wpspin = NULL;
	char *key;
	char *name = NULL;
	int name_len = 0;
	DBusMessageIter iter, dict;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);

	if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR) {
		error = dbus_message_get_error_name(reply);
		goto done;
	}

	if (check_reply_has_dict(reply) == FALSE)
		goto done;

	values_received = TRUE;

	dbus_message_iter_init(reply, &iter);
	dbus_message_iter_recurse(&iter, &dict);
	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;

		dbus_message_iter_recurse(&dict, &entry);
		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			break;

		dbus_message_iter_get_basic(&entry, &key);

		if (g_str_equal(key, "Identity")) {
			dbus_message_iter_next(&entry);
			if (dbus_message_iter_get_arg_type(&entry)
							!= DBUS_TYPE_VARIANT)
				break;
			dbus_message_iter_recurse(&entry, &value);
			dbus_message_iter_get_basic(&value, &identity);

		} else if (g_str_equal(key, "Passphrase")) {
			dbus_message_iter_next(&entry);
			if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_VARIANT)
				break;
			dbus_message_iter_recurse(&entry, &value);
			dbus_message_iter_get_basic(&value, &passphrase);

		} else if (g_str_equal(key, "WPS")) {
			wps = TRUE;

			dbus_message_iter_next(&entry);
			if (dbus_message_iter_get_arg_type(&entry)
							!= DBUS_TYPE_VARIANT)
				break;
			dbus_message_iter_recurse(&entry, &value);
			dbus_message_iter_get_basic(&value, &wpspin);
			break;
		} else if (g_str_equal(key, "Name")) {
			dbus_message_iter_next(&entry);
			if (dbus_message_iter_get_arg_type(&entry)
							!= DBUS_TYPE_VARIANT)
				break;
			dbus_message_iter_recurse(&entry, &value);
			dbus_message_iter_get_basic(&value, &name);
			name_len = strlen(name);
		} else if (g_str_equal(key, "SSID")) {
			dbus_message_iter_next(&entry);
			if (dbus_message_iter_get_arg_type(&entry)
							!= DBUS_TYPE_VARIANT)
				break;
			dbus_message_iter_recurse(&entry, &value);
			if (dbus_message_iter_get_arg_type(&value)
							!= DBUS_TYPE_VARIANT)
				break;
			if (dbus_message_iter_get_element_type(&value)
							!= DBUS_TYPE_VARIANT)
				break;
			dbus_message_iter_get_fixed_array(&value, &name,
							&name_len);
		}
		dbus_message_iter_next(&dict);
	}

done:
	passphrase_reply->callback(passphrase_reply->service, values_received,
				name, name_len,
				identity, passphrase,
				wps, wpspin, error,
				passphrase_reply->user_data);
	connman_service_unref(passphrase_reply->service);
	dbus_message_unref(reply);
	dbus_pending_call_unref(call);
	g_free(passphrase_reply);
}

static void request_input_append_alternates(DBusMessageIter *iter,
							void *user_data)
{
	const char *str = user_data;
	char **alternates, **alternative;

	if (str == NULL)
		return;

	alternates = g_strsplit(str, ",", 0);
	if (alternates == NULL)
		return;

	for (alternative = alternates; *alternative != NULL; alternative++)
		dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING,
								alternative);

	g_strfreev(alternates);
}

static void request_input_append_identity(DBusMessageIter *iter,
							void *user_data)
{
	char *str = "string";

	connman_dbus_dict_append_basic(iter, "Type",
				DBUS_TYPE_STRING, &str);
	str = "mandatory";
	connman_dbus_dict_append_basic(iter, "Requirement",
				DBUS_TYPE_STRING, &str);
}

static void request_input_append_passphrase(DBusMessageIter *iter,
							void *user_data)
{
	struct connman_service *service = user_data;
	char *value;
	const char *phase2;

	switch (__connman_service_get_security(service)) {
	case CONNMAN_SERVICE_SECURITY_WEP:
		value = "wep";
		break;
	case CONNMAN_SERVICE_SECURITY_PSK:
		value = "psk";
		break;
	case CONNMAN_SERVICE_SECURITY_8021X:
		phase2 = __connman_service_get_phase2(service);

		if (phase2 != NULL && (
				g_str_has_suffix(phase2, "GTC") == TRUE ||
				g_str_has_suffix(phase2, "OTP") == TRUE))
			value = "response";
		else
			value = "passphrase";

		break;
	default:
		value = "string";
		break;
	}
	connman_dbus_dict_append_basic(iter, "Type",
				DBUS_TYPE_STRING, &value);
	value = "mandatory";
	connman_dbus_dict_append_basic(iter, "Requirement",
				DBUS_TYPE_STRING, &value);

	if (__connman_service_wps_enabled(service) == TRUE) {
		connman_dbus_dict_append_array(iter, "Alternates",
					DBUS_TYPE_STRING,
					request_input_append_alternates,
					"WPS");
	}
}

static void request_input_append_wps(DBusMessageIter *iter, void *user_data)
{
	const char *str = "wpspin";

	connman_dbus_dict_append_basic(iter, "Type",
				DBUS_TYPE_STRING, &str);
	str = "alternate";
	connman_dbus_dict_append_basic(iter, "Requirement",
				DBUS_TYPE_STRING, &str);
}

static void request_input_append_name(DBusMessageIter *iter, void *user_data)
{
	const char *str = "string";

	connman_dbus_dict_append_basic(iter, "Type",
				DBUS_TYPE_STRING, &str);
	str = "mandatory";
	connman_dbus_dict_append_basic(iter, "Requirement",
				DBUS_TYPE_STRING, &str);
	connman_dbus_dict_append_array(iter, "Alternates",
				DBUS_TYPE_STRING,
				request_input_append_alternates,
				"SSID");
}

static void request_input_append_ssid(DBusMessageIter *iter, void *user_data)
{
	const char *str = "ssid";

	connman_dbus_dict_append_basic(iter, "Type",
				DBUS_TYPE_STRING, &str);
	str = "alternate";
	connman_dbus_dict_append_basic(iter, "Requirement",
				DBUS_TYPE_STRING, &str);
}

static void request_input_append_password(DBusMessageIter *iter,
							void *user_data)
{
	char *str = "passphrase";

	connman_dbus_dict_append_basic(iter, "Type",
				DBUS_TYPE_STRING, &str);
	str = "mandatory";
	connman_dbus_dict_append_basic(iter, "Requirement",
				DBUS_TYPE_STRING, &str);
}

static void request_input_append_previouspassphrase(DBusMessageIter *iter,
							void *user_data)
{
	struct connman_service *service = user_data;
	enum connman_service_security security;
	const char *passphrase, *str = NULL;

	passphrase = __connman_service_get_passphrase(service);

	security = __connman_service_get_security(service);
	switch (security) {
	case CONNMAN_SERVICE_SECURITY_WEP:
		str = "wep";
		break;
	case CONNMAN_SERVICE_SECURITY_PSK:
		str  = "psk";
		break;
	/*
	 * This should never happen: no passphrase is set if security is not
	 * one of the above.*/
	default:
		break;
	}

	connman_dbus_dict_append_basic(iter, "Type",
				DBUS_TYPE_STRING, &str);

	str = "informational";
	connman_dbus_dict_append_basic(iter, "Requirement",
				DBUS_TYPE_STRING, &str);

	connman_dbus_dict_append_basic(iter, "Value",
				DBUS_TYPE_STRING, &passphrase);
}

static void request_input_login_reply(DBusPendingCall *call, void *user_data)
{
	struct request_input_reply *username_password_reply = user_data;
	const char *error = NULL;
	connman_bool_t values_received = FALSE;
	char *username = NULL;
	char *password = NULL;
	char *key;
	DBusMessageIter iter, dict;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);

	if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR) {
		error = dbus_message_get_error_name(reply);
		goto done;
	}

	if (check_reply_has_dict(reply) == FALSE)
		goto done;

	values_received = TRUE;

	dbus_message_iter_init(reply, &iter);
	dbus_message_iter_recurse(&iter, &dict);
	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;

		dbus_message_iter_recurse(&dict, &entry);
		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			break;

		dbus_message_iter_get_basic(&entry, &key);

		if (g_str_equal(key, "Username")) {
			dbus_message_iter_next(&entry);
			if (dbus_message_iter_get_arg_type(&entry)
							!= DBUS_TYPE_VARIANT)
				break;
			dbus_message_iter_recurse(&entry, &value);
			dbus_message_iter_get_basic(&value, &username);

		} else if (g_str_equal(key, "Password")) {
			dbus_message_iter_next(&entry);
			if (dbus_message_iter_get_arg_type(&entry) !=
							DBUS_TYPE_VARIANT)
				break;
			dbus_message_iter_recurse(&entry, &value);
			dbus_message_iter_get_basic(&value, &password);
		}

		dbus_message_iter_next(&dict);
	}

done:
	username_password_reply->callback(username_password_reply->service,
					values_received, NULL, 0,
					username, password,
					FALSE, NULL, error,
					username_password_reply->user_data);
	connman_service_unref(username_password_reply->service);
	dbus_message_unref(reply);
	g_free(username_password_reply);
}

int __connman_agent_request_passphrase_input(struct connman_service *service,
				authentication_cb_t callback, void *user_data)
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

	if (__connman_service_is_hidden(service)) {
		connman_dbus_dict_append_dict(&dict, "Name",
					request_input_append_name, NULL);
		connman_dbus_dict_append_dict(&dict, "SSID",
					request_input_append_ssid, NULL);
	}

	if (__connman_service_get_security(service) ==
			CONNMAN_SERVICE_SECURITY_8021X) {
		connman_dbus_dict_append_dict(&dict, "Identity",
					request_input_append_identity, service);
	}

	if (__connman_service_get_security(service) !=
			CONNMAN_SERVICE_SECURITY_NONE) {
		connman_dbus_dict_append_dict(&dict, "Passphrase",
					request_input_append_passphrase, service);

		if (__connman_service_get_passphrase(service) != NULL)
			connman_dbus_dict_append_dict(&dict, "PreviousPassphrase",
					request_input_append_previouspassphrase,
					service);
	}

	if (__connman_service_wps_enabled(service) == TRUE) {
	    connman_dbus_dict_append_dict(&dict, "WPS",
				request_input_append_wps, NULL);
	}

	connman_dbus_dict_close(&iter, &dict);

	passphrase_reply = g_try_new0(struct request_input_reply, 1);
	if (passphrase_reply == NULL) {
		dbus_message_unref(message);
		return -ENOMEM;
	}

	if (dbus_connection_send_with_reply(connection, message, &call,
					connman_timeout_input_request())
			== FALSE) {
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

	return -EINPROGRESS;
}

int __connman_agent_request_login_input(struct connman_service *service,
				authentication_cb_t callback, void *user_data)
{
	DBusMessage *message;
	const char *path;
	DBusMessageIter iter;
	DBusMessageIter dict;
	DBusPendingCall *call;
	struct request_input_reply *username_password_reply;

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

	connman_dbus_dict_append_dict(&dict, "Username",
				request_input_append_identity, service);

	connman_dbus_dict_append_dict(&dict, "Password",
				request_input_append_password, service);

	connman_dbus_dict_close(&iter, &dict);

	username_password_reply = g_try_new0(struct request_input_reply, 1);
	if (username_password_reply == NULL) {
		dbus_message_unref(message);
		return -ENOMEM;
	}

	if (dbus_connection_send_with_reply(connection, message, &call,
					connman_timeout_input_request())
			== FALSE) {
		dbus_message_unref(message);
		g_free(username_password_reply);
		return -ESRCH;
	}

	if (call == NULL) {
		dbus_message_unref(message);
		g_free(username_password_reply);
		return -ESRCH;
	}

	username_password_reply->service = connman_service_ref(service);
	username_password_reply->callback = callback;
	username_password_reply->user_data = user_data;

	dbus_pending_call_set_notify(call, request_input_login_reply,
						username_password_reply, NULL);

	dbus_message_unref(message);

	return -EINPROGRESS;
}

struct request_browser_reply_data {
	struct connman_service *service;
	browser_authentication_cb_t callback;
	void *user_data;
};

static void request_browser_reply(DBusPendingCall *call, void *user_data)
{
	struct request_browser_reply_data *browser_reply_data = user_data;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	connman_bool_t result = FALSE;
	const char *error = NULL;

	if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR) {
		error = dbus_message_get_error_name(reply);
		goto done;
	}

	result = TRUE;

done:
	browser_reply_data->callback(browser_reply_data->service, result,
					error, browser_reply_data->user_data);
	connman_service_unref(browser_reply_data->service);
	dbus_message_unref(reply);
	g_free(browser_reply_data);
}

int __connman_agent_request_browser(struct connman_service *service,
				browser_authentication_cb_t callback,
				const char *url, void *user_data)
{
	struct request_browser_reply_data *browser_reply_data;
	DBusPendingCall *call;
	DBusMessage *message;
	DBusMessageIter iter;
	const char *path;

	if (service == NULL || agent_path == NULL || callback == NULL)
		return -ESRCH;

	if (url == NULL)
		url = "";

	message = dbus_message_new_method_call(agent_sender, agent_path,
					CONNMAN_AGENT_INTERFACE,
					"RequestBrowser");
	if (message == NULL)
		return -ENOMEM;

	dbus_message_iter_init_append(message, &iter);

	path = __connman_service_get_path(service);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH, &path);

	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &url);

	browser_reply_data = g_try_new0(struct request_browser_reply_data, 1);
	if (browser_reply_data == NULL) {
		dbus_message_unref(message);
		return -ENOMEM;
	}

	if (dbus_connection_send_with_reply(connection, message, &call,
					connman_timeout_browser_launch())
			== FALSE) {
		dbus_message_unref(message);
		g_free(browser_reply_data);
		return -ESRCH;
	}

	if (call == NULL) {
		dbus_message_unref(message);
		g_free(browser_reply_data);
		return -ESRCH;
	}

	browser_reply_data->service = connman_service_ref(service);
	browser_reply_data->callback = callback;
	browser_reply_data->user_data = user_data;

	dbus_pending_call_set_notify(call, request_browser_reply,
						browser_reply_data, NULL);

	dbus_message_unref(message);

	return -EINPROGRESS;
}

struct report_error_data {
	struct connman_service *service;
	report_error_cb_t callback;
	void *user_data;
};

static void report_error_reply(DBusPendingCall *call, void *user_data)
{
	struct report_error_data *report_error = user_data;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	gboolean retry = FALSE;
	const char *dbus_err;

	if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR) {
		dbus_err = dbus_message_get_error_name(reply);
		if (dbus_err != NULL &&
			strcmp(dbus_err,
				CONNMAN_AGENT_INTERFACE ".Error.Retry") == 0)
			retry = TRUE;
	}

	report_error->callback(report_error->service, retry,
			report_error->user_data);
	connman_service_unref(report_error->service);
	g_free(report_error);
	dbus_message_unref(reply);
	dbus_pending_call_unref(call);
}

int __connman_agent_report_error(struct connman_service *service,
				const char *error,
				report_error_cb_t callback, void *user_data)
{
	DBusMessage *message;
	DBusMessageIter iter;
	const char *path;
	struct report_error_data *report_error;
	DBusPendingCall *call;

	if (service == NULL || agent_path == NULL || error == NULL ||
		callback == NULL)
		return -ESRCH;

	message = dbus_message_new_method_call(agent_sender, agent_path,
					CONNMAN_AGENT_INTERFACE,
					"ReportError");
	if (message == NULL)
		return -ENOMEM;

	dbus_message_iter_init_append(message, &iter);

	path = __connman_service_get_path(service);
	dbus_message_iter_append_basic(&iter,
				DBUS_TYPE_OBJECT_PATH, &path);
	dbus_message_iter_append_basic(&iter,
				DBUS_TYPE_STRING, &error);

	report_error = g_try_new0(struct report_error_data, 1);
	if (report_error == NULL) {
		dbus_message_unref(message);
		return -ENOMEM;
	}

	if (dbus_connection_send_with_reply(connection, message, &call,
					connman_timeout_input_request())
			== FALSE) {
		dbus_message_unref(message);
		g_free(report_error);
		return -ESRCH;
	}

	if (call == NULL) {
		dbus_message_unref(message);
		g_free(report_error);
		return -ESRCH;
	}

	report_error->service = connman_service_ref(service);
	report_error->callback = callback;
	report_error->user_data = user_data;
	dbus_pending_call_set_notify(call, report_error_reply,
				report_error, NULL);
	dbus_message_unref(message);

	return -EINPROGRESS;
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
