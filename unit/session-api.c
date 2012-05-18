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

#include <errno.h>

#include <gdbus/gdbus.h>

#include "test-connman.h"

static enum connman_session_state string2state(const char *state)
{
	if (g_strcmp0(state, "connected") == 0)
		return CONNMAN_SESSION_STATE_CONNECTED;
	if (g_strcmp0(state, "online") == 0)
		return CONNMAN_SESSION_STATE_ONLINE;

	return CONNMAN_SESSION_STATE_DISCONNECTED;
}

static enum connman_session_state string2type(const char *type)
{
	if (g_strcmp0(type, "local") == 0)
		return CONNMAN_SESSION_TYPE_LOCAL;
	if (g_strcmp0(type, "internet") == 0)
		return CONNMAN_SESSION_TYPE_INTERNET;

	return CONNMAN_SESSION_TYPE_ANY;
}

static const char *roamingpolicy2string(enum connman_session_roaming_policy policy)
{
	switch (policy) {
	case CONNMAN_SESSION_ROAMING_POLICY_UNKNOWN:
		break;
	case CONNMAN_SESSION_ROAMING_POLICY_DEFAULT:
		return "default";
	case CONNMAN_SESSION_ROAMING_POLICY_ALWAYS:
		return "always";
	case CONNMAN_SESSION_ROAMING_POLICY_FORBIDDEN:
		return "forbidden";
	case CONNMAN_SESSION_ROAMING_POLICY_NATIONAL:
		return "national";
	case CONNMAN_SESSION_ROAMING_POLICY_INTERNATIONAL:
		return "international";
	}

	return "";
}

static enum connman_session_roaming_policy string2roamingpolicy(const char *policy)
{
	if (g_strcmp0(policy, "default") == 0)
		return CONNMAN_SESSION_ROAMING_POLICY_DEFAULT;
	else if (g_strcmp0(policy, "always") == 0)
		return CONNMAN_SESSION_ROAMING_POLICY_ALWAYS;
	else if (g_strcmp0(policy, "forbidden") == 0)
		return CONNMAN_SESSION_ROAMING_POLICY_FORBIDDEN;
	else if (g_strcmp0(policy, "national") == 0)
		return CONNMAN_SESSION_ROAMING_POLICY_NATIONAL;
	else if (g_strcmp0(policy, "international") == 0)
		return CONNMAN_SESSION_ROAMING_POLICY_INTERNATIONAL;
	else
		return CONNMAN_SESSION_ROAMING_POLICY_UNKNOWN;
}

void bearer_info_cleanup(gpointer data, gpointer user_data)
{
	struct test_bearer_info *info = data;

	g_free(info->name);
	g_free(info);
}

static GSList *session_parse_allowed_bearers(DBusMessageIter *iter)
{
	struct test_bearer_info *info;
	DBusMessageIter array;
	GSList *list = NULL;

	dbus_message_iter_recurse(iter, &array);

	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_STRING) {
		char *bearer = NULL;

		dbus_message_iter_get_basic(&array, &bearer);

		info = g_try_new0(struct test_bearer_info, 1);
		if (info == NULL) {
			g_slist_foreach(list, bearer_info_cleanup, NULL);
			g_slist_free(list);

			return NULL;
		}

		info->name = g_strdup(bearer);

		list = g_slist_append(list, info);

		dbus_message_iter_next(&array);
	}

	return list;
}

static DBusMessage *notify_release(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct test_session *session = user_data;

	LOG("session %p", session);

	if (session->notify != NULL)
		session->notify(session);

	return NULL;
}

static DBusMessage *notify_update(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct test_session *session = user_data;
	struct test_session_info *info = session->info;
	DBusMessageIter iter, array;
	GSList *allowed_bearers;

	LOG("session %p notify %s", session, session->notify_path);

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_recurse(&iter, &array);

	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;

		dbus_message_iter_recurse(&array, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		switch (dbus_message_iter_get_arg_type(&value)) {
		case DBUS_TYPE_ARRAY:
			if (g_str_equal(key, "AllowedBearers") == TRUE) {
				allowed_bearers = session_parse_allowed_bearers(&value);

				g_slist_foreach(info->allowed_bearers,
						bearer_info_cleanup, NULL);
				g_slist_free(info->allowed_bearers);

				info->allowed_bearers = allowed_bearers;

			} else if (g_str_equal(key, "IPv4") == TRUE) {
				/* XXX */

			} else if (g_str_equal(key, "IPv6") == TRUE) {
				/* XXX */

			} else {
				g_assert(FALSE);
				return __connman_error_invalid_arguments(msg);
			}
			break;
		case DBUS_TYPE_BOOLEAN:
			if (g_str_equal(key, "Priority") == TRUE) {
				dbus_message_iter_get_basic(&value,
							&info->priority);

			} else if (g_str_equal(key, "AvoidHandover") == TRUE) {
				dbus_message_iter_get_basic(&value,
							&info->avoid_handover);

			} else if (g_str_equal(key, "StayConnected") == TRUE) {
				dbus_message_iter_get_basic(&value,
							&info->stay_connected);

			} else if (g_str_equal(key, "EmergencyCall") == TRUE) {
				dbus_message_iter_get_basic(&value,
							&info->ecall);

			} else {
				g_assert(FALSE);
				return __connman_error_invalid_arguments(msg);
			}
			break;
		case DBUS_TYPE_UINT32:
			if (g_str_equal(key, "PeriodicConnect") == TRUE) {
				dbus_message_iter_get_basic(&value,
							&info->periodic_connect);

			} else if (g_str_equal(key, "IdleTimeout") == TRUE) {
				dbus_message_iter_get_basic(&value,
							&info->idle_timeout);

			} else if (g_str_equal(key, "SessionMarker") == TRUE) {
				dbus_message_iter_get_basic(&value,
							&info->marker);

			} else {
				g_assert(FALSE);
				return __connman_error_invalid_arguments(msg);
			}
			break;
		case DBUS_TYPE_STRING:
			if (g_str_equal(key, "State") == TRUE) {
				const char *val;
				dbus_message_iter_get_basic(&value, &val);

				info->state = string2state(val);
			} else if (g_str_equal(key, "Bearer") == TRUE) {
				const char *val;
				dbus_message_iter_get_basic(&value, &val);

				if (info->bearer != NULL)
					g_free(info->bearer);

				info->bearer = g_strdup(val);

			} else if (g_str_equal(key, "Name") == TRUE) {
				const char *val;
				dbus_message_iter_get_basic(&value, &val);

				if (info->name != NULL)
					g_free(info->name);

				info->name = g_strdup(val);

			} else if (g_str_equal(key, "RoamingPolicy") == TRUE) {
				const char *val;
				dbus_message_iter_get_basic(&value, &val);
				info->roaming_policy =
					string2roamingpolicy(val);

			} else if (g_str_equal(key, "Interface") == TRUE) {
				const char *val;
				dbus_message_iter_get_basic(&value, &val);

				if (info->interface != NULL)
					g_free(info->interface);

				info->interface = g_strdup(val);

			} else if (g_str_equal(key, "ConnectionType")
								== TRUE) {
				const char *val;
				dbus_message_iter_get_basic(&value, &val);

				info->type = string2type(val);
			} else {
				g_assert(FALSE);
				return __connman_error_invalid_arguments(msg);
			}
			break;
		default:
			g_assert(FALSE);
			return __connman_error_invalid_arguments(msg);
		}
		dbus_message_iter_next(&array);
	}

	if (session->notify != NULL)
		session->notify(session);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static const GDBusMethodTable notify_methods[] = {
	{ GDBUS_METHOD("Release", NULL, NULL, notify_release) },
	{ GDBUS_METHOD("Update",
			GDBUS_ARGS({ "settings", "a{sv}" }), NULL,
			notify_update) },
	{ },
};

int session_notify_register(struct test_session *session,
				const char *notify_path)
{
	if (g_dbus_register_interface(session->connection, notify_path,
			CONNMAN_NOTIFICATION_INTERFACE,
			notify_methods, NULL, NULL,
			session, NULL) == FALSE) {
		return -EINVAL;
	}

	return 0;
}

int session_notify_unregister(struct test_session *session,
				const char *notify_path)
{
	if (g_dbus_unregister_interface(session->connection, notify_path,
				CONNMAN_NOTIFICATION_INTERFACE) == FALSE) {
		return -EINVAL;
	}

	return 0;
}

static void append_allowed_bearers(DBusMessageIter *iter, void *user_data)
{
	struct test_session_info *info = user_data;
	GSList *list;

	for (list = info->allowed_bearers;
			list != NULL; list = list->next) {
		struct test_bearer_info *info = list->data;

		dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING,
						&info->name);
	}
}

void session_append_settings(DBusMessageIter *dict,
				struct test_session_info *info)
{
	const char *policy;

	connman_dbus_dict_append_basic(dict, "Priority",
						DBUS_TYPE_BOOLEAN,
						&info->priority);

	connman_dbus_dict_append_array(dict, "AllowedBearers",
						DBUS_TYPE_STRING,
						append_allowed_bearers,
						info);

	connman_dbus_dict_append_basic(dict, "AvoidHandover",
						DBUS_TYPE_BOOLEAN,
						&info->avoid_handover);

	connman_dbus_dict_append_basic(dict, "StayConnected",
						DBUS_TYPE_BOOLEAN,
						&info->stay_connected);

	connman_dbus_dict_append_basic(dict, "PeriodicConnect",
						DBUS_TYPE_UINT32,
						&info->periodic_connect);

	connman_dbus_dict_append_basic(dict, "IdleTimeout",
						DBUS_TYPE_UINT32,
						&info->idle_timeout);

	connman_dbus_dict_append_basic(dict, "EmergencyCall",
						DBUS_TYPE_BOOLEAN,
						&info->ecall);

	policy = roamingpolicy2string(info->roaming_policy);
	connman_dbus_dict_append_basic(dict, "RoamingPolicy",
						DBUS_TYPE_STRING,
						&policy);
}

DBusMessage *session_connect(DBusConnection *connection,
				struct test_session *session)
{
	DBusMessage *message, *reply;
	DBusError error;

	message = dbus_message_new_method_call(CONNMAN_SERVICE,
						session->session_path,
						CONNMAN_SESSION_INTERFACE,
							"Connect");
	if (message == NULL)
		return NULL;

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(connection,
							message, -1, &error);
	if (reply == NULL) {
		if (dbus_error_is_set(&error) == TRUE) {
			LOG("%s", error.message);
			dbus_error_free(&error);
		} else {
			LOG("Failed to get properties");
		}
		dbus_message_unref(message);
		return NULL;
	}

	dbus_message_unref(message);

	return reply;
}

DBusMessage *session_disconnect(DBusConnection *connection,
					struct test_session *session)
{
	DBusMessage *message, *reply;
	DBusError error;

	message = dbus_message_new_method_call(CONNMAN_SERVICE,
						session->session_path,
						CONNMAN_SESSION_INTERFACE,
							"Disconnect");
	if (message == NULL)
		return NULL;

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(connection,
							message, -1, &error);
	if (reply == NULL) {
		if (dbus_error_is_set(&error) == TRUE) {
			LOG("%s", error.message);
			dbus_error_free(&error);
		} else {
			LOG("Failed to get properties");
		}
		dbus_message_unref(message);
		return NULL;
	}

	dbus_message_unref(message);

	return reply;
}
