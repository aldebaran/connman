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

enum connman_session_roaming_policy {
	CONNMAN_SESSION_ROAMING_POLICY_UNKNOWN		= 0,
	CONNMAN_SESSION_ROAMING_POLICY_DEFAULT		= 1,
	CONNMAN_SESSION_ROAMING_POLICY_ALWAYS		= 2,
	CONNMAN_SESSION_ROAMING_POLICY_FORBIDDEN	= 3,
	CONNMAN_SESSION_ROAMING_POLICY_NATIONAL		= 4,
	CONNMAN_SESSION_ROAMING_POLICY_INTERNATIONAL	= 5,
};

struct connman_session {
	char *owner;
	char *session_path;
	char *notify_path;
	guint notify_watch;

	char *bearer;
	const char *name;
	char *ifname;
	connman_bool_t online;
	connman_bool_t priority;
	GSList *allowed_bearers;
	connman_bool_t avoid_handover;
	connman_bool_t stay_connected;
	unsigned int periodic_connect;
	unsigned int idle_timeout;
	connman_bool_t ecall;
	enum connman_session_roaming_policy roaming_policy;
	unsigned int marker;

	GSequence *service_list;
	struct connman_service *service;
};

struct bearer_info {
	char *name;
	connman_bool_t match_all;
	enum connman_service_type service_type;
};

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

	return NULL;
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

static enum connman_service_type bearer2service(const char *bearer)
{
	if (bearer == NULL)
		return CONNMAN_SERVICE_TYPE_UNKNOWN;

	if (g_strcmp0(bearer, "ethernet") == 0)
		return CONNMAN_SERVICE_TYPE_ETHERNET;
	else if (g_strcmp0(bearer, "wifi") == 0)
		return CONNMAN_SERVICE_TYPE_WIFI;
	else if (g_strcmp0(bearer, "wimax") == 0)
		return CONNMAN_SERVICE_TYPE_WIMAX;
	else if (g_strcmp0(bearer, "bluetooth") == 0)
		return CONNMAN_SERVICE_TYPE_BLUETOOTH;
	else if (g_strcmp0(bearer, "3g") == 0)
		return CONNMAN_SERVICE_TYPE_CELLULAR;
	else
		return CONNMAN_SERVICE_TYPE_UNKNOWN;
}

static char *service2bearer(enum connman_service_type type)
{
	switch (type) {
	case CONNMAN_SERVICE_TYPE_ETHERNET:
		return "ethernet";
	case CONNMAN_SERVICE_TYPE_WIFI:
		return "wifi";
	case CONNMAN_SERVICE_TYPE_WIMAX:
		return "wimax";
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
		return "bluetooth";
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		return "3g";
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_VPN:
	case CONNMAN_SERVICE_TYPE_GADGET:
		return NULL;
	}

	return NULL;
}

static char *session2bearer(struct connman_session *session)
{
	GSList *list;
	struct bearer_info *info;
	enum connman_service_type type;

	if (session->service == NULL)
		return NULL;

	type = connman_service_get_type(session->service);

	for (list = session->allowed_bearers; list != NULL; list = list->next) {
		info = list->data;

		if (info->match_all)
			return service2bearer(type);

		if (info->service_type == CONNMAN_SERVICE_TYPE_UNKNOWN)
			return info->name;

		if (info->service_type == type)
			return service2bearer(type);
	}

	return NULL;

}

static void cleanup_bearer_info(gpointer data, gpointer user_data)
{
	struct bearer_info *info = data;

	g_free(info->name);
	g_free(info);
}

static GSList *session_parse_allowed_bearers(DBusMessageIter *iter)
{
	struct bearer_info *info;
	DBusMessageIter array;
	GSList *list = NULL;

	dbus_message_iter_recurse(iter, &array);

	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_STRING) {
		char *bearer = NULL;

		dbus_message_iter_get_basic(&array, &bearer);

		info = g_try_new0(struct bearer_info, 1);
		if (info == NULL) {
			g_slist_foreach(list, cleanup_bearer_info, NULL);
			g_slist_free(list);

			return NULL;
		}

		info->name = g_strdup(bearer);
		info->service_type = bearer2service(info->name);

		if (info->service_type == CONNMAN_SERVICE_TYPE_UNKNOWN &&
				g_strcmp0(info->name, "*") == 0) {
			info->match_all = TRUE;
		} else {
			info->match_all = FALSE;
		}

		list = g_slist_append(list, info);

		dbus_message_iter_next(&array);
	}

	return list;
}

static GSList *session_allowed_bearers_any(void)
{
	struct bearer_info *info;
	GSList *list = NULL;

	info = g_try_new0(struct bearer_info, 1);
	if (info == NULL) {
		g_slist_free(list);

		return NULL;
	}

	info->name = g_strdup("");
	info->match_all = TRUE;
	info->service_type = CONNMAN_SERVICE_TYPE_UNKNOWN;

	list = g_slist_append(list, info);

	return list;
}

static void append_allowed_bearers(DBusMessageIter *iter, void *user_data)
{
	struct connman_session *session = user_data;
	GSList *list;

	for (list = session->allowed_bearers; list != NULL; list = list->next) {
		struct bearer_info *info = list->data;

		dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING,
						&info->name);
	}
}

static void append_ipconfig_ipv4(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;
	struct connman_ipconfig *ipconfig_ipv4;

	if (service == NULL)
		return;

	ipconfig_ipv4 = __connman_service_get_ip4config(service);
	if (ipconfig_ipv4 == NULL)
		return;

	__connman_ipconfig_append_ipv4(ipconfig_ipv4, iter);
}

static void append_ipconfig_ipv6(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;
	struct connman_ipconfig *ipconfig_ipv4, *ipconfig_ipv6;

	if (service == NULL)
		return;

	ipconfig_ipv4 = __connman_service_get_ip4config(service);
	ipconfig_ipv6 = __connman_service_get_ip6config(service);
	if (ipconfig_ipv6 == NULL)
		return;

	__connman_ipconfig_append_ipv6(ipconfig_ipv6, iter, ipconfig_ipv4);
}

static void append_service(DBusMessageIter *dict,
					struct connman_session *session)
{
	connman_dbus_dict_append_basic(dict, "Bearer",
					DBUS_TYPE_STRING, &session->bearer);

	connman_dbus_dict_append_basic(dict, "Online",
					DBUS_TYPE_BOOLEAN, &session->online);

	connman_dbus_dict_append_basic(dict, "Name",
					DBUS_TYPE_STRING, &session->name);

	connman_dbus_dict_append_dict(dict, "IPv4",
					append_ipconfig_ipv4, session->service);

	connman_dbus_dict_append_dict(dict, "IPv6",
					append_ipconfig_ipv6, session->service);

	connman_dbus_dict_append_basic(dict, "Interface",
					DBUS_TYPE_STRING, &session->ifname);

}

static void append_notify_all(DBusMessageIter *dict,
					struct connman_session *session)
{
	const char *policy;

	append_service(dict, session);

	connman_dbus_dict_append_basic(dict, "Priority",
					DBUS_TYPE_BOOLEAN, &session->priority);

	connman_dbus_dict_append_array(dict, "AllowedBearers",
					DBUS_TYPE_STRING,
					append_allowed_bearers,
					session);

	connman_dbus_dict_append_basic(dict, "AvoidHandover",
					DBUS_TYPE_BOOLEAN,
					&session->avoid_handover);

	connman_dbus_dict_append_basic(dict, "StayConnected",
					DBUS_TYPE_BOOLEAN,
					&session->stay_connected);

	connman_dbus_dict_append_basic(dict, "PeriodicConnect",
					DBUS_TYPE_UINT32,
					&session->periodic_connect);

	connman_dbus_dict_append_basic(dict, "IdleTimeout",
					DBUS_TYPE_UINT32,
					&session->idle_timeout);

	connman_dbus_dict_append_basic(dict, "EmergencyCall",
					DBUS_TYPE_BOOLEAN, &session->ecall);

	policy = roamingpolicy2string(session->roaming_policy);
	connman_dbus_dict_append_basic(dict, "RoamingPolicy",
					DBUS_TYPE_STRING,
					&policy);

	connman_dbus_dict_append_basic(dict, "SessionMarker",
					DBUS_TYPE_UINT32, &session->marker);
}

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

	append_notify_all(&dict, session);

	connman_dbus_dict_close(&array, &dict);

	g_dbus_send_message(connection, msg);

	return FALSE;
}

static gboolean service_changed(gpointer user_data)
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

	append_service(&dict, session);

	connman_dbus_dict_close(&array, &dict);

	g_dbus_send_message(connection, msg);

	return FALSE;
}

static void online_changed(struct connman_session *session)
{
	connman_dbus_setting_changed_basic(session->owner, session->notify_path,
						"Online", DBUS_TYPE_BOOLEAN,
						&session->online);
}

static void ipconfig_ipv4_changed(struct connman_session *session)
{
	connman_dbus_setting_changed_dict(session->owner, session->notify_path,
					"IPv4", append_ipconfig_ipv4, session->service);
}

static void ipconfig_ipv6_changed(struct connman_session *session)
{
	connman_dbus_setting_changed_dict(session->owner, session->notify_path,
					"IPv6", append_ipconfig_ipv6, session->service);
}

static void update_service(struct connman_session *session)
{
	int idx;

	if (session->service != NULL) {
		session->bearer = session2bearer(session);
		session->online =
			__connman_service_is_connected(session->service);
		session->name = __connman_service_get_name(session->service);
		idx = __connman_service_get_index(session->service);
		session->ifname = connman_inet_ifname(idx);

	} else {
		session->bearer = "";
		session->online = FALSE;
		session->name = "";
		session->ifname = "";
	}
}

static connman_bool_t service_match(struct connman_session *session,
					struct connman_service *service)
{
	GSList *list;

	DBG("session %p service %p", session, service);

	for (list = session->allowed_bearers; list != NULL; list = list->next) {
		struct bearer_info *info = list->data;
		enum connman_service_type service_type;

		if (info->match_all == TRUE)
			return TRUE;

		service_type = connman_service_get_type(service);
		if (info->service_type == service_type)
			return TRUE;
	}

	return FALSE;
}

static connman_bool_t session_select_service(struct connman_session *session)
{
	struct connman_service *service;
	GSequenceIter *iter;

	session->service_list =
		__connman_service_get_list(session, service_match);

	if (session->service_list == NULL)
		return FALSE;

	iter = g_sequence_get_begin_iter(session->service_list);

	while (g_sequence_iter_is_end(iter) == FALSE) {
		service = g_sequence_get(iter);

		if (__connman_service_is_connected(service) == TRUE) {
			session->service = service;
			return TRUE;
		}
		iter = g_sequence_iter_next(iter);
	}

	return FALSE;
}

static void print_name(gpointer data, gpointer user_data)
{
	struct connman_service *service = data;

	DBG("service %p name %s", service,
		__connman_service_get_name(service));
}

static void cleanup_session(gpointer user_data)
{
	struct connman_session *session = user_data;

	DBG("remove %s", session->session_path);

	g_sequence_free(session->service_list);

	g_slist_foreach(session->allowed_bearers, cleanup_bearer_info, NULL);
	g_slist_free(session->allowed_bearers);

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
	int err;

	DBG("session %p", session);

	if (session->service_list != NULL)
		g_sequence_free(session->service_list);

	session->service_list = __connman_service_get_list(session,
								service_match);

	g_sequence_foreach(session->service_list, print_name, NULL);

	err = __connman_service_session_connect(session->service_list,
						&session->service);
	if (err < 0)
		return __connman_error_failed(msg, -err);

	update_service(session);
	g_timeout_add_seconds(0, service_changed, session);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *disconnect_session(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_session *session = user_data;
	int err;

	DBG("session %p", session);

	if (session->service == NULL)
		return __connman_error_already_disabled(msg);

	err = __connman_service_disconnect(session->service);
	if (err < 0)
		return __connman_error_failed(msg, -err);

	session->service = NULL;
	update_service(session);
	g_timeout_add_seconds(0, service_changed, session);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *change_session(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_session *session = user_data;
	DBusMessageIter iter, value;
	DBusMessage *reply;
	DBusMessageIter reply_array, reply_dict;
	const char *name;
	GSList *allowed_bearers;

	DBG("session %p", session);
	if (dbus_message_iter_init(msg, &iter) == FALSE)
		return __connman_error_invalid_arguments(msg);

	reply = dbus_message_new_method_call(session->owner,
						session->notify_path,
						CONNMAN_NOTIFICATION_INTERFACE,
						"Update");
	if (reply == NULL)
		return __connman_error_failed(msg, ENOMEM);

	dbus_message_iter_init_append(reply, &reply_array);
	connman_dbus_dict_open(&reply_array, &reply_dict);

	dbus_message_iter_get_basic(&iter, &name);
	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &value);

	switch (dbus_message_iter_get_arg_type(&value)) {
	case DBUS_TYPE_ARRAY:
		if (g_str_equal(name, "AllowedBearers") == TRUE) {
			allowed_bearers = session_parse_allowed_bearers(&value);

			g_slist_foreach(session->allowed_bearers,
					cleanup_bearer_info, NULL);
			g_slist_free(session->allowed_bearers);

			if (allowed_bearers == NULL) {
				allowed_bearers = session_allowed_bearers_any();

				if (allowed_bearers == NULL) {
					dbus_message_unref(reply);
					return __connman_error_failed(msg, ENOMEM);
				}
			}

			session->allowed_bearers = allowed_bearers;

			/* update_allowed_bearers(); */

			connman_dbus_dict_append_array(&reply_dict,
							"AllowedBearers",
							DBUS_TYPE_STRING,
							append_allowed_bearers,
							session);
		}
		break;
	case DBUS_TYPE_BOOLEAN:
		if (g_str_equal(name, "Priority") == TRUE) {
			dbus_message_iter_get_basic(&value, &session->priority);

			/* update_priority(); */

			connman_dbus_dict_append_basic(&reply_dict, "Priority",
							DBUS_TYPE_BOOLEAN,
							&session->priority);

		} else if (g_str_equal(name, "AvoidHandover") == TRUE) {
			dbus_message_iter_get_basic(&value,
						&session->avoid_handover);

			/* update_avoid_handover(); */

			connman_dbus_dict_append_basic(&reply_dict,
						"AvoidHandover",
						DBUS_TYPE_BOOLEAN,
						&session->avoid_handover);

		} else if (g_str_equal(name, "StayConnected") == TRUE) {
			dbus_message_iter_get_basic(&value,
						&session->stay_connected);

			/* update_stay_connected(); */

			connman_dbus_dict_append_basic(&reply_dict,
						"StayConnected",
						DBUS_TYPE_BOOLEAN,
						&session->stay_connected);

		} else if (g_str_equal(name, "EmergencyCall") == TRUE) {
			dbus_message_iter_get_basic(&value, &session->ecall);

			/* update_ecall(); */

			connman_dbus_dict_append_basic(&reply_dict,
						"EmergencyCall",
						DBUS_TYPE_BOOLEAN,
						&session->ecall);

		}
		break;
	case DBUS_TYPE_UINT32:
		if (g_str_equal(name, "PeriodicConnect") == TRUE) {
			dbus_message_iter_get_basic(&value,
						&session->periodic_connect);

			/* update_periodic_update(); */

			connman_dbus_dict_append_basic(&reply_dict,
						"PeriodicConnect",
						DBUS_TYPE_UINT32,
						&session->periodic_connect);
		} else if (g_str_equal(name, "IdleTimeout") == TRUE) {
			dbus_message_iter_get_basic(&value,
						&session->idle_timeout);

			/* update_idle_timeout(); */

			connman_dbus_dict_append_basic(&reply_dict,
						"IdleTimeout",
						DBUS_TYPE_UINT32,
						&session->idle_timeout);
		}
		break;
	case DBUS_TYPE_STRING:
		if (g_str_equal(name, "RoamingPolicy") == TRUE) {
			const char *val;
			dbus_message_iter_get_basic(&value, &val);
			session->roaming_policy = string2roamingpolicy(val);

			/* update_roaming_allowed(); */

			val = roamingpolicy2string(session->roaming_policy);
			connman_dbus_dict_append_basic(&reply_dict,
						"RoamingPolicy",
						DBUS_TYPE_STRING,
						&val);
		}
		break;
	}

	connman_dbus_dict_close(&reply_array, &reply_dict);

	g_dbus_send_message(connection, reply);

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

	connman_bool_t priority = FALSE, avoid_handover = FALSE;
	connman_bool_t stay_connected = FALSE, ecall = FALSE;
	enum connman_session_roaming_policy roaming_policy =
				CONNMAN_SESSION_ROAMING_POLICY_FORBIDDEN;
	GSList *allowed_bearers = NULL;
	unsigned int periodic_connect = 0;
	unsigned int idle_timeout = 0;

	int err;

	owner = dbus_message_get_sender(msg);

	DBG("owner %s", owner);

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_recurse(&iter, &array);

	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key, *val;

		dbus_message_iter_recurse(&array, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		switch (dbus_message_iter_get_arg_type(&value)) {
		case DBUS_TYPE_ARRAY:
			if (g_str_equal(key, "AllowedBearers") == TRUE) {
				allowed_bearers =
					session_parse_allowed_bearers(&value);
			}
			break;
		case DBUS_TYPE_BOOLEAN:
			if (g_str_equal(key, "Priority") == TRUE) {
				dbus_message_iter_get_basic(&value,
							&priority);
			} else if (g_str_equal(key, "AvoidHandover") == TRUE) {
				dbus_message_iter_get_basic(&value,
							&avoid_handover);
			} else if (g_str_equal(key, "StayConnected") == TRUE) {
				dbus_message_iter_get_basic(&value,
							&stay_connected);
			} else if (g_str_equal(key, "EmergencyCall") == TRUE) {
				dbus_message_iter_get_basic(&value,
							&ecall);
			}
			break;
		case DBUS_TYPE_UINT32:
			if (g_str_equal(key, "PeriodicConnect") == TRUE) {
				dbus_message_iter_get_basic(&value,
							&periodic_connect);
			} else if (g_str_equal(key, "IdleTimeout") == TRUE) {
				dbus_message_iter_get_basic(&value,
							&idle_timeout);
			}
			break;
		case DBUS_TYPE_STRING:

			if (g_str_equal(key, "RoamingPolicy") == TRUE) {
				dbus_message_iter_get_basic(&value, &val);
				roaming_policy = string2roamingpolicy(val);
			}
		}
		dbus_message_iter_next(&array);
	}

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

	session->bearer = "";
	session->online = FALSE;
	session->priority = priority;
	session->avoid_handover = avoid_handover;
	session->stay_connected = stay_connected;
	session->periodic_connect = periodic_connect;
	session->idle_timeout = idle_timeout;
	session->ecall = ecall;
	session->roaming_policy = roaming_policy;

	if (session->allowed_bearers == NULL) {
		session->allowed_bearers = session_allowed_bearers_any();

		if (session->allowed_bearers == NULL) {
			err = -ENOMEM;
			goto err;
		}
	}

	session->service_list = NULL;

	update_service(session);

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


	/*
	 * Check if the session settings matches to a service which is
	 * a already connected
	 */
	if (session_select_service(session) == TRUE)
		update_service(session);

	g_timeout_add_seconds(0, session_notify_all, session);

	return 0;

err:
	connman_error("Failed to create session");
	g_free(session_path);

	g_slist_foreach(allowed_bearers, cleanup_bearer_info, NULL);
	g_slist_free(allowed_bearers);

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

static void service_state_changed(struct connman_service *service,
					enum connman_service_state state)
{
	GHashTableIter iter;
	gpointer key, value;
	struct connman_session *session;
	connman_bool_t online;

	DBG("service %p state %d", service, state);

	g_hash_table_iter_init(&iter, session_hash);

	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		session = value;

		if (session->service == service) {
			online = __connman_service_is_connected(service);
			if (session->online != online)
				continue;

			session->online = online;
			online_changed(session);
		}
	}
}

static void ipconfig_changed(struct connman_service *service,
				struct connman_ipconfig *ipconfig)
{
	GHashTableIter iter;
	gpointer key, value;
	struct connman_session *session;
	enum connman_ipconfig_type type;

	DBG("service %p ipconfig %p", service, ipconfig);

	type = __connman_ipconfig_get_config_type(ipconfig);

	g_hash_table_iter_init(&iter, session_hash);

	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		session = value;

		if (session->service == service) {
			if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
				ipconfig_ipv4_changed(session);
			else if (type == CONNMAN_IPCONFIG_TYPE_IPV6)
				ipconfig_ipv6_changed(session);
		}
	}
}

static struct connman_notifier session_notifier = {
	.name			= "session",
	.service_state_changed	= service_state_changed,
	.ipconfig_changed	= ipconfig_changed,
};

int __connman_session_init(void)
{
	int err;

	DBG("");

	connection = connman_dbus_get_connection();
	if (connection == NULL)
		return -1;

	err = connman_notifier_register(&session_notifier);
	if (err < 0) {
		dbus_connection_unref(connection);
		return err;
	}

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

	connman_notifier_unregister(&session_notifier);

	g_hash_table_foreach(session_hash, release_session, NULL);
	g_hash_table_destroy(session_hash);

	dbus_connection_unref(connection);
}
