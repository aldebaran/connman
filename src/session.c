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
static struct connman_session *ecall_session;

enum connman_session_trigger {
	CONNMAN_SESSION_TRIGGER_UNKNOWN		= 0,
	CONNMAN_SESSION_TRIGGER_SETTING		= 1,
	CONNMAN_SESSION_TRIGGER_CONNECT		= 2,
	CONNMAN_SESSION_TRIGGER_DISCONNECT	= 3,
	CONNMAN_SESSION_TRIGGER_PERIODIC	= 4,
	CONNMAN_SESSION_TRIGGER_SERVICE		= 5,
	CONNMAN_SESSION_TRIGGER_ECALL		= 6,
};

enum connman_session_roaming_policy {
	CONNMAN_SESSION_ROAMING_POLICY_UNKNOWN		= 0,
	CONNMAN_SESSION_ROAMING_POLICY_DEFAULT		= 1,
	CONNMAN_SESSION_ROAMING_POLICY_ALWAYS		= 2,
	CONNMAN_SESSION_ROAMING_POLICY_FORBIDDEN	= 3,
	CONNMAN_SESSION_ROAMING_POLICY_NATIONAL		= 4,
	CONNMAN_SESSION_ROAMING_POLICY_INTERNATIONAL	= 5,
};

struct session_info {
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

	struct connman_service *service;
};

struct connman_session {
	char *owner;
	char *session_path;
	char *notify_path;
	guint notify_watch;

	connman_bool_t append_all;
	connman_bool_t info_dirty;
	struct session_info info;
	struct session_info info_last;

	GSequence *service_list;
};

struct bearer_info {
	char *name;
	connman_bool_t match_all;
	enum connman_service_type service_type;
};

static const char *trigger2string(enum connman_session_trigger trigger)
{
	switch (trigger) {
	case CONNMAN_SESSION_TRIGGER_UNKNOWN:
		break;
	case CONNMAN_SESSION_TRIGGER_SETTING:
		return "setting";
	case CONNMAN_SESSION_TRIGGER_CONNECT:
		return "connect";
	case CONNMAN_SESSION_TRIGGER_DISCONNECT:
		return "disconnect";
	case CONNMAN_SESSION_TRIGGER_PERIODIC:
		return "periodic";
	case CONNMAN_SESSION_TRIGGER_SERVICE:
		return "service";
	case CONNMAN_SESSION_TRIGGER_ECALL:
		return "ecall";
	}

	return NULL;
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
		return "";
	}

	return "";
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
	struct session_info *info = user_data;
	GSList *list;

	for (list = info->allowed_bearers;
			list != NULL; list = list->next) {
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

static void append_notify(DBusMessageIter *dict,
					struct connman_session *session)
{
	struct session_info *info = &session->info;
	struct session_info *info_last = &session->info_last;
	const char *policy;

	if (session->append_all == TRUE ||
			info->bearer != info_last->bearer) {
		connman_dbus_dict_append_basic(dict, "Bearer",
						DBUS_TYPE_STRING,
						&info->bearer);
		info_last->bearer = info->bearer;
	}

	if (session->append_all == TRUE ||
			info->online != info_last->online) {
		connman_dbus_dict_append_basic(dict, "Online",
						DBUS_TYPE_BOOLEAN,
						&info->online);
		info_last->online = info->online;
	}

	if (session->append_all == TRUE ||
			info->name != info_last->name) {
		connman_dbus_dict_append_basic(dict, "Name",
						DBUS_TYPE_STRING,
						&info->name);
		info_last->name = info->name;
	}

	if (session->append_all == TRUE ||
			info->service != info_last->service) {
		connman_dbus_dict_append_dict(dict, "IPv4",
						append_ipconfig_ipv4,
						info->service);

		connman_dbus_dict_append_dict(dict, "IPv6",
						append_ipconfig_ipv6,
						info->service);

		connman_dbus_dict_append_basic(dict, "Interface",
						DBUS_TYPE_STRING,
						&info->ifname);

		info_last->ifname = info->ifname;
		info_last->service = info->service;
	}


	if (session->append_all == TRUE ||
			info->priority != info_last->priority) {
		connman_dbus_dict_append_basic(dict, "Priority",
						DBUS_TYPE_BOOLEAN,
						&info->priority);
		info_last->priority = info->priority;
	}

	if (session->append_all == TRUE ||
			info->allowed_bearers != info_last->allowed_bearers) {
		connman_dbus_dict_append_array(dict, "AllowedBearers",
						DBUS_TYPE_STRING,
						append_allowed_bearers,
						info);
		info_last->allowed_bearers = info->allowed_bearers;
	}

	if (session->append_all == TRUE ||
			info->avoid_handover != info_last->avoid_handover) {
		connman_dbus_dict_append_basic(dict, "AvoidHandover",
						DBUS_TYPE_BOOLEAN,
						&info->avoid_handover);
		info_last->avoid_handover = info->avoid_handover;
	}

	if (session->append_all == TRUE ||
			info->stay_connected != info_last->stay_connected) {
		connman_dbus_dict_append_basic(dict, "StayConnected",
						DBUS_TYPE_BOOLEAN,
						&info->stay_connected);
		info_last->stay_connected = info->stay_connected;
	}

	if (session->append_all == TRUE ||
			info->periodic_connect != info_last->periodic_connect) {
		connman_dbus_dict_append_basic(dict, "PeriodicConnect",
						DBUS_TYPE_UINT32,
						&info->periodic_connect);
		info_last->periodic_connect = info->periodic_connect;
	}

	if (session->append_all == TRUE ||
			info->idle_timeout != info_last->idle_timeout) {
		connman_dbus_dict_append_basic(dict, "IdleTimeout",
						DBUS_TYPE_UINT32,
						&info->idle_timeout);
		info_last->idle_timeout = info->idle_timeout;
	}

	if (session->append_all == TRUE ||
			info->ecall != info_last->ecall) {
		connman_dbus_dict_append_basic(dict, "EmergencyCall",
						DBUS_TYPE_BOOLEAN,
						&info->ecall);
		info_last->ecall = info->ecall;
	}

	if (session->append_all == TRUE ||
			info->roaming_policy != info_last->roaming_policy) {
		policy = roamingpolicy2string(info->roaming_policy);
		connman_dbus_dict_append_basic(dict, "RoamingPolicy",
						DBUS_TYPE_STRING,
						&policy);
		info_last->roaming_policy = info->roaming_policy;
	}

	if (session->append_all == TRUE ||
			info->marker != info_last->marker) {
		connman_dbus_dict_append_basic(dict, "SessionMarker",
						DBUS_TYPE_UINT32,
						&info->marker);
		info_last->marker = info->marker;
	}

	session->append_all = FALSE;
	session->info_dirty = FALSE;
}

static gboolean session_notify(gpointer user_data)
{
	struct connman_session *session = user_data;
	DBusMessage *msg;
	DBusMessageIter array, dict;

	if (session->info_dirty == FALSE)
		return 0;

	DBG("session %p owner %s notify_path %s", session,
		session->owner, session->notify_path);

	msg = dbus_message_new_method_call(session->owner, session->notify_path,
						CONNMAN_NOTIFICATION_INTERFACE,
						"Update");
	if (msg == NULL)
		return FALSE;

	dbus_message_iter_init_append(msg, &array);
	connman_dbus_dict_open(&array, &dict);

	append_notify(&dict, session);

	connman_dbus_dict_close(&array, &dict);

	g_dbus_send_message(connection, msg);

	session->info_dirty = FALSE;

	return FALSE;
}

static void ipconfig_ipv4_changed(struct connman_session *session)
{
	struct session_info *info = &session->info;

	connman_dbus_setting_changed_dict(session->owner, session->notify_path,
						"IPv4", append_ipconfig_ipv4,
						info->service);
}

static void ipconfig_ipv6_changed(struct connman_session *session)
{
	struct session_info *info = &session->info;

	connman_dbus_setting_changed_dict(session->owner, session->notify_path,
						"IPv6", append_ipconfig_ipv6,
						info->service);
}

static GSequenceIter *lookup_service(struct connman_session *session,
					struct connman_service *service)
{
	GSequenceIter *iter;

	if (service == NULL)
		return NULL;

	iter = g_sequence_get_begin_iter(session->service_list);

	while (g_sequence_iter_is_end(iter) == FALSE) {
		struct connman_service *service_iter = g_sequence_get(iter);

		if (service_iter == service)
			return iter;

		iter = g_sequence_iter_next(iter);
	}

	return NULL;
}

static connman_bool_t service_type_match(struct connman_session *session,
					struct connman_service *service)
{
	struct session_info *info = &session->info;
	GSList *list;

	for (list = info->allowed_bearers;
			list != NULL; list = list->next) {
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

static connman_bool_t service_match(struct connman_session *session,
					struct connman_service *service)
{
	if (service_type_match(session, service) == FALSE)
		return FALSE;

	return TRUE;
}

static int service_type_weight(enum connman_service_type type)
{
	/*
	 * The session doesn't care which service
	 * to use. Nevertheless we have to sort them
	 * according their type. The ordering is
	 *
	 * 1. Ethernet
	 * 2. Bluetooth
	 * 3. WiFi/WiMAX
	 * 4. GSM/UTMS/3G
	 */

	switch (type) {
	case CONNMAN_SERVICE_TYPE_ETHERNET:
		return 4;
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
		return 3;
	case CONNMAN_SERVICE_TYPE_WIFI:
	case CONNMAN_SERVICE_TYPE_WIMAX:
		return 2;
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		return 1;
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_VPN:
	case CONNMAN_SERVICE_TYPE_GADGET:
		break;
	}

	return 0;
}

static gint sort_allowed_bearers(struct connman_service *service_a,
					struct connman_service *service_b,
					struct connman_session *session)
{
	struct session_info *info = &session->info;
	GSList *list;
	enum connman_service_type type_a, type_b;
	int weight_a, weight_b;

	type_a = connman_service_get_type(service_a);
	type_b = connman_service_get_type(service_b);

	for (list = info->allowed_bearers;
			list != NULL; list = list->next) {
		struct bearer_info *info = list->data;

		if (info->match_all == TRUE) {
			if (type_a != type_b) {
				weight_a = service_type_weight(type_a);
				weight_b = service_type_weight(type_b);

				if (weight_a > weight_b)
					return -1;

				if (weight_a < weight_b)
					return 1;

				return 0;
			}
		}

		if (type_a == info->service_type &&
				type_b == info->service_type) {
			return 0;
		}

		if (type_a == info->service_type &&
				type_b != info->service_type) {
			return -1;
		}

		if (type_a != info->service_type &&
				type_b == info->service_type) {
			return 1;
		}
	}

	return 0;
}

static gint sort_services(gconstpointer a, gconstpointer b, gpointer user_data)
{
	struct connman_service *service_a = (void *)a;
	struct connman_service *service_b = (void *)b;
	struct connman_session *session = user_data;

	return sort_allowed_bearers(service_a, service_b, session);
}

static void cleanup_session(gpointer user_data)
{
	struct connman_session *session = user_data;
	struct session_info *info = &session->info;

	DBG("remove %s", session->session_path);

	g_sequence_free(session->service_list);

	g_slist_foreach(info->allowed_bearers, cleanup_bearer_info, NULL);
	g_slist_free(info->allowed_bearers);

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

static void update_info(struct session_info *info)
{
	enum connman_service_type type;
	int idx;

	if (info->service != NULL) {
		type = connman_service_get_type(info->service);
		info->bearer = service2bearer(type);

		info->online = __connman_service_is_connected(info->service);
		info->name = __connman_service_get_name(info->service);
		if (info->name == NULL)
			info->name = "";

		idx = __connman_service_get_index(info->service);
		info->ifname = connman_inet_ifname(idx);
		if (info->ifname == NULL)
			info->ifname = "";
	} else {
		info->bearer = "";
		info->online = FALSE;
		info->name = "";
		info->ifname = "";
	}
}

static void select_and_connect(struct connman_session *session,
				connman_bool_t do_connect)
{
	struct session_info *info = &session->info;
	struct connman_service *service = NULL;
	GSequenceIter *iter;

	DBG("session %p connect %d", session, do_connect);

	iter = g_sequence_get_begin_iter(session->service_list);

	while (g_sequence_iter_is_end(iter) == FALSE) {
		service = g_sequence_get(iter);

		if (__connman_service_is_connecting(service) == TRUE ||
				__connman_service_is_connected(service) == TRUE) {
			break;
		}

		if (__connman_service_is_idle(service) == TRUE &&
				do_connect == TRUE) {
			break;
		}

		service = NULL;

		iter = g_sequence_iter_next(iter);
	}

	if (info->service != NULL && info->service != service) {
		__connman_service_disconnect(info->service);
		info->service = NULL;
	}

	if (service != NULL) {
		info->service = service;

		if (do_connect == TRUE)
			__connman_service_connect(info->service);
	}
}

static void session_changed(struct connman_session *session,
				enum connman_session_trigger trigger)
{
	struct session_info *info = &session->info;
	struct session_info *info_last = &session->info_last;
	GSequenceIter *iter;

	/*
	 * TODO: This only a placeholder for the 'real' algorithm to
	 * play a bit around. So we are going to improve it step by step.
	 */

	DBG("session %p trigger %s", session, trigger2string(trigger));

	switch (trigger) {
	case CONNMAN_SESSION_TRIGGER_UNKNOWN:
		DBG("ignore session changed event");
		return;
	case CONNMAN_SESSION_TRIGGER_SETTING:
		if (info->service != NULL) {
			iter = lookup_service(session, info->service);
			if (iter == NULL) {
				/*
				 * This service is not part of this
				 * session anymore.
				 */

				__connman_service_disconnect(info->service);
				info->service = NULL;
			}
		}

		/* Try to free ride */
		if (info->online == FALSE)
			select_and_connect(session, FALSE);

		break;
	case CONNMAN_SESSION_TRIGGER_CONNECT:
		if (info->online == TRUE)
			break;

		select_and_connect(session, TRUE);

		break;
	case CONNMAN_SESSION_TRIGGER_DISCONNECT:
		if (info->online == FALSE)
			break;

		if (info->service != NULL)
			__connman_service_disconnect(info->service);

		info->service = NULL;

		break;
	case CONNMAN_SESSION_TRIGGER_PERIODIC:
		select_and_connect(session, TRUE);

		break;
	case CONNMAN_SESSION_TRIGGER_SERVICE:
		if (info->online == TRUE)
			break;

		if (info->stay_connected == TRUE) {
			DBG("StayConnected");
			select_and_connect(session, TRUE);

			break;
		}

		/* Try to free ride */
		select_and_connect(session, FALSE);

		break;
	case CONNMAN_SESSION_TRIGGER_ECALL:
		if (info->online == FALSE && info->service != NULL)
			info->service = NULL;

		break;
	}

	if (info->service != info_last->service) {
		update_info(info);
		session->info_dirty = TRUE;
	}

	session_notify(session);
}

static DBusMessage *connect_session(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_session *session = user_data;

	DBG("session %p", session);

	if (ecall_session != NULL && ecall_session != session)
		return __connman_error_failed(msg, EBUSY);

	session_changed(session, CONNMAN_SESSION_TRIGGER_CONNECT);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *disconnect_session(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_session *session = user_data;

	DBG("session %p", session);

	if (ecall_session != NULL && ecall_session != session)
		return __connman_error_failed(msg, EBUSY);

	session_changed(session, CONNMAN_SESSION_TRIGGER_DISCONNECT);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static void print_name(gpointer data, gpointer user_data)
{
	struct connman_service *service = data;

	DBG("service %p type %s name %s", service,
		service2bearer(connman_service_get_type(service)),
		__connman_service_get_name(service));
}

static void update_allowed_bearers(struct connman_session *session)
{
	if (session->service_list != NULL)
		g_sequence_free(session->service_list);

	session->service_list = __connman_service_get_list(session,
								service_match);
	g_sequence_sort(session->service_list, sort_services, session);
	g_sequence_foreach(session->service_list, print_name, NULL);

	session->info_dirty = TRUE;
}

static void update_ecall_sessions(struct connman_session *session)
{
	struct session_info *info = &session->info;
	struct connman_session *session_iter;
	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init(&iter, session_hash);

	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		session_iter = value;

		if (session_iter == session)
			continue;

		session_iter->info.ecall = info->ecall;
		session_iter->info_dirty = TRUE;

		session_changed(session_iter, CONNMAN_SESSION_TRIGGER_ECALL);
	}
}

static void update_ecall(struct connman_session *session)
{
	struct session_info *info = &session->info;
	struct session_info *info_last = &session->info_last;

	DBG("session %p ecall_session %p ecall %d -> %d", session,
		ecall_session, info_last->ecall, info->ecall);

	if (ecall_session == NULL) {
		if (!(info_last->ecall == FALSE && info->ecall == TRUE))
			goto err;

		ecall_session = session;
	} else if (ecall_session == session) {
		if (!(info_last->ecall == TRUE && info->ecall == FALSE))
			goto err;

		ecall_session = NULL;
	} else {
		goto err;
	}

	update_ecall_sessions(session);

	session->info_dirty = TRUE;
	return;

err:
	/* not a valid transition */
	info->ecall = info_last->ecall;
}

static DBusMessage *change_session(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_session *session = user_data;
	struct session_info *info = &session->info;
	struct session_info *info_last = &session->info_last;
	DBusMessageIter iter, value;
	const char *name;
	GSList *allowed_bearers;

	DBG("session %p", session);
	if (dbus_message_iter_init(msg, &iter) == FALSE)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &name);
	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &value);

	switch (dbus_message_iter_get_arg_type(&value)) {
	case DBUS_TYPE_ARRAY:
		if (g_str_equal(name, "AllowedBearers") == TRUE) {
			allowed_bearers = session_parse_allowed_bearers(&value);

			g_slist_foreach(info->allowed_bearers,
					cleanup_bearer_info, NULL);
			g_slist_free(info->allowed_bearers);

			if (allowed_bearers == NULL) {
				allowed_bearers = session_allowed_bearers_any();

				if (allowed_bearers == NULL)
					return __connman_error_failed(msg, ENOMEM);
			}

			info->allowed_bearers = allowed_bearers;

			update_allowed_bearers(session);
		} else {
			goto err;
		}
		break;
	case DBUS_TYPE_BOOLEAN:
		if (g_str_equal(name, "Priority") == TRUE) {
			dbus_message_iter_get_basic(&value,
					&info->priority);

			if (info_last->priority != info->priority)
				session->info_dirty = TRUE;
		} else if (g_str_equal(name, "AvoidHandover") == TRUE) {
			dbus_message_iter_get_basic(&value,
					&info->avoid_handover);

			if (info_last->avoid_handover != info->avoid_handover)
				session->info_dirty = TRUE;
		} else if (g_str_equal(name, "StayConnected") == TRUE) {
			dbus_message_iter_get_basic(&value,
					&info->stay_connected);

			if (info_last->stay_connected != info->stay_connected)
				session->info_dirty = TRUE;
		} else if (g_str_equal(name, "EmergencyCall") == TRUE) {
			dbus_message_iter_get_basic(&value,
					&info->ecall);

			update_ecall(session);
		} else {
			goto err;
		}
		break;
	case DBUS_TYPE_UINT32:
		if (g_str_equal(name, "PeriodicConnect") == TRUE) {
			dbus_message_iter_get_basic(&value,
					&info->periodic_connect);

			if (info_last->periodic_connect != info->periodic_connect)
				session->info_dirty = TRUE;
		} else if (g_str_equal(name, "IdleTimeout") == TRUE) {
			dbus_message_iter_get_basic(&value,
					&info->idle_timeout);

			if (info_last->idle_timeout != info->idle_timeout)
				session->info_dirty = TRUE;
		} else {
			goto err;
		}
		break;
	case DBUS_TYPE_STRING:
		if (g_str_equal(name, "RoamingPolicy") == TRUE) {
			const char *val;
			dbus_message_iter_get_basic(&value, &val);
			info->roaming_policy =
					string2roamingpolicy(val);

			if (info_last->roaming_policy != info->roaming_policy)
				session->info_dirty = TRUE;
		} else {
			goto err;
		}
		break;
	default:
		goto err;
	}

	if (session->info_dirty == TRUE)
		session_changed(session, CONNMAN_SESSION_TRIGGER_SETTING);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);

err:
	return __connman_error_invalid_arguments(msg);
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
	char *session_path = NULL;
	DBusMessageIter iter, array;
	struct connman_session *session;
	struct session_info *info, *info_last;

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

	if (ecall_session != NULL) {
		/*
		 * If there is an emergency call already going on,
		 * ignore session creation attempt
		 */
		err = -EBUSY;
		goto err;
	}

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
			} else {
				return -EINVAL;
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
			} else {
				return -EINVAL;
			}
			break;
		case DBUS_TYPE_UINT32:
			if (g_str_equal(key, "PeriodicConnect") == TRUE) {
				dbus_message_iter_get_basic(&value,
							&periodic_connect);
			} else if (g_str_equal(key, "IdleTimeout") == TRUE) {
				dbus_message_iter_get_basic(&value,
							&idle_timeout);
			} else {
				return -EINVAL;
			}
			break;
		case DBUS_TYPE_STRING:
			if (g_str_equal(key, "RoamingPolicy") == TRUE) {
				dbus_message_iter_get_basic(&value, &val);
				roaming_policy = string2roamingpolicy(val);
			} else {
				return -EINVAL;
			}
		}
		dbus_message_iter_next(&array);
	}

	dbus_message_iter_next(&iter);
	dbus_message_iter_get_basic(&iter, &notify_path);

	if (notify_path == NULL) {
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

	info = &session->info;
	info_last = &session->info_last;

	session->owner = g_strdup(owner);
	session->session_path = session_path;
	session->notify_path = g_strdup(notify_path);
	session->notify_watch =
		g_dbus_add_disconnect_watch(connection, session->owner,
					owner_disconnect, session, NULL);

	info->bearer = "";
	info->online = FALSE;
	info->priority = priority;
	info->avoid_handover = avoid_handover;
	info->stay_connected = stay_connected;
	info->periodic_connect = periodic_connect;
	info->idle_timeout = idle_timeout;
	info->ecall = ecall;
	info->roaming_policy = roaming_policy;
	info->service = NULL;
	info->marker = 0;

	if (allowed_bearers == NULL) {
		info->allowed_bearers =
				session_allowed_bearers_any();

		if (info->allowed_bearers == NULL) {
			err = -ENOMEM;
			goto err;
		}
	} else {
		info->allowed_bearers = allowed_bearers;
	}

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


	update_allowed_bearers(session);
	update_info(info);
	if (info->ecall == TRUE) {
		ecall_session = session;
		update_ecall_sessions(session);
	}

	info_last->bearer = info->bearer;
	info_last->online = info->online;
	info_last->priority = info->priority;
	info_last->avoid_handover = info->avoid_handover;
	info_last->stay_connected = info->stay_connected;
	info_last->periodic_connect = info->periodic_connect;
	info_last->idle_timeout = info->idle_timeout;
	info_last->ecall = info->ecall;
	info_last->roaming_policy = info->roaming_policy;
	info_last->service = info->service;
	info_last->marker = info->marker;
	info_last->allowed_bearers = info->allowed_bearers;
	update_info(info_last);

	session->info_dirty = TRUE;
	session->append_all = TRUE;

	session_changed(session, CONNMAN_SESSION_TRIGGER_SETTING);

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

static void service_add(struct connman_service *service)
{
	GHashTableIter iter;
	gpointer key, value;
	struct connman_session *session;

	DBG("service %p", service);

	g_hash_table_iter_init(&iter, session_hash);

	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		session = value;

		if (service_match(session, service) == FALSE)
			continue;

		g_sequence_insert_sorted(session->service_list, service,
						sort_services, session);

		session_changed(session, CONNMAN_SESSION_TRIGGER_SERVICE);
	}
}

static int service_remove_from_session(struct connman_session *session,
					struct connman_service *service)
{
	GSequenceIter *iter;

	iter = lookup_service(session, service);
	if (iter == NULL)
		return -ENOENT;

	session->info.online = FALSE;
	g_sequence_remove(iter);

	return 0;
}

static void service_remove(struct connman_service *service)
{

	GHashTableIter iter;
	gpointer key, value;
	struct connman_session *session;
	struct session_info *info;

	DBG("service %p", service);

	g_hash_table_iter_init(&iter, session_hash);

	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		session = value;
		info = &session->info;

		if (service_remove_from_session(session, service) != 0)
			continue;

		info->service = NULL;
		session_changed(session, CONNMAN_SESSION_TRIGGER_SERVICE);
	}
}

static void service_state_changed(struct connman_service *service,
					enum connman_service_state state)
{
	GHashTableIter iter;
	gpointer key, value;
	struct connman_session *session;
	struct session_info *info, *info_last;

	DBG("service %p state %d", service, state);

	g_hash_table_iter_init(&iter, session_hash);

	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		session = value;
		info = &session->info;
		info_last = &session->info_last;

		if (info->service == service) {
			info->online = __connman_service_is_connected(service);
			if (info_last->online != info->online)
				session->info_dirty = TRUE;
		}

		session_changed(session,
				CONNMAN_SESSION_TRIGGER_SERVICE);
	}
}

static void ipconfig_changed(struct connman_service *service,
				struct connman_ipconfig *ipconfig)
{
	GHashTableIter iter;
	gpointer key, value;
	struct connman_session *session;
	struct session_info *info;
	enum connman_ipconfig_type type;

	DBG("service %p ipconfig %p", service, ipconfig);

	type = __connman_ipconfig_get_config_type(ipconfig);

	g_hash_table_iter_init(&iter, session_hash);

	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		session = value;
		info = &session->info;

		if (info->service == service) {
			if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
				ipconfig_ipv4_changed(session);
			else if (type == CONNMAN_IPCONFIG_TYPE_IPV6)
				ipconfig_ipv6_changed(session);
		}
	}
}

static struct connman_notifier session_notifier = {
	.name			= "session",
	.service_add		= service_add,
	.service_remove		= service_remove,
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
