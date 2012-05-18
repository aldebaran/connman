/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2012  Intel Corporation. All rights reserved.
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

#include <gdbus.h>

#include "connman.h"

static DBusConnection *connection;
static GHashTable *session_hash;
static connman_bool_t sessionmode;
static struct session_info *ecall_info;

enum connman_session_trigger {
	CONNMAN_SESSION_TRIGGER_UNKNOWN		= 0,
	CONNMAN_SESSION_TRIGGER_SETTING		= 1,
	CONNMAN_SESSION_TRIGGER_CONNECT		= 2,
	CONNMAN_SESSION_TRIGGER_DISCONNECT	= 3,
	CONNMAN_SESSION_TRIGGER_PERIODIC	= 4,
	CONNMAN_SESSION_TRIGGER_SERVICE		= 5,
	CONNMAN_SESSION_TRIGGER_ECALL		= 6,
};

enum connman_session_reason {
	CONNMAN_SESSION_REASON_UNKNOWN		= 0,
	CONNMAN_SESSION_REASON_CONNECT		= 1,
	CONNMAN_SESSION_REASON_DISCONNECT	= 2,
	CONNMAN_SESSION_REASON_FREE_RIDE	= 3,
	CONNMAN_SESSION_REASON_PERIODIC		= 4,
};

enum connman_session_state {
	CONNMAN_SESSION_STATE_DISCONNECTED   = 0,
	CONNMAN_SESSION_STATE_CONNECTED      = 1,
	CONNMAN_SESSION_STATE_ONLINE         = 2,
};

enum connman_session_type {
	CONNMAN_SESSION_TYPE_ANY      = 0,
	CONNMAN_SESSION_TYPE_LOCAL    = 1,
	CONNMAN_SESSION_TYPE_INTERNET = 2,
};

enum connman_session_roaming_policy {
	CONNMAN_SESSION_ROAMING_POLICY_UNKNOWN		= 0,
	CONNMAN_SESSION_ROAMING_POLICY_DEFAULT		= 1,
	CONNMAN_SESSION_ROAMING_POLICY_ALWAYS		= 2,
	CONNMAN_SESSION_ROAMING_POLICY_FORBIDDEN	= 3,
	CONNMAN_SESSION_ROAMING_POLICY_NATIONAL		= 4,
	CONNMAN_SESSION_ROAMING_POLICY_INTERNATIONAL	= 5,
};

struct service_entry {
	/* track why this service was selected */
	enum connman_session_reason reason;
	enum connman_service_state state;
	const char *name;
	struct connman_service *service;
	char *ifname;
	const char *bearer;
	GSList *pending_timeouts;
};

struct session_info {
	enum connman_session_state state;
	enum connman_session_type type;
	connman_bool_t priority;
	GSList *allowed_bearers;
	connman_bool_t avoid_handover;
	connman_bool_t stay_connected;
	unsigned int periodic_connect;
	unsigned int idle_timeout;
	connman_bool_t ecall;
	enum connman_session_roaming_policy roaming_policy;
	unsigned int marker;

	struct service_entry *entry;
	enum connman_session_reason reason;
};

struct connman_session {
	char *owner;
	char *session_path;
	char *notify_path;
	guint notify_watch;

	connman_bool_t append_all;
	struct session_info *info;
	struct session_info *info_last;

	GSequence *service_list;
	GHashTable *service_hash;
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

static const char *reason2string(enum connman_session_reason reason)
{
	switch (reason) {
	case CONNMAN_SESSION_REASON_UNKNOWN:
		return "unknown";
	case CONNMAN_SESSION_REASON_CONNECT:
		return "connect";
	case CONNMAN_SESSION_REASON_DISCONNECT:
		return "disconnect";
	case CONNMAN_SESSION_REASON_FREE_RIDE:
		return "free-ride";
	case CONNMAN_SESSION_REASON_PERIODIC:
		return "periodic";
	}

	return NULL;
}

static const char *state2string(enum connman_session_state state)
{
	switch (state) {
	case CONNMAN_SESSION_STATE_DISCONNECTED:
		return "disconnected";
	case CONNMAN_SESSION_STATE_CONNECTED:
		return "connected";
	case CONNMAN_SESSION_STATE_ONLINE:
		return "online";
	}

	return NULL;
}

static const char *type2string(enum connman_session_type type)
{
	switch (type) {
	case CONNMAN_SESSION_TYPE_ANY:
		return "";
	case CONNMAN_SESSION_TYPE_LOCAL:
		return "local";
	case CONNMAN_SESSION_TYPE_INTERNET:
		return "internet";
	}

	return NULL;
}

static enum connman_session_type string2type(const char *type)
{
	if (g_strcmp0(type, "local") == 0)
		return CONNMAN_SESSION_TYPE_LOCAL;
	else if (g_strcmp0(type, "internet") == 0)
		return CONNMAN_SESSION_TYPE_INTERNET;

	return CONNMAN_SESSION_TYPE_ANY;
}

static const char *roamingpolicy2string(enum connman_session_roaming_policy policy)
{
	switch (policy) {
	case CONNMAN_SESSION_ROAMING_POLICY_UNKNOWN:
		return "unknown";
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
	else if (g_strcmp0(bearer, "cellular") == 0)
		return CONNMAN_SERVICE_TYPE_CELLULAR;
	else if (g_strcmp0(bearer, "vpn") == 0)
		return CONNMAN_SERVICE_TYPE_VPN;
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
		return "cellular";
	case CONNMAN_SERVICE_TYPE_VPN:
		return "vpn";
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
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

	if (__connman_service_is_connected_state(service,
				CONNMAN_IPCONFIG_TYPE_IPV4) == FALSE) {
		return;
	}

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

	if (__connman_service_is_connected_state(service,
				CONNMAN_IPCONFIG_TYPE_IPV6) == FALSE) {
		return;
	}

	ipconfig_ipv4 = __connman_service_get_ip4config(service);
	ipconfig_ipv6 = __connman_service_get_ip6config(service);
	if (ipconfig_ipv6 == NULL)
		return;

	__connman_ipconfig_append_ipv6(ipconfig_ipv6, iter, ipconfig_ipv4);
}

static void append_notify(DBusMessageIter *dict,
					struct connman_session *session)
{
	struct session_info *info = session->info;
	struct session_info *info_last = session->info_last;
	const char *policy;
	struct connman_service *service;
	const char *name, *ifname, *bearer;

	if (session->append_all == TRUE ||
			info->state != info_last->state) {
		const char *state = state2string(info->state);

		connman_dbus_dict_append_basic(dict, "State",
						DBUS_TYPE_STRING,
						&state);
		info_last->state = info->state;
	}

	if (session->append_all == TRUE ||
			info->entry != info_last->entry) {
		if (info->entry == NULL) {
			name = "";
			ifname = "";
			service = NULL;
			bearer = "";
		} else {
			name = info->entry->name;
			ifname = info->entry->ifname;
			service = info->entry->service;
			bearer = info->entry->bearer;
		}

		connman_dbus_dict_append_basic(dict, "Name",
						DBUS_TYPE_STRING,
						&name);

		connman_dbus_dict_append_dict(dict, "IPv4",
						append_ipconfig_ipv4,
						service);

		connman_dbus_dict_append_dict(dict, "IPv6",
						append_ipconfig_ipv6,
						service);

		connman_dbus_dict_append_basic(dict, "Interface",
						DBUS_TYPE_STRING,
						&ifname);

		connman_dbus_dict_append_basic(dict, "Bearer",
						DBUS_TYPE_STRING,
						&bearer);

		info_last->entry = info->entry;
	}

	if (session->append_all == TRUE || info->type != info_last->type) {
		const char *type = type2string(info->type);

		connman_dbus_dict_append_basic(dict, "ConnectionType",
						DBUS_TYPE_STRING,
						&type);
		info_last->type = info->type;
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
}

static connman_bool_t is_type_matching_state(enum connman_session_state *state,
						enum connman_session_type type)
{
	switch (type) {
	case CONNMAN_SESSION_TYPE_ANY:
		return TRUE;
	case CONNMAN_SESSION_TYPE_LOCAL:
		if (*state >= CONNMAN_SESSION_STATE_CONNECTED) {
			*state = CONNMAN_SESSION_STATE_CONNECTED;
			return TRUE;
		}

		break;
	case CONNMAN_SESSION_TYPE_INTERNET:
		if (*state == CONNMAN_SESSION_STATE_ONLINE)
			return TRUE;
		break;
	}

	return FALSE;
}

static connman_bool_t compute_notifiable_changes(struct connman_session *session)
{
	struct session_info *info_last = session->info_last;
	struct session_info *info = session->info;

	if (session->append_all == TRUE)
		return TRUE;

	if (info->state != info_last->state)
		return TRUE;

	if (info->entry != info_last->entry &&
			info->state >= CONNMAN_SESSION_STATE_CONNECTED)
		return TRUE;

	if (info->periodic_connect != info_last->periodic_connect ||
			info->allowed_bearers != info_last->allowed_bearers ||
			info->avoid_handover != info_last->avoid_handover ||
			info->stay_connected != info_last->stay_connected ||
			info->roaming_policy != info_last->roaming_policy ||
			info->idle_timeout != info_last->idle_timeout ||
			info->priority != info_last->priority ||
			info->marker != info_last->marker ||
			info->ecall != info_last->ecall ||
			info->type != info_last->type)
		return TRUE;

	return FALSE;
}

static gboolean session_notify(gpointer user_data)
{
	struct connman_session *session = user_data;
	DBusMessage *msg;
	DBusMessageIter array, dict;

	if (compute_notifiable_changes(session) == FALSE)
		return FALSE;

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

	return FALSE;
}

static void ipconfig_ipv4_changed(struct connman_session *session)
{
	struct session_info *info = session->info;

	connman_dbus_setting_changed_dict(session->owner, session->notify_path,
						"IPv4", append_ipconfig_ipv4,
						info->entry->service);
}

static void ipconfig_ipv6_changed(struct connman_session *session)
{
	struct session_info *info = session->info;

	connman_dbus_setting_changed_dict(session->owner, session->notify_path,
						"IPv6", append_ipconfig_ipv6,
						info->entry->service);
}

static connman_bool_t service_type_match(struct connman_session *session,
					struct connman_service *service)
{
	struct session_info *info = session->info;
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
	 * 4. Cellular
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
	struct session_info *info = session->info;
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
	struct service_entry *entry_a = (void *)a;
	struct service_entry *entry_b = (void *)b;
	struct connman_session *session = user_data;

	return sort_allowed_bearers(entry_a->service, entry_b->service,
				session);
}

static void cleanup_session(gpointer user_data)
{
	struct connman_session *session = user_data;
	struct session_info *info = session->info;

	DBG("remove %s", session->session_path);

	g_hash_table_destroy(session->service_hash);
	g_sequence_free(session->service_list);

	if (info->entry != NULL &&
			info->entry->reason == CONNMAN_SESSION_REASON_CONNECT) {
		__connman_service_disconnect(info->entry->service);
	}

	g_slist_foreach(info->allowed_bearers, cleanup_bearer_info, NULL);
	g_slist_free(info->allowed_bearers);

	g_free(session->owner);
	g_free(session->session_path);
	g_free(session->notify_path);
	g_free(session->info);
	g_free(session->info_last);

	g_free(session);
}

static enum connman_session_state service_to_session_state(enum connman_service_state state)
{
	switch (state) {
	case CONNMAN_SERVICE_STATE_UNKNOWN:
	case CONNMAN_SERVICE_STATE_IDLE:
	case CONNMAN_SERVICE_STATE_ASSOCIATION:
	case CONNMAN_SERVICE_STATE_CONFIGURATION:
	case CONNMAN_SERVICE_STATE_DISCONNECT:
	case CONNMAN_SERVICE_STATE_FAILURE:
		break;
	case CONNMAN_SERVICE_STATE_READY:
		return CONNMAN_SESSION_STATE_CONNECTED;
	case CONNMAN_SERVICE_STATE_ONLINE:
		return CONNMAN_SESSION_STATE_ONLINE;
	}

	return CONNMAN_SESSION_STATE_DISCONNECTED;
}

static connman_bool_t is_connected(enum connman_service_state state)
{
	switch (state) {
	case CONNMAN_SERVICE_STATE_UNKNOWN:
	case CONNMAN_SERVICE_STATE_IDLE:
	case CONNMAN_SERVICE_STATE_ASSOCIATION:
	case CONNMAN_SERVICE_STATE_CONFIGURATION:
	case CONNMAN_SERVICE_STATE_DISCONNECT:
	case CONNMAN_SERVICE_STATE_FAILURE:
		break;
	case CONNMAN_SERVICE_STATE_READY:
	case CONNMAN_SERVICE_STATE_ONLINE:
		return TRUE;
	}

	return FALSE;
}

static connman_bool_t is_connecting(enum connman_service_state state)
{
	switch (state) {
	case CONNMAN_SERVICE_STATE_UNKNOWN:
	case CONNMAN_SERVICE_STATE_IDLE:
		break;
	case CONNMAN_SERVICE_STATE_ASSOCIATION:
	case CONNMAN_SERVICE_STATE_CONFIGURATION:
		return TRUE;
	case CONNMAN_SERVICE_STATE_DISCONNECT:
	case CONNMAN_SERVICE_STATE_FAILURE:
	case CONNMAN_SERVICE_STATE_READY:
	case CONNMAN_SERVICE_STATE_ONLINE:
		break;
	}

	return FALSE;
}

static connman_bool_t explicit_connect(enum connman_session_reason reason)
{
	switch (reason) {
	case CONNMAN_SESSION_REASON_UNKNOWN:
	case CONNMAN_SESSION_REASON_FREE_RIDE:
	case CONNMAN_SESSION_REASON_DISCONNECT:
		break;
	case CONNMAN_SESSION_REASON_CONNECT:
	case CONNMAN_SESSION_REASON_PERIODIC:
		return TRUE;
	}

	return FALSE;
}

static connman_bool_t explicit_disconnect(struct session_info *info)
{
	if (info->entry == NULL)
		return FALSE;

	DBG("reason %s service %p state %d",
		reason2string(info->entry->reason),
		info->entry->service, info->entry->state);

	if (info->entry->reason == CONNMAN_SESSION_REASON_UNKNOWN)
		return FALSE;

	if (explicit_connect(info->entry->reason) == FALSE)
		return FALSE;

	if (__connman_service_session_dec(info->entry->service) == FALSE)
		return FALSE;

	if (ecall_info != NULL && ecall_info != info)
		return FALSE;

	return TRUE;
}

struct pending_data {
	unsigned int timeout;
	struct service_entry *entry;
	gboolean (*cb)(gpointer);
};

static void pending_timeout_free(gpointer data, gpointer user_data)
{
	struct pending_data *pending = data;

	DBG("pending %p timeout %d", pending, pending->timeout);
	g_source_remove(pending->timeout);
	g_free(pending);
}

static void pending_timeout_remove_all(struct service_entry *entry)
{
	DBG("");

	g_slist_foreach(entry->pending_timeouts, pending_timeout_free, NULL);
	g_slist_free(entry->pending_timeouts);
	entry->pending_timeouts = NULL;
}

static gboolean pending_timeout_cb(gpointer data)
{
	struct pending_data *pending = data;
	struct service_entry *entry = pending->entry;
	gboolean ret;

	DBG("pending %p timeout %d", pending, pending->timeout);

	ret = pending->cb(pending->entry);
	if (ret == FALSE) {
		entry->pending_timeouts =
			g_slist_remove(entry->pending_timeouts,
					pending);
		g_free(pending);
	}
	return ret;
}

static connman_bool_t pending_timeout_add(unsigned int seconds,
					gboolean (*cb)(gpointer),
					struct service_entry *entry)
{
	struct pending_data *pending = g_try_new0(struct pending_data, 1);

	if (pending == NULL || cb == NULL || entry == NULL) {
		g_free(pending);
		return FALSE;
	}

	pending->cb = cb;
	pending->entry = entry;
	pending->timeout = g_timeout_add_seconds(seconds, pending_timeout_cb,
						pending);
	entry->pending_timeouts = g_slist_prepend(entry->pending_timeouts,
						pending);

	DBG("pending %p entry %p timeout id %d", pending, entry,
		pending->timeout);

	return TRUE;
}

static gboolean call_disconnect(gpointer user_data)
{
	struct service_entry *entry = user_data;
	struct connman_service *service = entry->service;

	/*
	 * TODO: We should mark this entry as pending work. In case
	 * disconnect fails we just unassign this session from the
	 * service and can't do anything later on it
	 */
	DBG("disconnect service %p", service);
	__connman_service_disconnect(service);

	return FALSE;
}

static gboolean call_connect(gpointer user_data)
{
	struct service_entry *entry = user_data;
	struct connman_service *service = entry->service;

	DBG("connect service %p", service);
	__connman_service_connect(service);

	return FALSE;
}

static void deselect_service(struct session_info *info)
{
	struct service_entry *entry;
	connman_bool_t disconnect, connected;

	DBG("");

	if (info->entry == NULL)
		return;

	disconnect = explicit_disconnect(info);

	connected = is_connecting(info->entry->state) == TRUE ||
			is_connected(info->entry->state) == TRUE;

	info->state = CONNMAN_SESSION_STATE_DISCONNECTED;
	info->entry->reason = CONNMAN_SESSION_REASON_UNKNOWN;

	entry = info->entry;
	info->entry = NULL;

	DBG("disconnect %d connected %d", disconnect, connected);

	if (disconnect == TRUE && connected == TRUE)
		pending_timeout_add(0, call_disconnect, entry);
}

static void deselect_and_disconnect(struct connman_session *session,
					enum connman_session_reason reason)
{
	struct session_info *info = session->info;

	deselect_service(info);

	info->reason = reason;
}

static void select_connected_service(struct session_info *info,
					struct service_entry *entry)
{
	enum connman_session_state state;

	state = service_to_session_state(entry->state);
	if (is_type_matching_state(&state, info->type) == FALSE)
		return;

	info->state = state;

	info->entry = entry;
	info->entry->reason = info->reason;

	if (explicit_connect(info->reason) == FALSE)
		return;

	__connman_service_session_inc(info->entry->service);
}

static void select_offline_service(struct session_info *info,
					struct service_entry *entry)
{
	if (explicit_connect(info->reason) == FALSE)
		return;

	info->state = service_to_session_state(entry->state);

	info->entry = entry;
	info->entry->reason = info->reason;

	__connman_service_session_inc(info->entry->service);
	pending_timeout_add(0, call_connect, entry);
}

static void select_service(struct session_info *info,
				struct service_entry *entry)
{
	DBG("service %p", entry->service);

	if (is_connected(entry->state) == TRUE)
		select_connected_service(info, entry);
	else
		select_offline_service(info, entry);
}

static void select_and_connect(struct connman_session *session,
				enum connman_session_reason reason)
{
	struct session_info *info = session->info;
	struct service_entry *entry = NULL;
	GSequenceIter *iter;

	DBG("session %p reason %s", session, reason2string(reason));

	info->reason = reason;

	iter = g_sequence_get_begin_iter(session->service_list);

	while (g_sequence_iter_is_end(iter) == FALSE) {
		entry = g_sequence_get(iter);

		switch (entry->state) {
		case CONNMAN_SERVICE_STATE_ASSOCIATION:
		case CONNMAN_SERVICE_STATE_CONFIGURATION:
		case CONNMAN_SERVICE_STATE_READY:
		case CONNMAN_SERVICE_STATE_ONLINE:
		case CONNMAN_SERVICE_STATE_IDLE:
		case CONNMAN_SERVICE_STATE_DISCONNECT:
			select_service(info, entry);
			return;
		case CONNMAN_SERVICE_STATE_UNKNOWN:
		case CONNMAN_SERVICE_STATE_FAILURE:
			break;
		}

		iter = g_sequence_iter_next(iter);
	}
}

static struct service_entry *create_service_entry(struct connman_service *service,
					const char *name,
					enum connman_service_state state)
{
	struct service_entry *entry;
	enum connman_service_type type;
	int idx;

	entry = g_try_new0(struct service_entry, 1);
	if (entry == NULL)
		return entry;

	entry->reason = CONNMAN_SESSION_REASON_UNKNOWN;
	entry->state = state;
	if (name != NULL)
		entry->name = name;
	else
		entry->name = "";
	entry->service = service;

	idx = __connman_service_get_index(entry->service);
	entry->ifname = connman_inet_ifname(idx);
	if (entry->ifname == NULL)
		entry->ifname = g_strdup("");

	type = connman_service_get_type(entry->service);
	entry->bearer = service2bearer(type);

	return entry;
}

static void destroy_service_entry(gpointer data)
{
	struct service_entry *entry = data;

	pending_timeout_remove_all(entry);
	g_free(entry->ifname);

	g_free(entry);
}

static void populate_service_list(struct connman_session *session)
{
	struct service_entry *entry;
	GSequenceIter *iter;

	session->service_hash =
		g_hash_table_new_full(g_direct_hash, g_direct_equal,
					NULL, NULL);
	session->service_list = __connman_service_get_list(session,
							service_match,
							create_service_entry,
							destroy_service_entry);

	g_sequence_sort(session->service_list, sort_services, session);

	iter = g_sequence_get_begin_iter(session->service_list);

	while (g_sequence_iter_is_end(iter) == FALSE) {
		entry = g_sequence_get(iter);

		DBG("service %p type %s name %s", entry->service,
			service2bearer(connman_service_get_type(entry->service)),
			entry->name);

		g_hash_table_replace(session->service_hash,
					entry->service, iter);

		iter = g_sequence_iter_next(iter);
	}
}

static void session_changed(struct connman_session *session,
				enum connman_session_trigger trigger)
{
	struct session_info *info = session->info;
	struct session_info *info_last = session->info_last;
	GSequenceIter *service_iter = NULL, *service_iter_last = NULL;
	GSequence *service_list_last;
	GHashTable *service_hash_last;

	/*
	 * TODO: This only a placeholder for the 'real' algorithm to
	 * play a bit around. So we are going to improve it step by step.
	 */

	DBG("session %p trigger %s reason %s", session, trigger2string(trigger),
						reason2string(info->reason));

	if (info->entry != NULL) {
		enum connman_session_state state;

		state = service_to_session_state(info->entry->state);

		if (is_type_matching_state(&state, info->type) == TRUE)
			info->state = state;
	}

	switch (trigger) {
	case CONNMAN_SESSION_TRIGGER_UNKNOWN:
		DBG("ignore session changed event");
		return;
	case CONNMAN_SESSION_TRIGGER_SETTING:
		if (info->allowed_bearers != info_last->allowed_bearers) {

			service_hash_last = session->service_hash;
			service_list_last = session->service_list;

			populate_service_list(session);

			if (info->entry != NULL) {
				service_iter_last = g_hash_table_lookup(
							service_hash_last,
							info->entry->service);
				service_iter = g_hash_table_lookup(
							session->service_hash,
							info->entry->service);
			}

			if (service_iter == NULL && service_iter_last != NULL) {
				/*
				 * The currently selected service is
				 * not part of this session anymore.
				 */
				deselect_and_disconnect(session, info->reason);
			}

			g_hash_table_remove_all(service_hash_last);
			g_sequence_free(service_list_last);
		}

		if (info->type != info_last->type) {
			if (info->state >= CONNMAN_SESSION_STATE_CONNECTED &&
					is_type_matching_state(&info->state,
							info->type) == FALSE)
				deselect_and_disconnect(session, info->reason);
		}

		if (info->state == CONNMAN_SESSION_STATE_DISCONNECTED) {
			select_and_connect(session,
					CONNMAN_SESSION_REASON_FREE_RIDE);
		}

		break;
	case CONNMAN_SESSION_TRIGGER_CONNECT:
		if (info->state >= CONNMAN_SESSION_STATE_CONNECTED) {
			if (info->entry->reason == CONNMAN_SESSION_REASON_CONNECT)
				break;
			info->entry->reason = CONNMAN_SESSION_REASON_CONNECT;
			__connman_service_session_inc(info->entry->service);
			break;
		}

		if (info->entry != NULL &&
				is_connecting(info->entry->state) == TRUE) {
			break;
		}

		select_and_connect(session,
				CONNMAN_SESSION_REASON_CONNECT);

		break;
	case CONNMAN_SESSION_TRIGGER_DISCONNECT:
		deselect_and_disconnect(session,
					CONNMAN_SESSION_REASON_DISCONNECT);

		break;
	case CONNMAN_SESSION_TRIGGER_PERIODIC:
		if (info->state >= CONNMAN_SESSION_STATE_CONNECTED) {
			info->entry->reason = CONNMAN_SESSION_REASON_PERIODIC;
			__connman_service_session_inc(info->entry->service);
			break;
		}

		select_and_connect(session,
				CONNMAN_SESSION_REASON_PERIODIC);

		break;
	case CONNMAN_SESSION_TRIGGER_SERVICE:
		if (info->entry != NULL &&
			(is_connecting(info->entry->state) == TRUE ||
				is_connected(info->entry->state) == TRUE)) {
			break;
		}

		deselect_and_disconnect(session, info->reason);

		if (info->reason == CONNMAN_SESSION_REASON_FREE_RIDE ||
				info->stay_connected == TRUE) {
			select_and_connect(session, info->reason);
		}

		break;
	case CONNMAN_SESSION_TRIGGER_ECALL:
		if (info->state == CONNMAN_SESSION_STATE_DISCONNECTED &&
				info->entry != NULL &&
				info->entry->service != NULL) {
			deselect_and_disconnect(session, info->reason);
		}

		break;
	}

	session_notify(session);
}

static DBusMessage *connect_session(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_session *session = user_data;
	struct session_info *info = session->info;

	DBG("session %p", session);

	if (ecall_info != NULL && ecall_info != info)
		return __connman_error_failed(msg, EBUSY);

	session_changed(session, CONNMAN_SESSION_TRIGGER_CONNECT);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *disconnect_session(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_session *session = user_data;
	struct session_info *info = session->info;

	DBG("session %p", session);

	if (ecall_info != NULL && ecall_info != info)
		return __connman_error_failed(msg, EBUSY);

	session_changed(session, CONNMAN_SESSION_TRIGGER_DISCONNECT);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static void update_ecall_sessions(struct connman_session *session)
{
	struct session_info *info = session->info;
	struct connman_session *session_iter;
	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init(&iter, session_hash);

	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		session_iter = value;

		if (session_iter == session)
			continue;

		session_iter->info->ecall = info->ecall;

		session_changed(session_iter, CONNMAN_SESSION_TRIGGER_ECALL);
	}
}

static void update_ecall(struct connman_session *session)
{
	struct session_info *info = session->info;
	struct session_info *info_last = session->info_last;

	DBG("session %p ecall_info %p ecall %d -> %d", session,
		ecall_info, info_last->ecall, info->ecall);

	if (ecall_info == NULL) {
		if (!(info_last->ecall == FALSE && info->ecall == TRUE))
			goto err;

		ecall_info = info;
	} else if (ecall_info == info) {
		if (!(info_last->ecall == TRUE && info->ecall == FALSE))
			goto err;

		ecall_info = NULL;
	} else {
		goto err;
	}

	update_ecall_sessions(session);

	return;

err:
	/* not a valid transition */
	info->ecall = info_last->ecall;
}

static DBusMessage *change_session(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_session *session = user_data;
	struct session_info *info = session->info;
	DBusMessageIter iter, value;
	const char *name;
	const char *val;
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
		} else {
			goto err;
		}
		break;
	case DBUS_TYPE_BOOLEAN:
		if (g_str_equal(name, "Priority") == TRUE) {
			dbus_message_iter_get_basic(&value,
					&info->priority);
		} else if (g_str_equal(name, "AvoidHandover") == TRUE) {
			dbus_message_iter_get_basic(&value,
					&info->avoid_handover);
		} else if (g_str_equal(name, "StayConnected") == TRUE) {
			dbus_message_iter_get_basic(&value,
					&info->stay_connected);
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
		} else if (g_str_equal(name, "IdleTimeout") == TRUE) {
			dbus_message_iter_get_basic(&value,
					&info->idle_timeout);
		} else {
			goto err;
		}
		break;
	case DBUS_TYPE_STRING:
		if (g_str_equal(name, "ConnectionType") == TRUE) {
			dbus_message_iter_get_basic(&value, &val);
			info->type = string2type(val);
		} else if (g_str_equal(name, "RoamingPolicy") == TRUE) {
			dbus_message_iter_get_basic(&value, &val);
			info->roaming_policy =
					string2roamingpolicy(val);
		} else {
			goto err;
		}
		break;
	default:
		goto err;
	}

	session_changed(session, CONNMAN_SESSION_TRIGGER_SETTING);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);

err:
	return __connman_error_invalid_arguments(msg);
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

	deselect_and_disconnect(session,
				CONNMAN_SESSION_REASON_DISCONNECT);

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
	struct session_info *info = session->info;

	DBG("session %p", session);

	if (ecall_info != NULL && ecall_info != info)
		return __connman_error_failed(msg, EBUSY);

	session_disconnect(session);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static const GDBusMethodTable session_methods[] = {
	{ GDBUS_METHOD("Destroy", NULL, NULL, destroy_session) },
	{ GDBUS_METHOD("Connect", NULL, NULL, connect_session) },
	{ GDBUS_METHOD("Disconnect", NULL, NULL,
			disconnect_session ) },
	{ GDBUS_METHOD("Change",
			GDBUS_ARGS({ "name", "s" }, { "value", "v" }),
			NULL, change_session) },
	{ },
};

int __connman_session_create(DBusMessage *msg)
{
	const char *owner, *notify_path;
	char *session_path = NULL;
	DBusMessageIter iter, array;
	struct connman_session *session = NULL;
	struct session_info *info, *info_last;

	enum connman_session_type type = CONNMAN_SESSION_TYPE_ANY;
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

	if (ecall_info != NULL) {
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
			if (g_str_equal(key, "ConnectionType") == TRUE) {
				dbus_message_iter_get_basic(&value, &val);
				type = string2type(val);
			} else if (g_str_equal(key, "RoamingPolicy") == TRUE) {
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
		session = NULL;
		err = -EEXIST;
		goto err;
	}

	session = g_try_new0(struct connman_session, 1);
	if (session == NULL) {
		err = -ENOMEM;
		goto err;
	}

	session->info = g_try_new0(struct session_info, 1);
	if (session->info == NULL) {
		err = -ENOMEM;
		goto err;
	}

	session->info_last = g_try_new0(struct session_info, 1);
	if (session->info_last == NULL) {
		err = -ENOMEM;
		goto err;
	}

	info = session->info;
	info_last = session->info_last;

	session->owner = g_strdup(owner);
	session->session_path = session_path;
	session->notify_path = g_strdup(notify_path);
	session->notify_watch =
		g_dbus_add_disconnect_watch(connection, session->owner,
					owner_disconnect, session, NULL);

	info->state = CONNMAN_SESSION_STATE_DISCONNECTED;
	info->type = type;
	info->priority = priority;
	info->avoid_handover = avoid_handover;
	info->stay_connected = stay_connected;
	info->periodic_connect = periodic_connect;
	info->idle_timeout = idle_timeout;
	info->ecall = ecall;
	info->roaming_policy = roaming_policy;
	info->entry = NULL;
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


	populate_service_list(session);
	if (info->ecall == TRUE) {
		ecall_info = info;
		update_ecall_sessions(session);
	}

	info_last->state = info->state;
	info_last->priority = info->priority;
	info_last->avoid_handover = info->avoid_handover;
	info_last->stay_connected = info->stay_connected;
	info_last->periodic_connect = info->periodic_connect;
	info_last->idle_timeout = info->idle_timeout;
	info_last->ecall = info->ecall;
	info_last->roaming_policy = info->roaming_policy;
	info_last->entry = info->entry;
	info_last->marker = info->marker;
	info_last->allowed_bearers = info->allowed_bearers;

	session->append_all = TRUE;

	session_changed(session, CONNMAN_SESSION_TRIGGER_SETTING);

	return 0;

err:
	connman_error("Failed to create session");

	if (session != NULL) {
		if (session->info_last != NULL)
			g_free(session->info_last);
		if (session->info != NULL)
			g_free(session->info);
		g_free(session);
	}

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

	if (sessionmode != enable) {
		sessionmode = enable;

		connman_dbus_property_changed_basic(CONNMAN_MANAGER_PATH,
				CONNMAN_MANAGER_INTERFACE, "SessionMode",
				DBUS_TYPE_BOOLEAN, &sessionmode);
	}

	if (sessionmode == TRUE)
		__connman_service_disconnect_all();
}

static void service_add(struct connman_service *service,
			const char *name)
{
	GHashTableIter iter;
	GSequenceIter *iter_service_list;
	gpointer key, value;
	struct connman_session *session;
	struct service_entry *entry;

	DBG("service %p", service);

	g_hash_table_iter_init(&iter, session_hash);

	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		session = value;

		if (service_match(session, service) == FALSE)
			continue;

		entry = create_service_entry(service, name,
						CONNMAN_SERVICE_STATE_IDLE);
		if (entry == NULL)
			continue;

		iter_service_list =
			g_sequence_insert_sorted(session->service_list,
							entry, sort_services,
							session);

		g_hash_table_replace(session->service_hash, service,
					iter_service_list);

		session_changed(session, CONNMAN_SESSION_TRIGGER_SERVICE);
	}
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
		GSequenceIter *iter;
		session = value;
		info = session->info;

		iter = g_hash_table_lookup(session->service_hash, service);
		if (iter == NULL)
			continue;

		g_sequence_remove(iter);

		if (info->entry != NULL && info->entry->service == service)
			info->entry = NULL;
		session_changed(session, CONNMAN_SESSION_TRIGGER_SERVICE);
	}
}

static void service_state_changed(struct connman_service *service,
					enum connman_service_state state)
{
	GHashTableIter iter;
	gpointer key, value;

	DBG("service %p state %d", service, state);

	g_hash_table_iter_init(&iter, session_hash);

	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		struct connman_session *session = value;
		GSequenceIter *service_iter;

		service_iter = g_hash_table_lookup(session->service_hash, service);
		if (service_iter != NULL) {
			struct service_entry *entry;

			entry = g_sequence_get(service_iter);
			entry->state = state;
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
		info = session->info;

		if (info->state == CONNMAN_SESSION_STATE_DISCONNECTED)
			continue;

		if (info->entry != NULL && info->entry->service == service) {
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
	session_hash = NULL;

	dbus_connection_unref(connection);
}
