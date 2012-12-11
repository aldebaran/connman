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

#include <connman/session.h>

#include "connman.h"

static DBusConnection *connection;
static GHashTable *session_hash;
static connman_bool_t sessionmode;
static struct connman_session *ecall_session;
static GSList *policy_list;

enum connman_session_trigger {
	CONNMAN_SESSION_TRIGGER_UNKNOWN		= 0,
	CONNMAN_SESSION_TRIGGER_SETTING		= 1,
	CONNMAN_SESSION_TRIGGER_CONNECT		= 2,
	CONNMAN_SESSION_TRIGGER_DISCONNECT	= 3,
	CONNMAN_SESSION_TRIGGER_SERVICE		= 4,
	CONNMAN_SESSION_TRIGGER_ECALL		= 5,
};

enum connman_session_reason {
	CONNMAN_SESSION_REASON_UNKNOWN		= 0,
	CONNMAN_SESSION_REASON_CONNECT		= 1,
	CONNMAN_SESSION_REASON_FREE_RIDE	= 2,
};

enum connman_session_state {
	CONNMAN_SESSION_STATE_DISCONNECTED   = 0,
	CONNMAN_SESSION_STATE_CONNECTED      = 1,
	CONNMAN_SESSION_STATE_ONLINE         = 2,
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
	struct connman_session_config config;
	enum connman_session_state state;
	struct service_entry *entry;
	enum connman_session_reason reason;
};

struct connman_session {
	char *owner;
	char *session_path;
	char *notify_path;
	guint notify_watch;

	struct connman_session_policy *policy;

	connman_bool_t append_all;
	struct session_info *info;
	struct session_info *info_last;
	struct connman_session_config *policy_config;
	GSList *user_allowed_bearers;

	connman_bool_t ecall;

	GSequence *service_list;
	GHashTable *service_hash;
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
	case CONNMAN_SESSION_REASON_FREE_RIDE:
		return "free-ride";
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
	case CONNMAN_SESSION_TYPE_UNKNOWN:
		return "";
	case CONNMAN_SESSION_TYPE_ANY:
		return "any";
	case CONNMAN_SESSION_TYPE_LOCAL:
		return "local";
	case CONNMAN_SESSION_TYPE_INTERNET:
		return "internet";
	}

	return NULL;
}

enum connman_session_roaming_policy connman_session_parse_roaming_policy(const char *policy)
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

enum connman_session_type connman_session_parse_connection_type(const char *type)
{
	if (g_strcmp0(type, "any") == 0)
		return CONNMAN_SESSION_TYPE_ANY;
	if (g_strcmp0(type, "local") == 0)
		return CONNMAN_SESSION_TYPE_LOCAL;
	else if (g_strcmp0(type, "internet") == 0)
		return CONNMAN_SESSION_TYPE_INTERNET;

	return CONNMAN_SESSION_TYPE_UNKNOWN;
}

static int bearer2service(const char *bearer, enum connman_service_type *type)
{
	if (g_strcmp0(bearer, "ethernet") == 0)
		*type = CONNMAN_SERVICE_TYPE_ETHERNET;
	else if (g_strcmp0(bearer, "wifi") == 0)
		*type = CONNMAN_SERVICE_TYPE_WIFI;
	else if (g_strcmp0(bearer, "bluetooth") == 0)
		*type = CONNMAN_SERVICE_TYPE_BLUETOOTH;
	else if (g_strcmp0(bearer, "cellular") == 0)
		*type = CONNMAN_SERVICE_TYPE_CELLULAR;
	else if (g_strcmp0(bearer, "vpn") == 0)
		*type = CONNMAN_SERVICE_TYPE_VPN;
	else if (g_strcmp0(bearer, "*") == 0)
		*type = CONNMAN_SERVICE_TYPE_UNKNOWN;
	else
		return -EINVAL;

	return 0;
}

static char *service2bearer(enum connman_service_type type)
{
	switch (type) {
	case CONNMAN_SERVICE_TYPE_ETHERNET:
		return "ethernet";
	case CONNMAN_SERVICE_TYPE_WIFI:
		return "wifi";
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

static void destroy_policy_config(struct connman_session *session)
{
	if (session->policy == NULL) {
		g_free(session->policy_config);
		return;
	}

	(*session->policy->destroy)(session);
}

static void free_session(struct connman_session *session)
{
	if (session == NULL)
		return;

	if (session->notify_watch > 0)
		g_dbus_remove_watch(connection, session->notify_watch);

	destroy_policy_config(session);
	g_slist_free(session->info->config.allowed_bearers);
	g_free(session->owner);
	g_free(session->session_path);
	g_free(session->notify_path);
	g_free(session->info);
	g_free(session->info_last);

	g_free(session);
}

static void cleanup_session(gpointer user_data)
{
	struct connman_session *session = user_data;
	struct session_info *info = session->info;

	DBG("remove %s", session->session_path);

	g_slist_free(session->user_allowed_bearers);
	g_hash_table_destroy(session->service_hash);
	g_sequence_free(session->service_list);

	if (info->entry != NULL &&
			info->entry->reason == CONNMAN_SESSION_REASON_CONNECT) {
		__connman_service_disconnect(info->entry->service);
	}

	free_session(session);
}

static int assign_policy_plugin(struct connman_session *session)
{
	if (session->policy != NULL)
		return -EALREADY;

	if (policy_list == NULL)
		return 0;

	session->policy = policy_list->data;

	return 0;
}

struct user_config {
	DBusMessage *pending;

	enum connman_session_type type;
	GSList *allowed_bearers;
};

static void cleanup_user_config(struct user_config *user_config)
{
	if (user_config == NULL)
		return;

	if (user_config->pending != NULL)
		dbus_message_unref(user_config->pending);

	g_slist_free(user_config->allowed_bearers);
	g_free(user_config);
}

static int create_policy_config(struct connman_session *session,
				connman_session_config_cb callback,
				struct user_config *user_config)
{
	struct connman_session_config *config;

	if (session->policy == NULL) {
		config = connman_session_create_default_config();
		if (config == NULL) {
			free_session(session);
			cleanup_user_config(user_config);
			return -ENOMEM;
		}

		return callback(session, config, user_config, 0);
	}

	return (*session->policy->create)(session, callback, user_config);
}

static void probe_policy(struct connman_session_policy *policy)
{

	GHashTableIter iter;
	gpointer key, value;
	struct connman_session *session;

	DBG("policy %p name %s", policy, policy->name);

	g_hash_table_iter_init(&iter, session_hash);

	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		session = value;

		if (session->policy != NULL)
			continue;

		assign_policy_plugin(session);
	}
}

static void remove_policy(struct connman_session_policy *policy)
{
	GHashTableIter iter;
	gpointer key, value;
	struct connman_session *session;

	DBG("policy %p name %s", policy, policy->name);

	g_hash_table_iter_init(&iter, session_hash);

	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		session = value;

		if (session->policy != policy)
			continue;

		session->policy = NULL;
		assign_policy_plugin(session);
	}
}

static gint compare_priority(gconstpointer a, gconstpointer b)
{
	const struct connman_session_policy *policy1 = a;
	const struct connman_session_policy *policy2 = b;

	return policy2->priority - policy1->priority;
}


int connman_session_policy_register(struct connman_session_policy *policy)
{
	DBG("name %s", policy->name);

	if (policy->create == NULL || policy->destroy == NULL)
		return -EINVAL;

	policy_list = g_slist_insert_sorted(policy_list, policy,
						compare_priority);

	probe_policy(policy);

	return 0;
}

void connman_session_policy_unregister(struct connman_session_policy *policy)
{
	DBG("name %s", policy->name);

	policy_list = g_slist_remove(policy_list, policy);

	remove_policy(policy);
}

int connman_session_set_default_config(struct connman_session_config *config)
{
	config->priority = FALSE;
	config->roaming_policy = CONNMAN_SESSION_ROAMING_POLICY_DEFAULT;
	config->type = CONNMAN_SESSION_TYPE_ANY;
	config->ecall = FALSE;

	g_slist_free(config->allowed_bearers);
	config->allowed_bearers = g_slist_prepend(NULL,
				GINT_TO_POINTER(CONNMAN_SERVICE_TYPE_UNKNOWN));
	if (config->allowed_bearers == NULL)
		return -ENOMEM;

	return 0;
}

struct connman_session_config *connman_session_create_default_config(void)
{
	struct connman_session_config *config;

	config = g_try_new0(struct connman_session_config, 1);
	if (config == NULL)
		return NULL;

	if (connman_session_set_default_config(config) < 0) {
		g_free(config);
		return NULL;
	}

	return config;
}

static enum connman_session_type apply_policy_on_type(
			enum connman_session_type policy,
			enum connman_session_type type)
{
	if (type == CONNMAN_SESSION_TYPE_UNKNOWN)
		return CONNMAN_SESSION_TYPE_UNKNOWN;

	if (policy == CONNMAN_SESSION_TYPE_ANY)
		return type;

	if (policy == CONNMAN_SESSION_TYPE_LOCAL)
		return CONNMAN_SESSION_TYPE_LOCAL;

	return CONNMAN_SESSION_TYPE_INTERNET;
}

int connman_session_parse_bearers(const char *token, GSList **list)
{
	enum connman_service_type bearer;
	int err;

	if (g_strcmp0(token, "") == 0)
		return 0;

	err = bearer2service(token, &bearer);
	if (err < 0)
		return err;

	*list = g_slist_append(*list, GINT_TO_POINTER(bearer));

	return 0;
}

static int parse_bearers(DBusMessageIter *iter, GSList **list)
{
	DBusMessageIter array;
	int type, err;

	dbus_message_iter_recurse(iter, &array);

	*list = NULL;

	while ((type = dbus_message_iter_get_arg_type(&array)) !=
			DBUS_TYPE_INVALID) {
		char *bearer_name = NULL;

		if (type != DBUS_TYPE_STRING) {
			g_slist_free(*list);
			*list = NULL;
			return -EINVAL;
		}

		dbus_message_iter_get_basic(&array, &bearer_name);

		err = connman_session_parse_bearers(bearer_name, list);
		if (err < 0) {
			g_slist_free(*list);
			*list = NULL;
			return err;
		}

		dbus_message_iter_next(&array);
	}

	return 0;
}

static int filter_bearer(GSList *policy_bearers,
				enum connman_service_type bearer,
				GSList **list)
{
	enum connman_service_type policy;
	GSList *it;

	if (policy_bearers == NULL)
		goto clone;

	for (it = policy_bearers; it != NULL; it = it->next) {
		policy = GPOINTER_TO_INT(it->data);

		if (bearer == CONNMAN_SERVICE_TYPE_UNKNOWN) {
			bearer = policy;
			goto clone;
		}

		if (policy != CONNMAN_SERVICE_TYPE_UNKNOWN && policy != bearer)
			continue;

		goto clone;
	}

	*list = NULL;

	return 0;

clone:
	*list = g_slist_append(*list, GINT_TO_POINTER(bearer));

	return 0;
}

static int apply_policy_on_bearers(GSList *policy_bearers, GSList *bearers,
				GSList **list)
{
	enum connman_service_type bearer;
	GSList *it;
	int err;

	*list = NULL;

	for (it = bearers; it != NULL; it = it->next) {
		bearer = GPOINTER_TO_INT(it->data);

		err = filter_bearer(policy_bearers, bearer, list);
		if (err < 0)
			return err;
	}

	return 0;
}

const char *connman_session_get_owner(struct connman_session *session)
{
	return session->owner;
}

static void append_allowed_bearers(DBusMessageIter *iter, void *user_data)
{
	struct session_info *info = user_data;
	GSList *list;

	for (list = info->config.allowed_bearers;
			list != NULL; list = list->next) {
		enum connman_service_type bearer = GPOINTER_TO_INT(list->data);
		const char *name = __connman_service_type2string(bearer);

		if (name == NULL)
			name = "*";

		dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING,
						&name);
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

	if (session->append_all == TRUE ||
			info->config.type != info_last->config.type) {
		const char *type = type2string(info->config.type);

		connman_dbus_dict_append_basic(dict, "ConnectionType",
						DBUS_TYPE_STRING,
						&type);
		info_last->config.type = info->config.type;
	}

	if (session->append_all == TRUE ||
			info->config.allowed_bearers != info_last->config.allowed_bearers) {
		connman_dbus_dict_append_array(dict, "AllowedBearers",
						DBUS_TYPE_STRING,
						append_allowed_bearers,
						info);
		info_last->config.allowed_bearers = info->config.allowed_bearers;
	}

	session->append_all = FALSE;
}

static connman_bool_t is_type_matching_state(enum connman_session_state *state,
						enum connman_session_type type)
{
	switch (type) {
	case CONNMAN_SESSION_TYPE_UNKNOWN:
		return FALSE;
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

	if (info->config.allowed_bearers != info_last->config.allowed_bearers ||
			info->config.type != info_last->config.type)
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

	for (list = info->config.allowed_bearers;
			list != NULL; list = list->next) {
		enum connman_service_type bearer = GPOINTER_TO_INT(list->data);
		enum connman_service_type service_type;

		if (bearer == CONNMAN_SERVICE_TYPE_UNKNOWN)
			return TRUE;

		service_type = connman_service_get_type(service);
		if (bearer == service_type)
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
	 * 3. WiFi
	 * 4. Cellular
	 */

	switch (type) {
	case CONNMAN_SERVICE_TYPE_ETHERNET:
		return 4;
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
		return 3;
	case CONNMAN_SERVICE_TYPE_WIFI:
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

	for (list = info->config.allowed_bearers;
			list != NULL; list = list->next) {
		enum connman_service_type bearer = GPOINTER_TO_INT(list->data);

		if (bearer == CONNMAN_SERVICE_TYPE_UNKNOWN) {
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

		if (type_a == bearer && type_b == bearer)
			return 0;

		if (type_a == bearer &&	type_b != bearer)
			return -1;

		if (type_a != bearer &&	type_b == bearer)
			return 1;
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
		break;
	case CONNMAN_SESSION_REASON_CONNECT:
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

static void deselect_and_disconnect(struct connman_session *session)
{
	struct session_info *info = session->info;

	deselect_service(info);

	info->reason = CONNMAN_SESSION_REASON_FREE_RIDE;
}

static void select_connected_service(struct session_info *info,
					struct service_entry *entry)
{
	enum connman_session_state state;

	state = service_to_session_state(entry->state);
	if (is_type_matching_state(&state, info->config.type) == FALSE)
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

		if (is_type_matching_state(&state, info->config.type) == TRUE)
			info->state = state;
	}

	switch (trigger) {
	case CONNMAN_SESSION_TRIGGER_UNKNOWN:
		DBG("ignore session changed event");
		return;
	case CONNMAN_SESSION_TRIGGER_SETTING:
		if (info->config.allowed_bearers != info_last->config.allowed_bearers) {

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
				deselect_and_disconnect(session);
			}

			g_hash_table_remove_all(service_hash_last);
			g_sequence_free(service_list_last);
		}

		if (info->config.type != info_last->config.type) {
			if (info->state >= CONNMAN_SESSION_STATE_CONNECTED &&
					is_type_matching_state(&info->state,
							info->config.type) == FALSE)
				deselect_and_disconnect(session);
		}

		if (info->state == CONNMAN_SESSION_STATE_DISCONNECTED) {
			select_and_connect(session,
					CONNMAN_SESSION_REASON_FREE_RIDE);
		}

		break;
	case CONNMAN_SESSION_TRIGGER_ECALL:
		/*
		 * For the time beeing we fallback to normal connect
		 * strategy.
		 */
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
		deselect_and_disconnect(session);

		break;
	case CONNMAN_SESSION_TRIGGER_SERVICE:
		if (info->entry != NULL &&
			(is_connecting(info->entry->state) == TRUE ||
				is_connected(info->entry->state) == TRUE)) {
			break;
		}

		deselect_and_disconnect(session);

		if (info->reason == CONNMAN_SESSION_REASON_FREE_RIDE) {
			select_and_connect(session, info->reason);
		}

		break;
	}

	session_notify(session);
}

int connman_session_config_update(struct connman_session *session)
{
	struct session_info *info = session->info;
	GSList *allowed_bearers;
	int err;

	DBG("session %p", session);

	/*
	 * We update all configuration even though only one entry
	 * might have changed. We can still optimize this later.
	 */

	err = apply_policy_on_bearers(
		session->policy_config->allowed_bearers,
		session->user_allowed_bearers,
		&allowed_bearers);
	if (err < 0)
		return err;

	g_slist_free(info->config.allowed_bearers);
	info->config.allowed_bearers = allowed_bearers;

	info->config.type = apply_policy_on_type(
				session->policy_config->type,
				info->config.type);

	info->config.roaming_policy = session->policy_config->roaming_policy;

	info->config.ecall = session->policy_config->ecall;
	if (info->config.ecall == TRUE)
		ecall_session = session;

	info->config.priority = session->policy_config->priority;

	session_changed(session, CONNMAN_SESSION_TRIGGER_SETTING);

	return 0;
}

static DBusMessage *connect_session(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_session *session = user_data;

	DBG("session %p", session);

	if (ecall_session != NULL) {
		if (ecall_session->ecall == TRUE && ecall_session != session)
			return __connman_error_failed(msg, EBUSY);

		session->ecall = TRUE;
		session_changed(session, CONNMAN_SESSION_TRIGGER_ECALL);
	} else
		session_changed(session, CONNMAN_SESSION_TRIGGER_CONNECT);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *disconnect_session(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_session *session = user_data;

	DBG("session %p", session);

	if (ecall_session != NULL) {
		if (ecall_session->ecall == TRUE && ecall_session != session)
			return __connman_error_failed(msg, EBUSY);

		session->ecall = FALSE;
	}

	session_changed(session, CONNMAN_SESSION_TRIGGER_DISCONNECT);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
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
	int err;

	DBG("session %p", session);
	if (dbus_message_iter_init(msg, &iter) == FALSE)
		return __connman_error_invalid_arguments(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &name);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_recurse(&iter, &value);

	switch (dbus_message_iter_get_arg_type(&value)) {
	case DBUS_TYPE_ARRAY:
		if (g_str_equal(name, "AllowedBearers") == TRUE) {
			err = parse_bearers(&value, &allowed_bearers);
			if (err < 0)
				return __connman_error_failed(msg, err);

			g_slist_free(info->config.allowed_bearers);
			session->user_allowed_bearers = allowed_bearers;

			err = apply_policy_on_bearers(
					session->policy_config->allowed_bearers,
					session->user_allowed_bearers,
					&info->config.allowed_bearers);

			if (err < 0)
				return __connman_error_failed(msg, err);
		} else {
			goto err;
		}
		break;
	case DBUS_TYPE_STRING:
		if (g_str_equal(name, "ConnectionType") == TRUE) {
			dbus_message_iter_get_basic(&value, &val);
			info->config.type = apply_policy_on_type(
				session->policy_config->type,
				connman_session_parse_connection_type(val));
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

	deselect_and_disconnect(session);

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

	if (ecall_session != NULL && ecall_session != session)
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

static int session_create_cb(struct connman_session *session,
				struct connman_session_config *config,
				void *user_data, int err)
{
	DBusMessage *reply;
	struct user_config *user_config = user_data;
	struct session_info *info, *info_last;

	DBG("session %p config %p", session, config);

	if (err != 0)
		goto out;

	session->policy_config = config;

	info = session->info;
	info_last = session->info_last;

	if (session->policy_config->ecall == TRUE)
		ecall_session = session;

	info->state = CONNMAN_SESSION_STATE_DISCONNECTED;
	info->config.type = apply_policy_on_type(
				session->policy_config->type,
				user_config->type);
	info->config.priority = session->policy_config->priority;
	info->config.roaming_policy = session->policy_config->roaming_policy;
	info->entry = NULL;

	session->user_allowed_bearers = user_config->allowed_bearers;
	user_config->allowed_bearers = NULL;

	err = apply_policy_on_bearers(
			session->policy_config->allowed_bearers,
			session->user_allowed_bearers,
			&info->config.allowed_bearers);
	if (err < 0)
		goto out;

	g_hash_table_replace(session_hash, session->session_path, session);

	DBG("add %s", session->session_path);

	if (g_dbus_register_interface(connection, session->session_path,
					CONNMAN_SESSION_INTERFACE,
					session_methods, NULL,
					NULL, session, NULL) == FALSE) {
		connman_error("Failed to register %s", session->session_path);
		g_hash_table_remove(session_hash, session->session_path);
		err = -EINVAL;
		goto out;
	}

	reply = g_dbus_create_reply(user_config->pending,
				DBUS_TYPE_OBJECT_PATH, &session->session_path,
				DBUS_TYPE_INVALID);
	g_dbus_send_message(connection, reply);
	user_config->pending = NULL;

	populate_service_list(session);

	info_last->state = info->state;
	info_last->config.priority = info->config.priority;
	info_last->config.roaming_policy = info->config.roaming_policy;
	info_last->entry = info->entry;
	info_last->config.allowed_bearers = info->config.allowed_bearers;

	session->append_all = TRUE;

	session_changed(session, CONNMAN_SESSION_TRIGGER_SETTING);

out:
	if (err < 0) {
		reply = __connman_error_failed(user_config->pending, -err);
		g_dbus_send_message(connection, reply);

		free_session(session);
	}

	cleanup_user_config(user_config);

	return err;
}

int __connman_session_create(DBusMessage *msg)
{
	const char *owner, *notify_path;
	char *session_path = NULL;
	DBusMessageIter iter, array;
	struct connman_session *session = NULL;
	struct user_config *user_config = NULL;
	connman_bool_t user_allowed_bearers = FALSE;
	connman_bool_t user_connection_type = FALSE;
	int err;

	owner = dbus_message_get_sender(msg);

	DBG("owner %s", owner);

	if (ecall_session != NULL && ecall_session->ecall == TRUE) {
		/*
		 * If there is an emergency call already going on,
		 * ignore session creation attempt
		 */
		err = -EBUSY;
		goto err;
	}

	user_config = g_try_new0(struct user_config, 1);
	if (user_config == NULL) {
		err = -ENOMEM;
		goto err;
	}

	user_config->pending = dbus_message_ref(msg);

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
				err = parse_bearers(&value,
						&user_config->allowed_bearers);
				if (err < 0)
					goto err;

				user_allowed_bearers = TRUE;
			} else {
				err = -EINVAL;
				goto err;
			}
			break;
		case DBUS_TYPE_STRING:
			if (g_str_equal(key, "ConnectionType") == TRUE) {
				dbus_message_iter_get_basic(&value, &val);
				user_config->type =
					connman_session_parse_connection_type(val);

				user_connection_type = TRUE;
			} else {
				err = -EINVAL;
				goto err;
			}
		}
		dbus_message_iter_next(&array);
	}

	/*
	 * If the user hasn't provided a configuration, we set
	 * the default configuration.
	 *
	 * For AllowedBearers this is '*', ...
	 */
	if (user_allowed_bearers == FALSE) {
		user_config->allowed_bearers =
			g_slist_append(NULL,
				GINT_TO_POINTER(CONNMAN_SERVICE_TYPE_UNKNOWN));
		if (user_config->allowed_bearers == NULL) {
			err = -ENOMEM;
			goto err;
		}
	}

	/* ... and for ConnectionType it is 'any'. */
	if (user_connection_type == FALSE)
		user_config->type = CONNMAN_SESSION_TYPE_ANY;

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
		g_free(session_path);
		session = NULL;
		err = -EEXIST;
		goto err;
	}

	session = g_try_new0(struct connman_session, 1);
	if (session == NULL) {
		g_free(session_path);
		err = -ENOMEM;
		goto err;
	}

	session->session_path = session_path;

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

	session->owner = g_strdup(owner);
	session->notify_path = g_strdup(notify_path);
	session->notify_watch =
		g_dbus_add_disconnect_watch(connection, session->owner,
					owner_disconnect, session, NULL);

	err = assign_policy_plugin(session);
	if (err < 0)
		goto err;

	err = create_policy_config(session, session_create_cb, user_config);
	if (err < 0 && err != -EINPROGRESS)
		return err;

	return -EINPROGRESS;

err:
	connman_error("Failed to create session");

	free_session(session);

	cleanup_user_config(user_config);
	return err;
}

void connman_session_destroy(struct connman_session *session)
{
	DBG("session %p", session);

	session_disconnect(session);
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

	connman_session_destroy(session);

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
		GSequenceIter *seq_iter;
		session = value;
		info = session->info;

		seq_iter = g_hash_table_lookup(session->service_hash, service);
		if (seq_iter == NULL)
			continue;

		g_sequence_remove(seq_iter);

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
