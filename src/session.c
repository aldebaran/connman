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
static struct connman_session *ecall_session;
static GSList *policy_list;
static uint32_t session_mark = 256;
static struct firewall_context *global_firewall = NULL;

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

struct session_info {
	struct connman_session_config config;
	enum connman_session_state state;
	enum connman_session_reason reason;
};

struct connman_session {
	char *owner;
	char *session_path;
	char *notify_path;
	guint notify_watch;

	struct connman_session_policy *policy;

	bool append_all;
	struct session_info *info;
	struct session_info *info_last;
	struct connman_service *service;
	struct connman_service *service_last;
	struct connman_session_config *policy_config;
	GSList *user_allowed_bearers;

	bool ecall;

	enum connman_session_id_type id_type;
	struct firewall_context *fw;
	struct nfacct_context *nfctx;
	uint32_t mark;
	int index;
	char *gateway;

	GList *service_list;
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
		return "*";
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_GADGET:
		return "";
	}

	return "";
}

static int init_firewall(void)
{
	struct firewall_context *fw;
	int err;

	if (global_firewall)
		return 0;

	fw = __connman_firewall_create();

	err = __connman_firewall_add_rule(fw, "mangle", "INPUT",
					"-j CONNMARK --restore-mark");
	if (err < 0)
		goto err;

	err = __connman_firewall_add_rule(fw, "mangle", "POSTROUTING",
					"-j CONNMARK --save-mark");
	if (err < 0)
		goto err;

	err = __connman_firewall_enable(fw);
	if (err < 0)
		goto err;

	global_firewall = fw;

	return 0;

err:
	__connman_firewall_destroy(fw);

	return err;
}

static void cleanup_firewall(void)
{
	if (!global_firewall)
		return;

	__connman_firewall_disable(global_firewall);
	__connman_firewall_destroy(global_firewall);
}

static int enable_nfacct(struct firewall_context *fw, uint32_t mark)
{
	int err;

	err = __connman_firewall_add_rule(fw, "filter", "INPUT",
			"-m mark --mark %d -m nfacct "
			"--nfacct-name session-input-%d",
			mark, mark);
	if (err < 0)
		return err;

	err = __connman_firewall_add_rule(fw, "filter", "OUTPUT",
			"-m mark --mark %d -m nfacct "
			"--nfacct-name session-output-%d",
			mark, mark);

	return err;
}

static int init_firewall_session(struct connman_session *session)
{
	struct firewall_context *fw;
	int err;

	if (session->policy_config->id_type == CONNMAN_SESSION_ID_TYPE_UNKNOWN)
		return 0;

	DBG("");

	err = init_firewall();
	if (err < 0)
		return err;

	fw = __connman_firewall_create();
	if (!fw)
		return -ENOMEM;

	switch (session->policy_config->id_type) {
	case CONNMAN_SESSION_ID_TYPE_UID:
		err = __connman_firewall_add_rule(fw, "mangle", "OUTPUT",
				"-m owner --uid-owner %s -j MARK --set-mark %d",
						session->policy_config->id,
						session->mark);
		break;
	case CONNMAN_SESSION_ID_TYPE_GID:
		err = __connman_firewall_add_rule(fw, "mangle", "OUTPUT",
				"-m owner --gid-owner %s -j MARK --set-mark %d",
						session->policy_config->id,
						session->mark);
		break;
	case CONNMAN_SESSION_ID_TYPE_LSM:
	default:
		err = -EINVAL;
	}

	if (err < 0)
		goto err;

	session->id_type = session->policy_config->id_type;

	err = enable_nfacct(fw, session->mark);
	if (err < 0)
		connman_warn_once("Support for nfacct missing");

	err = __connman_firewall_enable(fw);
	if (err)
		goto err;

	session->fw = fw;

	return 0;

err:
	__connman_firewall_destroy(fw);

	return err;
}

static void cleanup_firewall_session(struct connman_session *session)
{
	if (!session->fw)
		return;

	__connman_firewall_disable(session->fw);
	__connman_firewall_destroy(session->fw);

	session->fw = NULL;
}

static int init_routing_table(struct connman_session *session)
{
	int err;

	if (session->policy_config->id_type == CONNMAN_SESSION_ID_TYPE_UNKNOWN)
		return 0;

	DBG("");

	err = __connman_inet_add_fwmark_rule(session->mark,
						AF_INET, session->mark);
	if (err < 0)
		return err;

	err = __connman_inet_add_fwmark_rule(session->mark,
						AF_INET6, session->mark);
	if (err < 0)
		__connman_inet_del_fwmark_rule(session->mark,
						AF_INET, session->mark);

	return err;
}

static void del_default_route(struct connman_session *session)
{
	if (!session->gateway)
		return;

	DBG("index %d routing table %d default gateway %s",
		session->index, session->mark, session->gateway);

	__connman_inet_del_default_from_table(session->mark,
					session->index, session->gateway);
	g_free(session->gateway);
	session->gateway = NULL;
	session->index = -1;
}

static void add_default_route(struct connman_session *session)
{
	struct connman_ipconfig *ipconfig;
	int err;

	if (!session->service)
		return;

	ipconfig = __connman_service_get_ip4config(session->service);
	session->index = __connman_ipconfig_get_index(ipconfig);
	session->gateway = g_strdup(__connman_ipconfig_get_gateway(ipconfig));

	DBG("index %d routing table %d default gateway %s",
		session->index, session->mark, session->gateway);

	err = __connman_inet_add_default_to_table(session->mark,
					session->index, session->gateway);
	if (err < 0)
		DBG("session %p %s", session, strerror(-err));
}

static void cleanup_routing_table(struct connman_session *session)
{
	DBG("");

	__connman_inet_del_fwmark_rule(session->mark,
					AF_INET6, session->mark);

	__connman_inet_del_fwmark_rule(session->mark,
					AF_INET, session->mark);

	del_default_route(session);
}

static void update_routing_table(struct connman_session *session)
{
	del_default_route(session);
	add_default_route(session);
}

static void destroy_policy_config(struct connman_session *session)
{
	if (!session->policy) {
		g_free(session->policy_config);
		return;
	}

	(*session->policy->destroy)(session);
}

static void free_session(struct connman_session *session)
{
	if (!session)
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
	g_free(session->gateway);

	g_free(session);
}

static void cleanup_session_final(struct connman_session *session)
{
	struct session_info *info = session->info;

	DBG("remove %s", session->session_path);

	if (info->reason == CONNMAN_SESSION_REASON_CONNECT)
		__connman_service_set_active_session(false,
				session->info->config.allowed_bearers);

	g_slist_free(session->user_allowed_bearers);
	if (session->service_hash)
		g_hash_table_destroy(session->service_hash);
	g_list_free(session->service_list);

	free_session(session);
}

static void nfacct_cleanup_cb(unsigned int error, struct nfacct_context *ctx,
				void *user_data)
{
	struct connman_session *session = user_data;

	DBG("");

	__connman_nfacct_destroy_context(session->nfctx);

	cleanup_session_final(session);
}

static void cleanup_session(gpointer user_data)
{
	struct connman_session *session = user_data;

	DBG("remove %s", session->session_path);

	cleanup_routing_table(session);
	cleanup_firewall_session(session);

	if (session->nfctx)
		__connman_nfacct_disable(session->nfctx, nfacct_cleanup_cb,
						session);
	else
		cleanup_session_final(session);
}

static int assign_policy_plugin(struct connman_session *session)
{
	if (session->policy)
		return -EALREADY;

	if (!policy_list)
		return 0;

	session->policy = policy_list->data;

	return 0;
}

struct creation_data {
	DBusMessage *pending;
	struct connman_session *session;

	/* user config */
	enum connman_session_type type;
	GSList *allowed_bearers;
};

static void cleanup_creation_data(struct creation_data *creation_data)
{
	if (!creation_data)
		return;

	if (creation_data->pending)
		dbus_message_unref(creation_data->pending);

	g_slist_free(creation_data->allowed_bearers);
	g_free(creation_data);
}

static int create_policy_config(struct connman_session *session,
				connman_session_config_func_t cb,
				struct creation_data *creation_data)
{
	struct connman_session_config *config;

	if (!session->policy) {
		config = connman_session_create_default_config();
		if (!config) {
			free_session(session);
			cleanup_creation_data(creation_data);
			return -ENOMEM;
		}

		return cb(session, config, creation_data, 0);
	}

	return (*session->policy->create)(session, cb, creation_data);
}

static void remove_policy(struct connman_session_policy *policy)
{
	GHashTableIter iter;
	gpointer key, value;
	struct connman_session *session;

	if (!session_hash)
		return;

	DBG("policy %p name %s", policy, policy->name);

	g_hash_table_iter_init(&iter, session_hash);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
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

	if (!policy->create || !policy->destroy)
		return -EINVAL;

	policy_list = g_slist_insert_sorted(policy_list, policy,
						compare_priority);

	return 0;
}

void connman_session_policy_unregister(struct connman_session_policy *policy)
{
	DBG("name %s", policy->name);

	policy_list = g_slist_remove(policy_list, policy);

	remove_policy(policy);
}

void connman_session_set_default_config(struct connman_session_config *config)
{
	config->id_type = CONNMAN_SESSION_ID_TYPE_UNKNOWN;
	g_free(config->id);
	config->id = NULL;

	config->priority = FALSE;
	config->roaming_policy = CONNMAN_SESSION_ROAMING_POLICY_DEFAULT;
	config->type = CONNMAN_SESSION_TYPE_ANY;
	config->ecall = FALSE;

	g_slist_free(config->allowed_bearers);
	config->allowed_bearers = g_slist_prepend(NULL,
				GINT_TO_POINTER(CONNMAN_SERVICE_TYPE_UNKNOWN));
}

struct connman_session_config *connman_session_create_default_config(void)
{
	struct connman_session_config *config;

	config = g_new0(struct connman_session_config, 1);
	connman_session_set_default_config(config);

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

	if (!policy_bearers)
		return 0;

	for (it = policy_bearers; it; it = it->next) {
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

	for (it = bearers; it; it = it->next) {
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
			list; list = list->next) {
		enum connman_service_type bearer = GPOINTER_TO_INT(list->data);
		const char *name = __connman_service_type2string(bearer);

		if (!name)
			name = "*";

		dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING,
						&name);
	}
}

static void append_ipconfig_ipv4(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;
	struct connman_ipconfig *ipconfig_ipv4;

	if (!service)
		return;

	if (!__connman_service_is_connected_state(service,
						CONNMAN_IPCONFIG_TYPE_IPV4))
		return;

	ipconfig_ipv4 = __connman_service_get_ip4config(service);
	if (!ipconfig_ipv4)
		return;

	__connman_ipconfig_append_ipv4(ipconfig_ipv4, iter);
}

static void append_ipconfig_ipv6(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;
	struct connman_ipconfig *ipconfig_ipv4, *ipconfig_ipv6;

	if (!service)
		return;

	if (!__connman_service_is_connected_state(service,
						CONNMAN_IPCONFIG_TYPE_IPV6))
		return;

	ipconfig_ipv4 = __connman_service_get_ip4config(service);
	ipconfig_ipv6 = __connman_service_get_ip6config(service);
	if (!ipconfig_ipv6)
		return;

	__connman_ipconfig_append_ipv6(ipconfig_ipv6, iter, ipconfig_ipv4);
}

static void append_notify(DBusMessageIter *dict,
					struct connman_session *session)
{
	struct session_info *info = session->info;
	struct session_info *info_last = session->info_last;
	struct connman_service *service;
	enum connman_service_type type;
	const char *name, *bearer;
	char *ifname;
	int idx;

	if (session->append_all || info->state != info_last->state) {
		const char *state = state2string(info->state);

		connman_dbus_dict_append_basic(dict, "State",
						DBUS_TYPE_STRING,
						&state);
		info_last->state = info->state;
	}

	if (session->append_all || session->service != session->service_last) {
		if (session->service) {
			service = session->service;
			name = __connman_service_get_name(service);
			idx = __connman_service_get_index(service);

			ifname = connman_inet_ifname(idx);
			if (!ifname)
				ifname = g_strdup("");

			type = connman_service_get_type(service);
			bearer = service2bearer(type);
		} else {
			service = NULL;
			name = "";
			ifname = g_strdup("");
			bearer = "";
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

		g_free(ifname);

		session->service_last = session->service;
	}

	if (session->append_all ||
			info->config.type != info_last->config.type) {
		const char *type = type2string(info->config.type);

		connman_dbus_dict_append_basic(dict, "ConnectionType",
						DBUS_TYPE_STRING,
						&type);
		info_last->config.type = info->config.type;
	}

	if (session->append_all ||
			info->config.allowed_bearers != info_last->config.allowed_bearers) {
		connman_dbus_dict_append_array(dict, "AllowedBearers",
						DBUS_TYPE_STRING,
						append_allowed_bearers,
						info);
		info_last->config.allowed_bearers = info->config.allowed_bearers;
	}

	session->append_all = false;
}

static bool is_type_matching_state(enum connman_session_state *state,
						enum connman_session_type type)
{
	switch (type) {
	case CONNMAN_SESSION_TYPE_UNKNOWN:
		return false;
	case CONNMAN_SESSION_TYPE_ANY:
		return true;
	case CONNMAN_SESSION_TYPE_LOCAL:
		if (*state >= CONNMAN_SESSION_STATE_CONNECTED) {
			*state = CONNMAN_SESSION_STATE_CONNECTED;
			return true;
		}

		break;
	case CONNMAN_SESSION_TYPE_INTERNET:
		if (*state == CONNMAN_SESSION_STATE_ONLINE)
			return true;
		break;
	}

	return false;
}

static bool compute_notifiable_changes(struct connman_session *session)
{
	struct session_info *info_last = session->info_last;
	struct session_info *info = session->info;

	if (session->append_all)
		return true;

	if (info->state != info_last->state)
		return true;

	if (session->service != session->service_last &&
			info->state >= CONNMAN_SESSION_STATE_CONNECTED)
		return true;

	if (info->config.allowed_bearers != info_last->config.allowed_bearers ||
			info->config.type != info_last->config.type)
		return true;

	return false;
}

static gboolean session_notify(gpointer user_data)
{
	struct connman_session *session = user_data;
	DBusMessage *msg;
	DBusMessageIter array, dict;

	if (!compute_notifiable_changes(session))
		return FALSE;

	DBG("session %p owner %s notify_path %s", session,
		session->owner, session->notify_path);

	msg = dbus_message_new_method_call(session->owner, session->notify_path,
						CONNMAN_NOTIFICATION_INTERFACE,
						"Update");
	if (!msg)
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
	connman_dbus_setting_changed_dict(session->owner, session->notify_path,
						"IPv4", append_ipconfig_ipv4,
						session->service);
}

static void ipconfig_ipv6_changed(struct connman_session *session)
{
	connman_dbus_setting_changed_dict(session->owner, session->notify_path,
						"IPv6", append_ipconfig_ipv6,
						session->service);
}

static bool service_type_match(struct connman_session *session,
					struct connman_service *service)
{
	struct session_info *info = session->info;
	GSList *list;

	for (list = info->config.allowed_bearers;
			list; list = list->next) {
		enum connman_service_type bearer = GPOINTER_TO_INT(list->data);
		enum connman_service_type service_type;

		if (bearer == CONNMAN_SERVICE_TYPE_UNKNOWN)
			return true;

		service_type = connman_service_get_type(service);
		if (bearer == service_type)
			return true;
	}

	return false;
}

static bool service_match(struct connman_session *session,
					struct connman_service *service)
{
	if (!service_type_match(session, service))
		return false;

	return true;
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
			list; list = list->next) {
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
	struct connman_service *service_a = (void *)a;
	struct connman_service *service_b = (void *)b;
	struct connman_session *session = user_data;

	return sort_allowed_bearers(service_a, service_b, session);
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

static bool is_connected(enum connman_service_state state)
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
		return true;
	}

	return false;
}

static bool is_connecting(enum connman_service_state state)
{
	switch (state) {
	case CONNMAN_SERVICE_STATE_UNKNOWN:
	case CONNMAN_SERVICE_STATE_IDLE:
		break;
	case CONNMAN_SERVICE_STATE_ASSOCIATION:
	case CONNMAN_SERVICE_STATE_CONFIGURATION:
		return true;
	case CONNMAN_SERVICE_STATE_DISCONNECT:
	case CONNMAN_SERVICE_STATE_FAILURE:
	case CONNMAN_SERVICE_STATE_READY:
	case CONNMAN_SERVICE_STATE_ONLINE:
		break;
	}

	return false;
}

static bool is_disconnected(enum connman_service_state state)
{
	if (is_connected(state) || is_connecting(state))
		return false;

	return true;
}

static bool explicit_connect(enum connman_session_reason reason)
{
	switch (reason) {
	case CONNMAN_SESSION_REASON_UNKNOWN:
	case CONNMAN_SESSION_REASON_FREE_RIDE:
		break;
	case CONNMAN_SESSION_REASON_CONNECT:
		return true;
	}

	return false;
}

static void deselect_and_disconnect(struct connman_session *session)
{
	struct session_info *info = session->info;

	if (info->reason == CONNMAN_SESSION_REASON_CONNECT)
		__connman_service_set_active_session(false,
				info->config.allowed_bearers);

	info->reason = CONNMAN_SESSION_REASON_FREE_RIDE;

	info->state = CONNMAN_SESSION_STATE_DISCONNECTED;

	if (!session->service)
		return;

	session->service = NULL;

	update_routing_table(session);
}

static void select_connected_service(struct connman_session *session,
					struct connman_service *service)
{
	struct session_info *info = session->info;
	enum connman_service_state service_state;
	enum connman_session_state state;

	service_state = __connman_service_get_state(service);
	state = service_to_session_state(service_state);
	if (!is_type_matching_state(&state, info->config.type))
		return;

	info->state = state;

	session->service = service;
}

static void select_offline_service(struct connman_session *session,
					struct connman_service *service)
{
	struct session_info *info = session->info;
	enum connman_service_state service_state;

	if (!explicit_connect(info->reason))
		return;

	service_state = __connman_service_get_state(service);
	info->state = service_to_session_state(service_state);

	session->service = service;
}

static void select_service(struct connman_session *session,
				struct connman_service *service)
{
	enum connman_service_state service_state;

	DBG("service %p", service);

	service_state = __connman_service_get_state(service);
	if (is_connected(service_state))
		select_connected_service(session, service);
	else
		select_offline_service(session, service);
}

static void select_and_connect(struct connman_session *session,
				enum connman_session_reason reason)
{
	struct session_info *info = session->info;
	struct connman_service *service = NULL;
	enum connman_service_state service_state;
	GList *list;

	DBG("session %p reason %s", session, reason2string(reason));

	if (info->reason != reason &&
			reason == CONNMAN_SESSION_REASON_CONNECT) {
		__connman_service_set_active_session(true,
				info->config.allowed_bearers);

		__connman_service_auto_connect();
	}

	info->reason = reason;

	for (list = session->service_list; list; list = list->next) {
		service = list->data;

		service_state = __connman_service_get_state(service);
		switch (service_state) {
		case CONNMAN_SERVICE_STATE_ASSOCIATION:
		case CONNMAN_SERVICE_STATE_CONFIGURATION:
		case CONNMAN_SERVICE_STATE_READY:
		case CONNMAN_SERVICE_STATE_ONLINE:
		case CONNMAN_SERVICE_STATE_IDLE:
		case CONNMAN_SERVICE_STATE_DISCONNECT:
			select_service(session, service);
			update_routing_table(session);
			return;
		case CONNMAN_SERVICE_STATE_UNKNOWN:
		case CONNMAN_SERVICE_STATE_FAILURE:
			break;
		}
	}
}

static void iterate_service_cb(struct connman_service *service,
				void *user_data)
{
	struct connman_session *session = user_data;
	enum connman_service_state service_state;

	service_state = __connman_service_get_state(service);
	if (!is_connected(service_state))
		return;

	if (!service_match(session, service))
		return;

	g_hash_table_replace(session->service_hash, service, NULL);
}

static void populate_service_list(struct connman_session *session)
{
	GHashTableIter iter;
	gpointer key, value;

	session->service_hash =
		g_hash_table_new_full(g_direct_hash, g_direct_equal,
					NULL, NULL);
	__connman_service_iterate_services(iterate_service_cb, session);

	g_hash_table_iter_init(&iter, session->service_hash);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		struct connman_service *service = key;

		DBG("service %p type %s name %s", service,
			service2bearer(connman_service_get_type(service)),
			__connman_service_get_name(service));
		session->service_list = g_list_prepend(session->service_list,
							service);
	}

	session->service_list = g_list_sort_with_data(session->service_list,
						sort_services, session);
}

static void session_changed(struct connman_session *session,
				enum connman_session_trigger trigger)
{
	struct session_info *info = session->info;
	struct session_info *info_last = session->info_last;
	struct connman_service *service = NULL, *service_last = NULL;
	enum connman_service_state service_state;
	GHashTable *service_hash_last;

	/*
	 * TODO: This only a placeholder for the 'real' algorithm to
	 * play a bit around. So we are going to improve it step by step.
	 */

	DBG("session %p trigger %s reason %s", session, trigger2string(trigger),
						reason2string(info->reason));


	if (session->service) {
		enum connman_session_state state;

		service_state = __connman_service_get_state(session->service);
		state = service_to_session_state(service_state);

		if (is_type_matching_state(&state, info->config.type))
			info->state = state;
	}

	switch (trigger) {
	case CONNMAN_SESSION_TRIGGER_UNKNOWN:
		DBG("ignore session changed event");
		return;
	case CONNMAN_SESSION_TRIGGER_SETTING:
		if (info->config.allowed_bearers != info_last->config.allowed_bearers) {

			service_hash_last = session->service_hash;
			g_list_free(session->service_list);
			session->service_list = NULL;

			service = session->service;

			populate_service_list(session);

			if (service) {
				service_last = g_hash_table_lookup(
							service_hash_last,
							service);
			}

			if (service_last &&
				!g_hash_table_lookup(session->service_hash,
							service)) {

				/*
				 * The currently selected service is
				 * not part of this session anymore.
				 */
				deselect_and_disconnect(session);
			}

			g_hash_table_destroy(service_hash_last);
		}

		if (info->config.type != info_last->config.type) {
			if (info->state >= CONNMAN_SESSION_STATE_CONNECTED &&
					!is_type_matching_state(&info->state,
							info->config.type))
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
		if (info->state >= CONNMAN_SESSION_STATE_CONNECTED)
			break;

		if (session->service) {
			service_state = __connman_service_get_state(
						session->service);
			if (is_connecting(service_state))
				break;
		}

		select_and_connect(session, CONNMAN_SESSION_REASON_CONNECT);

		break;
	case CONNMAN_SESSION_TRIGGER_DISCONNECT:
		deselect_and_disconnect(session);

		break;
	case CONNMAN_SESSION_TRIGGER_SERVICE:
		if (session->service) {
			service_state = __connman_service_get_state(
						session->service);
			if (is_connecting(service_state) ||
				is_connected(service_state))
			break;
		}

		select_and_connect(session, info->reason);

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

	if (session->id_type != session->policy_config->id_type) {
		cleanup_firewall_session(session);
		err = init_firewall_session(session);
		if (err < 0) {
			connman_session_destroy(session);
			return err;
		}

		session->id_type = session->policy_config->id_type;
	}

	err = apply_policy_on_bearers(
		session->policy_config->allowed_bearers,
		session->user_allowed_bearers,
		&allowed_bearers);
	if (err < 0)
		return err;

	if (info->reason == CONNMAN_SESSION_REASON_CONNECT)
		__connman_service_set_active_session(false,
				info->config.allowed_bearers);

	g_slist_free(info->config.allowed_bearers);
	info->config.allowed_bearers = allowed_bearers;

	if (info->reason == CONNMAN_SESSION_REASON_CONNECT)
		__connman_service_set_active_session(true,
				info->config.allowed_bearers);

	info->config.type = apply_policy_on_type(
				session->policy_config->type,
				info->config.type);

	info->config.roaming_policy = session->policy_config->roaming_policy;

	info->config.ecall = session->policy_config->ecall;
	if (info->config.ecall)
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

	if (ecall_session) {
		if (ecall_session->ecall && ecall_session != session)
			return __connman_error_failed(msg, EBUSY);

		session->ecall = true;
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

	if (ecall_session) {
		if (ecall_session->ecall && ecall_session != session)
			return __connman_error_failed(msg, EBUSY);

		session->ecall = false;
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
	if (!dbus_message_iter_init(msg, &iter))
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
		if (g_str_equal(name, "AllowedBearers")) {
			err = parse_bearers(&value, &allowed_bearers);
			if (err < 0)
				return __connman_error_failed(msg, -err);

			if (info->reason == CONNMAN_SESSION_REASON_CONNECT)
				__connman_service_set_active_session(false,
						info->config.allowed_bearers);

			g_slist_free(info->config.allowed_bearers);
			session->user_allowed_bearers = allowed_bearers;

			err = apply_policy_on_bearers(
					session->policy_config->allowed_bearers,
					session->user_allowed_bearers,
					&info->config.allowed_bearers);

			if (err < 0)
				return __connman_error_failed(msg, -err);

			if (info->reason == CONNMAN_SESSION_REASON_CONNECT)
				__connman_service_set_active_session(true,
						info->config.allowed_bearers);

		} else {
			goto err;
		}
		break;
	case DBUS_TYPE_STRING:
		if (g_str_equal(name, "ConnectionType")) {
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
	if (!message)
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

	if (ecall_session && ecall_session != session)
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

static void session_nfacct_stats_cb(struct nfacct_context *ctx,
					uint64_t packets, uint64_t bytes,
					void *user_data)
{
	struct connman_session *session = user_data;

	DBG("session %p", session);

	/* XXX add accounting code here */
}

static int session_create_final(struct creation_data *creation_data,
				struct connman_session *session)
{
	struct session_info *info, *info_last;
	DBusMessage *reply;
	int err;

	DBG("");

	info = session->info;
	info_last = session->info_last;

	if (session->policy_config->ecall)
		ecall_session = session;

	info->state = CONNMAN_SESSION_STATE_DISCONNECTED;
	info->config.type = apply_policy_on_type(
				session->policy_config->type,
				creation_data->type);
	info->config.priority = session->policy_config->priority;
	info->config.roaming_policy = session->policy_config->roaming_policy;

	session->user_allowed_bearers = creation_data->allowed_bearers;
	creation_data->allowed_bearers = NULL;

	err = apply_policy_on_bearers(
			session->policy_config->allowed_bearers,
			session->user_allowed_bearers,
			&info->config.allowed_bearers);
	if (err < 0)
		goto err;

	g_hash_table_replace(session_hash, session->session_path, session);

	DBG("add %s", session->session_path);

	if (!g_dbus_register_interface(connection, session->session_path,
					CONNMAN_SESSION_INTERFACE,
					session_methods, NULL, NULL,
					session, NULL)) {
		connman_error("Failed to register %s", session->session_path);
		g_hash_table_remove(session_hash, session->session_path);
		err = -EINVAL;
		goto err;
	}

	reply = g_dbus_create_reply(creation_data->pending,
				DBUS_TYPE_OBJECT_PATH, &session->session_path,
				DBUS_TYPE_INVALID);
	g_dbus_send_message(connection, reply);
	creation_data->pending = NULL;

	populate_service_list(session);

	info_last->state = info->state;
	info_last->config.priority = info->config.priority;
	info_last->config.roaming_policy = info->config.roaming_policy;
	info_last->config.allowed_bearers = info->config.allowed_bearers;

	session->append_all = true;

	session_changed(session, CONNMAN_SESSION_TRIGGER_SETTING);

	cleanup_creation_data(creation_data);

err:
	return err;
}

static void session_nfacct_enable_cb(unsigned int error,
					struct nfacct_context *ctx,
					void *user_data)
{
	struct creation_data *creation_data = user_data;
	struct connman_session *session = creation_data->session;
	DBusMessage *reply;
	int err;

	DBG("");

	if (error != 0) {
		err = -error;
		goto err;
	}

	err = init_firewall_session(session);
	if (err < 0)
		goto err;

	err = init_routing_table(session);
	if (err < 0)
		goto err;

	err = session_create_final(creation_data, session);
	if (err < 0)
		goto err;

	return;

err:
	reply = __connman_error_failed(creation_data->pending, -err);
	g_dbus_send_message(connection, reply);
	creation_data->pending = NULL;

	cleanup_session(creation_data->session);
	cleanup_creation_data(creation_data);
}

static int session_policy_config_cb(struct connman_session *session,
				struct connman_session_config *config,
				void *user_data, int err)
{
	struct creation_data *creation_data = user_data;
	char *input, *output;
	DBusMessage *reply;

	DBG("session %p config %p", session, config);

	if (err < 0)
		goto err;

	session->policy_config = config;

	session->mark = session_mark++;
	session->index = -1;

	session->nfctx = __connman_nfacct_create_context();
	if (!session->nfctx) {
		err = -ENOMEM;
		goto err;
	}

	input = g_strdup_printf("session-input-%d", session->mark);
	err = __connman_nfacct_add(session->nfctx, input,
					session_nfacct_stats_cb,
					session);
	g_free(input);
	if (err < 0)
		goto err;

	output = g_strdup_printf("session-output-%d", session->mark);
	err = __connman_nfacct_add(session->nfctx, output,
					session_nfacct_stats_cb,
					session);
	g_free(output);
	if (err < 0)
		goto err;

	err = __connman_nfacct_enable(session->nfctx,
					session_nfacct_enable_cb,
					creation_data);
	if (err < 0)
		goto err;

	return -EINPROGRESS;

err:
	reply = __connman_error_failed(creation_data->pending, -err);
	g_dbus_send_message(connection, reply);
	creation_data->pending = NULL;

	cleanup_session(session);
	cleanup_creation_data(creation_data);

	return err;
}

int __connman_session_create(DBusMessage *msg)
{
	const char *owner, *notify_path;
	char *session_path = NULL;
	DBusMessageIter iter, array;
	struct connman_session *session = NULL;
	struct creation_data *creation_data = NULL;
	bool user_allowed_bearers = false;
	bool user_connection_type = false;
	int err, i;
	char *str;

	owner = dbus_message_get_sender(msg);

	DBG("owner %s", owner);

	if (ecall_session && ecall_session->ecall) {
		/*
		 * If there is an emergency call already going on,
		 * ignore session creation attempt
		 */
		err = -EBUSY;
		goto err;
	}

	creation_data = g_try_new0(struct creation_data, 1);
	if (!creation_data) {
		err = -ENOMEM;
		goto err;
	}

	creation_data->pending = dbus_message_ref(msg);

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
			if (g_str_equal(key, "AllowedBearers")) {
				err = parse_bearers(&value,
					&creation_data->allowed_bearers);
				if (err < 0)
					goto err;

				user_allowed_bearers = true;
			} else {
				err = -EINVAL;
				goto err;
			}
			break;
		case DBUS_TYPE_STRING:
			if (g_str_equal(key, "ConnectionType")) {
				dbus_message_iter_get_basic(&value, &val);
				creation_data->type =
					connman_session_parse_connection_type(val);

				user_connection_type = true;
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
	if (!user_allowed_bearers) {
		creation_data->allowed_bearers =
			g_slist_append(NULL,
				GINT_TO_POINTER(CONNMAN_SERVICE_TYPE_UNKNOWN));
		if (!creation_data->allowed_bearers) {
			err = -ENOMEM;
			goto err;
		}
	}

	/* ... and for ConnectionType it is 'any'. */
	if (!user_connection_type)
		creation_data->type = CONNMAN_SESSION_TYPE_ANY;

	dbus_message_iter_next(&iter);
	dbus_message_iter_get_basic(&iter, &notify_path);

	if (!notify_path) {
		err = -EINVAL;
		goto err;
	}

	str = g_strdup(owner);
	for (i = 0; str[i] != '\0'; i++)
		if (str[i] == ':' || str[i] == '.')
			str[i] = '_';
	session_path = g_strdup_printf("/sessions/%s%s", str, notify_path);
	g_free(str);

	if (!session_path) {
		err = -ENOMEM;
		goto err;
	}

	session = g_hash_table_lookup(session_hash, session_path);
	if (session) {
		g_free(session_path);
		session = NULL;
		err = -EEXIST;
		goto err;
	}

	session = g_try_new0(struct connman_session, 1);
	if (!session) {
		g_free(session_path);
		err = -ENOMEM;
		goto err;
	}

	creation_data->session = session;
	session->session_path = session_path;

	session->info = g_try_new0(struct session_info, 1);
	if (!session->info) {
		err = -ENOMEM;
		goto err;
	}

	session->info_last = g_try_new0(struct session_info, 1);
	if (!session->info_last) {
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

	err = create_policy_config(session, session_policy_config_cb,
					creation_data);
	if (err < 0 && err != -EINPROGRESS)
		return err;

	return -EINPROGRESS;

err:
	connman_error("Failed to create session");

	free_session(session);

	cleanup_creation_data(creation_data);
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
	if (!session_path)
		return -EINVAL;

	session = g_hash_table_lookup(session_hash, session_path);
	if (!session)
		return -EINVAL;

	if (g_strcmp0(owner, session->owner) != 0)
		return -EACCES;

	connman_session_destroy(session);

	return 0;
}

static void service_add(struct connman_service *service, const char *name)
{
	GHashTableIter iter;
	gpointer key, value;
	struct connman_session *session;

	DBG("service %p", service);

	g_hash_table_iter_init(&iter, session_hash);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		session = value;

		if (!service_match(session, service))
			continue;

		if (g_hash_table_lookup(session->service_hash, service)) {
			session->service_list =
				g_list_sort_with_data(session->service_list,
						sort_services, session);
		} else {
			session->service_list =
				g_list_insert_sorted_with_data(
				session->service_list, service,
				sort_services, session);

			g_hash_table_replace(session->service_hash,
						service, service);
		}

		session_changed(session, CONNMAN_SESSION_TRIGGER_SERVICE);
	}
}

static void service_remove(struct connman_service *service)
{
	GHashTableIter iter;
	gpointer key, value;

	DBG("service %p", service);

	g_hash_table_iter_init(&iter, session_hash);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		struct connman_session *session = value;

		if (!g_hash_table_lookup(session->service_hash, service))
			continue;

		session->service_list = g_list_remove(session->service_list,
							service);

		g_hash_table_remove(session->service_hash, service);

		if (session->service && session->service == service)
			session->service = NULL;
		session_changed(session, CONNMAN_SESSION_TRIGGER_SERVICE);
	}
}

static void service_state_changed(struct connman_service *service,
					enum connman_service_state state)
{
	DBG("service %p state %d", service, state);

	if (is_connected(state))
		service_add(service, __connman_service_get_name(service));
	else if (is_disconnected(state))
		service_remove(service);
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

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		session = value;
		info = session->info;

		if (info->state == CONNMAN_SESSION_STATE_DISCONNECTED)
			continue;

		if (session->service && session->service == service) {
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

static int session_nfacct_flush_cb(unsigned int error, void *user_data)
{
	if (error == 0)
		return 0;

	connman_error("Could not flush nfacct table: %s", strerror(error));

	return -error;
}

int __connman_session_init(void)
{
	int err;

	DBG("");

	connection = connman_dbus_get_connection();
	if (!connection)
		return -1;

	err = connman_notifier_register(&session_notifier);
	if (err < 0) {
		dbus_connection_unref(connection);
		return err;
	}

	session_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						NULL, cleanup_session);

	if (__connman_firewall_is_up()) {
		err = init_firewall();
		if (err < 0)
			return err;
		__connman_nfacct_flush(session_nfacct_flush_cb, NULL);
	}

	return 0;
}

void __connman_session_cleanup(void)
{
	DBG("");

	if (!connection)
		return;

	cleanup_firewall();

	connman_notifier_unregister(&session_notifier);

	g_hash_table_foreach(session_hash, release_session, NULL);
	g_hash_table_destroy(session_hash);
	session_hash = NULL;

	dbus_connection_unref(connection);
}
