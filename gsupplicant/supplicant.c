/*
 *
 *  WPA supplicant library with GLib integration
 *
 *  Copyright (C) 2010  Intel Corporation. All rights reserved.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <syslog.h>

#include <glib.h>
#include <gdbus.h>

#include "dbus.h"
#include "gsupplicant.h"

#define TIMEOUT 5000

#define IEEE80211_CAP_ESS	0x0001
#define IEEE80211_CAP_IBSS	0x0002
#define IEEE80211_CAP_PRIVACY	0x0010

static DBusConnection *connection;

static const GSupplicantCallbacks *callbacks_pointer;

static dbus_bool_t system_available = FALSE;
static dbus_bool_t system_ready = FALSE;

static dbus_int32_t debug_level;
static dbus_bool_t debug_timestamp = FALSE;
static dbus_bool_t debug_showkeys = FALSE;

static const char *debug_strings[] = {
	"msgdump", "debug", "info", "warning", "error", NULL
};

static unsigned int eap_methods;

struct strvalmap {
	const char *str;
	unsigned int val;
};

static struct strvalmap eap_method_map[] = {
	{ "MD5",	G_SUPPLICANT_EAP_METHOD_MD5	},
	{ "TLS",	G_SUPPLICANT_EAP_METHOD_TLS	},
	{ "MSCHAPV2",	G_SUPPLICANT_EAP_METHOD_MSCHAPV2	},
	{ "PEAP",	G_SUPPLICANT_EAP_METHOD_PEAP	},
	{ "TTLS",	G_SUPPLICANT_EAP_METHOD_TTLS	},
	{ "GTC",	G_SUPPLICANT_EAP_METHOD_GTC	},
	{ "OTP",	G_SUPPLICANT_EAP_METHOD_OTP	},
	{ "LEAP",	G_SUPPLICANT_EAP_METHOD_LEAP	},
	{ "WSC",	G_SUPPLICANT_EAP_METHOD_WSC	},
	{ }
};

static struct strvalmap keymgmt_map[] = {
	{ "none",		G_SUPPLICANT_KEYMGMT_NONE		},
	{ "ieee8021x",		G_SUPPLICANT_KEYMGMT_IEEE8021X	},
	{ "wpa-none",		G_SUPPLICANT_KEYMGMT_WPA_NONE	},
	{ "wpa-psk",		G_SUPPLICANT_KEYMGMT_WPA_PSK	},
	{ "wpa-psk-sha256",	G_SUPPLICANT_KEYMGMT_WPA_PSK_256	},
	{ "wpa-ft-psk",		G_SUPPLICANT_KEYMGMT_WPA_FT_PSK	},
	{ "wpa-ft-eap",		G_SUPPLICANT_KEYMGMT_WPA_FT_EAP	},
	{ "wpa-eap",		G_SUPPLICANT_KEYMGMT_WPA_EAP	},
	{ "wpa-eap-sha256",	G_SUPPLICANT_KEYMGMT_WPA_EAP_256	},
	{ "wps",		G_SUPPLICANT_KEYMGMT_WPS		},
	{ }
};

static struct strvalmap authalg_capa_map[] = {
	{ "open",	G_SUPPLICANT_CAPABILITY_AUTHALG_OPEN	},
	{ "shared",	G_SUPPLICANT_CAPABILITY_AUTHALG_SHARED	},
	{ "leap",	G_SUPPLICANT_CAPABILITY_AUTHALG_LEAP	},
	{ }
};

static struct strvalmap proto_capa_map[] = {
	{ "wpa",	G_SUPPLICANT_CAPABILITY_PROTO_WPA		},
	{ "rsn",	G_SUPPLICANT_CAPABILITY_PROTO_RSN		},
	{ }
};

static struct strvalmap group_map[] = {
	{ "wep40",	G_SUPPLICANT_GROUP_WEP40	},
	{ "wep104",	G_SUPPLICANT_GROUP_WEP104	},
	{ "tkip",	G_SUPPLICANT_GROUP_TKIP	},
	{ "ccmp",	G_SUPPLICANT_GROUP_CCMP	},
	{ }
};

static struct strvalmap pairwise_map[] = {
	{ "none",	G_SUPPLICANT_PAIRWISE_NONE	},
	{ "tkip",	G_SUPPLICANT_PAIRWISE_TKIP	},
	{ "ccmp",	G_SUPPLICANT_PAIRWISE_CCMP	},
	{ }
};

static struct strvalmap scan_capa_map[] = {
	{ "active",	G_SUPPLICANT_CAPABILITY_SCAN_ACTIVE	},
	{ "passive",	G_SUPPLICANT_CAPABILITY_SCAN_PASSIVE	},
	{ "ssid",	G_SUPPLICANT_CAPABILITY_SCAN_SSID		},
	{ }
};

static struct strvalmap mode_capa_map[] = {
	{ "infrastructure",	G_SUPPLICANT_CAPABILITY_MODE_INFRA	},
	{ "ad-hoc",		G_SUPPLICANT_CAPABILITY_MODE_IBSS	},
	{ "ap",			G_SUPPLICANT_CAPABILITY_MODE_AP		},
	{ }
};

static GHashTable *interface_table;
static GHashTable *bss_mapping;

struct _GSupplicantInterface {
	char *path;
	unsigned int keymgmt_capa;
	unsigned int authalg_capa;
	unsigned int proto_capa;
	unsigned int group_capa;
	unsigned int pairwise_capa;
	unsigned int scan_capa;
	unsigned int mode_capa;
	dbus_bool_t ready;
	GSupplicantState state;
	dbus_bool_t scanning;
	GSupplicantInterfaceCallback scan_callback;
	void *scan_data;
	int apscan;
	char *ifname;
	char *driver;
	char *bridge;
	GHashTable *network_table;
	GHashTable *net_mapping;
	GHashTable *bss_mapping;
	void *data;
};

struct _GSupplicantNetwork {
	GSupplicantInterface *interface;
	char *path;
	char *group;
	char *name;
	unsigned char ssid[32];
	unsigned int ssid_len;
	dbus_int16_t signal;
	GSupplicantMode mode;
	GSupplicantSecurity security;
	GHashTable *bss_table;
	GHashTable *config_table;
};

struct g_supplicant_bss {
	GSupplicantInterface *interface;
	char *path;
	unsigned char bssid[6];
	unsigned char ssid[32];
	unsigned int ssid_len;
	dbus_uint16_t frequency;
	dbus_uint32_t maxrate;
	dbus_int16_t signal;
	GSupplicantMode mode;
	GSupplicantSecurity security;
	unsigned int keymgmt;
	unsigned int pairwise;
	unsigned int group;
	dbus_bool_t privacy;
	dbus_bool_t psk;
	dbus_bool_t ieee8021x;
};

static inline void debug(const char *format, ...)
{
	char str[256];
	va_list ap;

	if (callbacks_pointer->debug == NULL)
		return;

	va_start(ap, format);

	if (vsnprintf(str, sizeof(str), format, ap) > 0)
		callbacks_pointer->debug(str);

	va_end(ap);
}

#define SUPPLICANT_DBG(fmt, arg...) \
	debug("%s:%s() " fmt, __FILE__, __FUNCTION__ , ## arg);

static GSupplicantMode string2mode(const char *mode)
{
	if (mode == NULL)
		return G_SUPPLICANT_MODE_UNKNOWN;

	if (g_str_equal(mode, "infrastructure") == TRUE)
		return G_SUPPLICANT_MODE_INFRA;
	else if (g_str_equal(mode, "ad-hoc") == TRUE)
		return G_SUPPLICANT_MODE_IBSS;

	return G_SUPPLICANT_MODE_UNKNOWN;
}

static const char *mode2string(GSupplicantMode mode)
{
	switch (mode) {
	case G_SUPPLICANT_MODE_UNKNOWN:
		break;
	case G_SUPPLICANT_MODE_INFRA:
		return "managed";
	case G_SUPPLICANT_MODE_IBSS:
		return "adhoc";
	}

	return NULL;
}

static const char *security2string(GSupplicantSecurity security)
{
	switch (security) {
	case G_SUPPLICANT_SECURITY_UNKNOWN:
		break;
	case G_SUPPLICANT_SECURITY_NONE:
		return "none";
	case G_SUPPLICANT_SECURITY_WEP:
		return "wep";
	case G_SUPPLICANT_SECURITY_PSK:
		return "psk";
	case G_SUPPLICANT_SECURITY_IEEE8021X:
		return "ieee8021x";
	}

	return NULL;
}

static GSupplicantState string2state(const char *state)
{
	if (state == NULL)
		return G_SUPPLICANT_STATE_UNKNOWN;

	if (g_str_equal(state, "unknown") == TRUE)
		return G_SUPPLICANT_STATE_UNKNOWN;
	else if (g_str_equal(state, "disconnected") == TRUE)
		return G_SUPPLICANT_STATE_DISCONNECTED;
	else if (g_str_equal(state, "inactive") == TRUE)
		return G_SUPPLICANT_STATE_INACTIVE;
	else if (g_str_equal(state, "scanning") == TRUE)
		return G_SUPPLICANT_STATE_SCANNING;
	else if (g_str_equal(state, "authenticating") == TRUE)
		return G_SUPPLICANT_STATE_AUTHENTICATING;
	else if (g_str_equal(state, "associating") == TRUE)
		return G_SUPPLICANT_STATE_ASSOCIATING;
	else if (g_str_equal(state, "associated") == TRUE)
		return G_SUPPLICANT_STATE_ASSOCIATED;
	else if (g_str_equal(state, "group_handshake") == TRUE)
		return G_SUPPLICANT_STATE_GROUP_HANDSHAKE;
	else if (g_str_equal(state, "4way_handshake") == TRUE)
		return G_SUPPLICANT_STATE_4WAY_HANDSHAKE;
	else if (g_str_equal(state, "completed") == TRUE)
		return G_SUPPLICANT_STATE_COMPLETED;

	return G_SUPPLICANT_STATE_UNKNOWN;
}

static void callback_system_ready(void)
{
	if (system_ready == TRUE)
		return;

	system_ready = TRUE;

	if (callbacks_pointer == NULL)
		return;

	if (callbacks_pointer->system_ready == NULL)
		return;

	callbacks_pointer->system_ready();
}

static void callback_system_killed(void)
{
	system_ready = FALSE;

	if (callbacks_pointer == NULL)
		return;

	if (callbacks_pointer->system_killed == NULL)
		return;

	callbacks_pointer->system_killed();
}

static void callback_interface_added(GSupplicantInterface *interface)
{
	SUPPLICANT_DBG("");

	if (callbacks_pointer == NULL)
		return;

	if (callbacks_pointer->interface_added == NULL)
		return;

	callbacks_pointer->interface_added(interface);
}

static void callback_interface_state(GSupplicantInterface *interface)
{
	if (callbacks_pointer == NULL)
		return;

	if (callbacks_pointer->interface_state == NULL)
		return;

	callbacks_pointer->interface_state(interface);
}

static void callback_interface_removed(GSupplicantInterface *interface)
{
	if (callbacks_pointer == NULL)
		return;

	if (callbacks_pointer->interface_removed == NULL)
		return;

	callbacks_pointer->interface_removed(interface);
}

static void callback_scan_started(GSupplicantInterface *interface)
{
	if (callbacks_pointer == NULL)
		return;

	if (callbacks_pointer->scan_started == NULL)
		return;

	callbacks_pointer->scan_started(interface);
}

static void callback_scan_finished(GSupplicantInterface *interface)
{
	if (callbacks_pointer == NULL)
		return;

	if (callbacks_pointer->scan_finished == NULL)
		return;

	callbacks_pointer->scan_finished(interface);
}

static void callback_network_added(GSupplicantNetwork *network)
{
	if (callbacks_pointer == NULL)
		return;

	if (callbacks_pointer->network_added == NULL)
		return;

	callbacks_pointer->network_added(network);
}

static void callback_network_removed(GSupplicantNetwork *network)
{
	if (callbacks_pointer == NULL)
		return;

	if (callbacks_pointer->network_removed == NULL)
		return;

	callbacks_pointer->network_removed(network);
}

static void remove_interface(gpointer data)
{
	GSupplicantInterface *interface = data;

	g_hash_table_destroy(interface->bss_mapping);
	g_hash_table_destroy(interface->net_mapping);
	g_hash_table_destroy(interface->network_table);

	callback_interface_removed(interface);

	g_free(interface->path);
	g_free(interface->ifname);
	g_free(interface->driver);
	g_free(interface->bridge);
	g_free(interface);
}

static void remove_network(gpointer data)
{
	GSupplicantNetwork *network = data;

	g_hash_table_destroy(network->bss_table);

	callback_network_removed(network);

	g_hash_table_destroy(network->config_table);

	g_free(network->group);
	g_free(network->name);
	g_free(network);
}

static void remove_bss(gpointer data)
{
	struct g_supplicant_bss *bss = data;

	g_free(bss->path);
	g_free(bss);
}

static void debug_strvalmap(const char *label, struct strvalmap *map,
							unsigned int val)
{
	int i;

	for (i = 0; map[i].str != NULL; i++) {
		if (val & map[i].val)
			SUPPLICANT_DBG("%s: %s", label, map[i].str);
	}
}

static void interface_capability_keymgmt(DBusMessageIter *iter, void *user_data)
{
	GSupplicantInterface *interface = user_data;
	const char *str = NULL;
	int i;

	dbus_message_iter_get_basic(iter, &str);
	if (str == NULL)
		return;

	for (i = 0; keymgmt_map[i].str != NULL; i++)
		if (strcmp(str, keymgmt_map[i].str) == 0) {
			interface->keymgmt_capa |= keymgmt_map[i].val;
			break;
		}
}

static void interface_capability_authalg(DBusMessageIter *iter, void *user_data)
{
	GSupplicantInterface *interface = user_data;
	const char *str = NULL;
	int i;

	dbus_message_iter_get_basic(iter, &str);
	if (str == NULL)
		return;

	for (i = 0; authalg_capa_map[i].str != NULL; i++)
		if (strcmp(str, authalg_capa_map[i].str) == 0) {
			interface->authalg_capa |= authalg_capa_map[i].val;
			break;
		}
}

static void interface_capability_proto(DBusMessageIter *iter, void *user_data)
{
	GSupplicantInterface *interface = user_data;
	const char *str = NULL;
	int i;

	dbus_message_iter_get_basic(iter, &str);
	if (str == NULL)
		return;

	for (i = 0; proto_capa_map[i].str != NULL; i++)
		if (strcmp(str, proto_capa_map[i].str) == 0) {
			interface->proto_capa |= proto_capa_map[i].val;
			break;
		}
}

static void interface_capability_pairwise(DBusMessageIter *iter,
							void *user_data)
{
	GSupplicantInterface *interface = user_data;
	const char *str = NULL;
	int i;

	dbus_message_iter_get_basic(iter, &str);
	if (str == NULL)
		return;

	for (i = 0; pairwise_map[i].str != NULL; i++)
		if (strcmp(str, pairwise_map[i].str) == 0) {
			interface->pairwise_capa |= pairwise_map[i].val;
			break;
		}
}

static void interface_capability_group(DBusMessageIter *iter, void *user_data)
{
	GSupplicantInterface *interface = user_data;
	const char *str = NULL;
	int i;

	dbus_message_iter_get_basic(iter, &str);
	if (str == NULL)
		return;

	for (i = 0; group_map[i].str != NULL; i++)
		if (strcmp(str, group_map[i].str) == 0) {
			interface->group_capa |= group_map[i].val;
			break;
		}
}

static void interface_capability_scan(DBusMessageIter *iter, void *user_data)
{
	GSupplicantInterface *interface = user_data;
	const char *str = NULL;
	int i;

	dbus_message_iter_get_basic(iter, &str);
	if (str == NULL)
		return;

	for (i = 0; scan_capa_map[i].str != NULL; i++)
		if (strcmp(str, scan_capa_map[i].str) == 0) {
			interface->scan_capa |= scan_capa_map[i].val;
			break;
		}
}

static void interface_capability_mode(DBusMessageIter *iter, void *user_data)
{
	GSupplicantInterface *interface = user_data;
	const char *str = NULL;
	int i;

	dbus_message_iter_get_basic(iter, &str);
	if (str == NULL)
		return;

	for (i = 0; mode_capa_map[i].str != NULL; i++)
		if (strcmp(str, mode_capa_map[i].str) == 0) {
			interface->mode_capa |= mode_capa_map[i].val;
			break;
		}
}

static void interface_capability(const char *key, DBusMessageIter *iter,
							void *user_data)
{
	GSupplicantInterface *interface = user_data;

	if (key == NULL)
		return;

	if (g_strcmp0(key, "KeyMgmt") == 0)
		supplicant_dbus_array_foreach(iter,
				interface_capability_keymgmt, interface);
	else if (g_strcmp0(key, "AuthAlg") == 0)
		supplicant_dbus_array_foreach(iter,
				interface_capability_authalg, interface);
	else if (g_strcmp0(key, "Protocol") == 0)
		supplicant_dbus_array_foreach(iter,
				interface_capability_proto, interface);
	else if (g_strcmp0(key, "Pairwise") == 0)
		supplicant_dbus_array_foreach(iter,
				interface_capability_pairwise, interface);
	else if (g_strcmp0(key, "Group") == 0)
		supplicant_dbus_array_foreach(iter,
				interface_capability_group, interface);
	else if (g_strcmp0(key, "Scan") == 0)
		supplicant_dbus_array_foreach(iter,
				interface_capability_scan, interface);
	else if (g_strcmp0(key, "Modes") == 0)
		supplicant_dbus_array_foreach(iter,
				interface_capability_mode, interface);
	else
		SUPPLICANT_DBG("key %s type %c",
				key, dbus_message_iter_get_arg_type(iter));
}

void g_supplicant_interface_set_data(GSupplicantInterface *interface,
								void *data)
{
	if (interface == NULL)
		return;

	interface->data = data;
}

void *g_supplicant_interface_get_data(GSupplicantInterface *interface)
{
	if (interface == NULL)
		return NULL;

	return interface->data;
}

const char *g_supplicant_interface_get_ifname(GSupplicantInterface *interface)
{
	if (interface == NULL)
		return NULL;

	return interface->ifname;
}

const char *g_supplicant_interface_get_driver(GSupplicantInterface *interface)
{
	if (interface == NULL)
		return NULL;

	return interface->driver;
}

GSupplicantState g_supplicant_interface_get_state(
					GSupplicantInterface *interface)
{
	if (interface == NULL)
		return G_SUPPLICANT_STATE_UNKNOWN;

	return interface->state;
}

GSupplicantInterface *g_supplicant_network_get_interface(
					GSupplicantNetwork *network)
{
	if (network == NULL)
		return NULL;

	return network->interface;
}

const char *g_supplicant_network_get_name(GSupplicantNetwork *network)
{
	if (network == NULL || network->name == NULL)
		return "";

	return network->name;
}

const char *g_supplicant_network_get_identifier(GSupplicantNetwork *network)
{
	if (network == NULL || network->group == NULL)
		return "";

	return network->group;
}

const char *g_supplicant_network_get_path(GSupplicantNetwork *network)
{
	if (network == NULL || network->path == NULL)
		return NULL;

	return network->path;
}

const char *g_supplicant_network_get_mode(GSupplicantNetwork *network)
{
	if (network == NULL)
		return G_SUPPLICANT_MODE_UNKNOWN;

	return mode2string(network->mode);
}

const char *g_supplicant_network_get_security(GSupplicantNetwork *network)
{
	if (network == NULL)
		return G_SUPPLICANT_SECURITY_UNKNOWN;

	return security2string(network->security);
}

const void *g_supplicant_network_get_ssid(GSupplicantNetwork *network,
						unsigned int *ssid_len)
{
	if (network == NULL || network->ssid == NULL) {
		*ssid_len = 0;
		return NULL;
	}

	*ssid_len = network->ssid_len;
	return network->ssid;
}

dbus_int16_t g_supplicant_network_get_signal(GSupplicantNetwork *network)
{
	if (network == NULL)
		return 0;

	return network->signal;
}

static void merge_network(GSupplicantNetwork *network)
{
	GString *str;
	const char *ssid, *mode, *key_mgmt;
	unsigned int i, ssid_len;
	char *group;

	ssid = g_hash_table_lookup(network->config_table, "ssid");
	mode = g_hash_table_lookup(network->config_table, "mode");
	key_mgmt = g_hash_table_lookup(network->config_table, "key_mgmt");

	SUPPLICANT_DBG("ssid %s mode %s", ssid, mode);

	if (ssid != NULL)
		ssid_len = strlen(ssid);
	else
		ssid_len = 0;

	str = g_string_sized_new((ssid_len * 2) + 24);
	if (str == NULL)
		return;

	for (i = 0; i < ssid_len; i++)
		g_string_append_printf(str, "%02x", ssid[i]);

	if (g_strcmp0(mode, "0") == 0)
		g_string_append_printf(str, "_managed");
	else if (g_strcmp0(mode, "1") == 0)
		g_string_append_printf(str, "_adhoc");

	if (g_strcmp0(key_mgmt, "WPA-PSK") == 0)
		g_string_append_printf(str, "_psk");

	group = g_string_free(str, FALSE);

	SUPPLICANT_DBG("%s", group);

	g_free(group);

	g_hash_table_destroy(network->config_table);

	g_free(network->path);
	g_free(network);
}

static void network_property(const char *key, DBusMessageIter *iter,
							void *user_data)
{
	GSupplicantNetwork *network = user_data;

	if (network->interface == NULL)
		return;

	if (key == NULL) {
		merge_network(network);
		return;
	}

	if (g_strcmp0(key, "Enabled") == 0) {
		dbus_bool_t enabled = FALSE;

		dbus_message_iter_get_basic(iter, &enabled);
	} else if (dbus_message_iter_get_arg_type(iter) == DBUS_TYPE_STRING) {
		const char *str = NULL;

		dbus_message_iter_get_basic(iter, &str);
		if (str != NULL) {
			g_hash_table_replace(network->config_table,
						g_strdup(key), g_strdup(str));
		}
	} else
		SUPPLICANT_DBG("key %s type %c",
				key, dbus_message_iter_get_arg_type(iter));
}

static void interface_network_added(DBusMessageIter *iter, void *user_data)
{
	GSupplicantInterface *interface = user_data;
	GSupplicantNetwork *network;
	const char *path = NULL;

	SUPPLICANT_DBG("");

	dbus_message_iter_get_basic(iter, &path);
	if (path == NULL)
		return;

	if (g_strcmp0(path, "/") == 0)
		return;

	network = g_hash_table_lookup(interface->net_mapping, path);
	if (network != NULL)
		return;

	network = g_try_new0(GSupplicantNetwork, 1);
	if (network == NULL)
		return;

	network->interface = interface;
	network->path = g_strdup(path);

	network->config_table = g_hash_table_new_full(g_str_hash, g_str_equal,
							g_free, g_free);

	dbus_message_iter_next(iter);
	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_INVALID) {
		supplicant_dbus_property_foreach(iter, network_property,
								network);
		network_property(NULL, NULL, network);
		return;
	}

	supplicant_dbus_property_get_all(path,
				SUPPLICANT_INTERFACE ".Interface.Network",
						network_property, network);
}

static void interface_network_removed(DBusMessageIter *iter, void *user_data)
{
	GSupplicantInterface *interface = user_data;
	GSupplicantNetwork *network;
	const char *path = NULL;

	dbus_message_iter_get_basic(iter, &path);
	if (path == NULL)
		return;

	network = g_hash_table_lookup(interface->net_mapping, path);
	if (network == NULL)
		return;

	g_hash_table_remove(interface->net_mapping, path);
}

static char *create_name(unsigned char *ssid, int ssid_len)
{
	char *name;
	int i;

	if (ssid_len < 1 || ssid[0] == '\0')
		name = NULL;
	else
		name = g_try_malloc0(ssid_len + 1);

	if (name == NULL)
		return g_strdup("");

	for (i = 0; i < ssid_len; i++) {
		if (g_ascii_isprint(ssid[i]))
			name[i] = ssid[i];
		else
			name[i] = ' ';
	}

	return name;
}

static char *create_group(struct g_supplicant_bss *bss)
{
	GString *str;
	unsigned int i;
	const char *mode, *security;

	str = g_string_sized_new((bss->ssid_len * 2) + 24);
	if (str == NULL)
		return NULL;

	if (bss->ssid_len > 0 && bss->ssid[0] != '\0') {
		for (i = 0; i < bss->ssid_len; i++)
			g_string_append_printf(str, "%02x", bss->ssid[i]);
	} else
		g_string_append_printf(str, "hidden");

	mode = mode2string(bss->mode);
	if (mode != NULL)
		g_string_append_printf(str, "_%s", mode);

	security = security2string(bss->security);
	if (security != NULL)
		g_string_append_printf(str, "_%s", security);

	return g_string_free(str, FALSE);
}

static void add_bss_to_network(struct g_supplicant_bss *bss)
{
	GSupplicantInterface *interface = bss->interface;
	GSupplicantNetwork *network;
	char *group;

	group = create_group(bss);
	if (group == NULL)
		return;

	network = g_hash_table_lookup(interface->network_table, group);
	if (network != NULL) {
		g_free(group);
		goto done;
	}

	network = g_try_new0(GSupplicantNetwork, 1);
	if (network == NULL) {
		g_free(group);
		return;
	}

	network->interface = interface;
	if (network->path == NULL)
		network->path = g_strdup(bss->path);
	network->group = group;
	network->name = create_name(bss->ssid, bss->ssid_len);
	network->mode = bss->mode;
	network->security = bss->security;
	network->ssid_len = bss->ssid_len;
	memcpy(network->ssid, bss->ssid, bss->ssid_len);
	network->signal = bss->signal;

	network->bss_table = g_hash_table_new_full(g_str_hash, g_str_equal,
							NULL, remove_bss);

	network->config_table = g_hash_table_new_full(g_str_hash, g_str_equal,
							g_free, g_free);

	g_hash_table_replace(interface->network_table,
						network->group, network);

	callback_network_added(network);

done:
	g_hash_table_replace(interface->bss_mapping, bss->path, network);
	g_hash_table_replace(network->bss_table, bss->path, bss);

	g_hash_table_replace(bss_mapping, bss->path, interface);
}

static void bss_rates(DBusMessageIter *iter, void *user_data)
{
	struct g_supplicant_bss *bss = user_data;
	dbus_uint32_t rate = 0;

	dbus_message_iter_get_basic(iter, &rate);
	if (rate == 0)
		return;

	if (rate > bss->maxrate)
		bss->maxrate = rate;
}

static void bss_keymgmt(DBusMessageIter *iter, void *user_data)
{
	struct g_supplicant_bss *bss = user_data;
	const char *str = NULL;
	int i;

	dbus_message_iter_get_basic(iter, &str);
	if (str == NULL)
		return;

	for (i = 0; keymgmt_map[i].str != NULL; i++)
		if (strcmp(str, keymgmt_map[i].str) == 0) {
			bss->keymgmt |= keymgmt_map[i].val;
			break;
		}
}

static void bss_group(DBusMessageIter *iter, void *user_data)
{
	struct g_supplicant_bss *bss = user_data;
	const char *str = NULL;
	int i;

	dbus_message_iter_get_basic(iter, &str);
	if (str == NULL)
		return;

	for (i = 0; group_map[i].str != NULL; i++)
		if (strcmp(str, group_map[i].str) == 0) {
			bss->group |= group_map[i].val;
			break;
		}
}

static void bss_pairwise(DBusMessageIter *iter, void *user_data)
{
	struct g_supplicant_bss *bss = user_data;
	const char *str = NULL;
	int i;

	dbus_message_iter_get_basic(iter, &str);
	if (str == NULL)
		return;

	for (i = 0; pairwise_map[i].str != NULL; i++)
		if (strcmp(str, pairwise_map[i].str) == 0) {
			bss->pairwise |= pairwise_map[i].val;
			break;
		}
}

static void bss_wpa(const char *key, DBusMessageIter *iter,
			void *user_data)
{
	if (g_strcmp0(key, "KeyMgmt") == 0)
		supplicant_dbus_array_foreach(iter, bss_keymgmt, user_data);
	else if (g_strcmp0(key, "Group") == 0)
		supplicant_dbus_array_foreach(iter, bss_group, user_data);
	else if (g_strcmp0(key, "Pairwise") == 0)
		supplicant_dbus_array_foreach(iter, bss_pairwise, user_data);

}


static void bss_property(const char *key, DBusMessageIter *iter,
							void *user_data)
{
	struct g_supplicant_bss *bss = user_data;

	if (bss->interface == NULL)
		return;

	SUPPLICANT_DBG("key %s", key);

	if (key == NULL) {
		if (bss->ieee8021x == TRUE)
			bss->security = G_SUPPLICANT_SECURITY_IEEE8021X;
		else if (bss->psk == TRUE)
			bss->security = G_SUPPLICANT_SECURITY_PSK;
		else if (bss->privacy == TRUE)
			bss->security = G_SUPPLICANT_SECURITY_WEP;
		else
			bss->security = G_SUPPLICANT_SECURITY_NONE;

		add_bss_to_network(bss);
		return;
	}

	if (g_strcmp0(key, "BSSID") == 0) {
		DBusMessageIter array;
		unsigned char *addr;
		int addr_len;

		dbus_message_iter_recurse(iter, &array);
		dbus_message_iter_get_fixed_array(&array, &addr, &addr_len);

		if (addr_len == 6)
			memcpy(bss->bssid, addr, addr_len);
	} else if (g_strcmp0(key, "SSID") == 0) {
		DBusMessageIter array;
		unsigned char *ssid;
		int ssid_len;

		dbus_message_iter_recurse(iter, &array);
		dbus_message_iter_get_fixed_array(&array, &ssid, &ssid_len);

		if (ssid_len > 0 && ssid_len < 33) {
			memcpy(bss->ssid, ssid, ssid_len);
			bss->ssid_len = ssid_len;
		} else {
			memset(bss->ssid, 0, sizeof(bss->ssid));
			bss->ssid_len = 0;
		}
	} else if (g_strcmp0(key, "Capabilities") == 0) {
		dbus_uint16_t capabilities = 0x0000;

		dbus_message_iter_get_basic(iter, &capabilities);

		if (capabilities & IEEE80211_CAP_ESS)
			bss->mode = G_SUPPLICANT_MODE_INFRA;
		else if (capabilities & IEEE80211_CAP_IBSS)
			bss->mode = G_SUPPLICANT_MODE_IBSS;

		if (capabilities & IEEE80211_CAP_PRIVACY)
			bss->privacy = TRUE;
	} else if (g_strcmp0(key, "Mode") == 0) {
		const char *mode = NULL;

		dbus_message_iter_get_basic(iter, &mode);
		bss->mode = string2mode(mode);
	} else if (g_strcmp0(key, "Frequency") == 0) {
		dbus_uint16_t frequency = 0;

		dbus_message_iter_get_basic(iter, &frequency);
		bss->frequency = frequency;
	} else if (g_strcmp0(key, "Signal") == 0) {
		dbus_int16_t signal = 0;

		dbus_message_iter_get_basic(iter, &signal);

		bss->signal = signal;
	} else if (g_strcmp0(key, "Level") == 0) {
		dbus_int32_t level = 0;

		dbus_message_iter_get_basic(iter, &level);
	} else if (g_strcmp0(key, "Rates") == 0) {
		supplicant_dbus_array_foreach(iter, bss_rates, bss);
	} else if (g_strcmp0(key, "MaxRate") == 0) {
		dbus_uint32_t maxrate = 0;

		dbus_message_iter_get_basic(iter, &maxrate);
		if (maxrate != 0)
			bss->maxrate = maxrate;
	} else if (g_strcmp0(key, "Privacy") == 0) {
		dbus_bool_t privacy = FALSE;

		dbus_message_iter_get_basic(iter, &privacy);
		bss->privacy = privacy;
	} else if ((g_strcmp0(key, "RSN") == 0) ||
			(g_strcmp0(key, "WPA") == 0)) {
		supplicant_dbus_property_foreach(iter, bss_wpa, bss);

		if (bss->keymgmt &
			(G_SUPPLICANT_KEYMGMT_WPA_EAP |
				G_SUPPLICANT_KEYMGMT_WPA_FT_EAP |
				G_SUPPLICANT_KEYMGMT_WPA_EAP_256))
			bss->ieee8021x = TRUE;

		if (bss->keymgmt &
			(G_SUPPLICANT_KEYMGMT_WPA_PSK |
				G_SUPPLICANT_KEYMGMT_WPA_FT_PSK |
				G_SUPPLICANT_KEYMGMT_WPA_PSK_256))
			bss->psk = TRUE;
	} else
		SUPPLICANT_DBG("key %s type %c",
				key, dbus_message_iter_get_arg_type(iter));
}

static void interface_bss_added(DBusMessageIter *iter, void *user_data)
{
	GSupplicantInterface *interface = user_data;
	GSupplicantNetwork *network;
	struct g_supplicant_bss *bss;
	const char *path = NULL;

	SUPPLICANT_DBG("");

	dbus_message_iter_get_basic(iter, &path);
	if (path == NULL)
		return;

	if (g_strcmp0(path, "/") == 0)
		return;

	SUPPLICANT_DBG("%s", path);

	network = g_hash_table_lookup(interface->bss_mapping, path);
	if (network != NULL) {
		bss = g_hash_table_lookup(network->bss_table, path);
		if (bss != NULL)
			return;
	}

	bss = g_try_new0(struct g_supplicant_bss, 1);
	if (bss == NULL)
		return;

	bss->interface = interface;
	bss->path = g_strdup(path);

	dbus_message_iter_next(iter);
	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_INVALID) {
		supplicant_dbus_property_foreach(iter, bss_property, bss);
		bss_property(NULL, NULL, bss);
		return;
	}

	supplicant_dbus_property_get_all(path,
					SUPPLICANT_INTERFACE ".Interface.BSS",
							bss_property, bss);
}

static void interface_bss_removed(DBusMessageIter *iter, void *user_data)
{
	GSupplicantInterface *interface = user_data;
	GSupplicantNetwork *network;
	const char *path = NULL;

	dbus_message_iter_get_basic(iter, &path);
	if (path == NULL)
		return;

	network = g_hash_table_lookup(interface->bss_mapping, path);
	if (network == NULL)
		return;

	g_hash_table_remove(bss_mapping, path);

	g_hash_table_remove(interface->bss_mapping, path);
	g_hash_table_remove(network->bss_table, path);

	if (g_hash_table_size(network->bss_table) == 0)
		g_hash_table_remove(interface->network_table, network->group);
}

static void interface_property(const char *key, DBusMessageIter *iter,
							void *user_data)
{
	GSupplicantInterface *interface = user_data;

	if (interface == NULL)
		return;

	SUPPLICANT_DBG("%s", key);

	if (key == NULL) {
		debug_strvalmap("KeyMgmt capability", keymgmt_map,
						interface->keymgmt_capa);
		debug_strvalmap("AuthAlg capability", authalg_capa_map,
						interface->authalg_capa);
		debug_strvalmap("Protocol capability", proto_capa_map,
						interface->proto_capa);
		debug_strvalmap("Pairwise capability", pairwise_map,
						interface->pairwise_capa);
		debug_strvalmap("Group capability", group_map,
						interface->group_capa);
		debug_strvalmap("Scan capability", scan_capa_map,
						interface->scan_capa);
		debug_strvalmap("Mode capability", mode_capa_map,
						interface->mode_capa);

		interface->ready = TRUE;
		callback_interface_added(interface);
		return;
	}

	if (g_strcmp0(key, "Capabilities") == 0) {
		supplicant_dbus_property_foreach(iter, interface_capability,
								interface);
	} else if (g_strcmp0(key, "State") == 0) {
		const char *str = NULL;

		dbus_message_iter_get_basic(iter, &str);
		if (str != NULL)
			if (string2state(str) != interface->state) {
				interface->state = string2state(str);
				callback_interface_state(interface);
			}

		SUPPLICANT_DBG("state %s (%d)", str, interface->state);
	} else if (g_strcmp0(key, "Scanning") == 0) {
		dbus_bool_t scanning = FALSE;

		dbus_message_iter_get_basic(iter, &scanning);
		interface->scanning = scanning;

		if (interface->ready == TRUE) {
			if (interface->scanning == TRUE)
				callback_scan_started(interface);
			else
				callback_scan_finished(interface);
		}
	} else if (g_strcmp0(key, "ApScan") == 0) {
		int apscan = 1;

		dbus_message_iter_get_basic(iter, &apscan);
		interface->apscan = apscan;
	} else if (g_strcmp0(key, "Ifname") == 0) {
		const char *str = NULL;

		dbus_message_iter_get_basic(iter, &str);
		if (str != NULL)
			interface->ifname = g_strdup(str);
	} else if (g_strcmp0(key, "Driver") == 0) {
		const char *str = NULL;

		dbus_message_iter_get_basic(iter, &str);
		if (str != NULL)
			interface->driver = g_strdup(str);
	} else if (g_strcmp0(key, "BridgeIfname") == 0) {
		const char *str = NULL;

		dbus_message_iter_get_basic(iter, &str);
		if (str != NULL)
			interface->bridge = g_strdup(str);
	} else if (g_strcmp0(key, "CurrentBSS") == 0) {
		interface_bss_added(iter, interface);
	} else if (g_strcmp0(key, "CurrentNetwork") == 0) {
		interface_network_added(iter, interface);
	} else if (g_strcmp0(key, "BSSs") == 0) {
		supplicant_dbus_array_foreach(iter, interface_bss_added,
								interface);
	} else if (g_strcmp0(key, "Blobs") == 0) {
		/* Nothing */
	} else if (g_strcmp0(key, "Networks") == 0) {
		supplicant_dbus_array_foreach(iter, interface_network_added,
								interface);
	} else
		SUPPLICANT_DBG("key %s type %c",
				key, dbus_message_iter_get_arg_type(iter));
}

static void scan_network_update(DBusMessageIter *iter, void *user_data)
{
	GSupplicantInterface *interface = user_data;
	GSupplicantNetwork *network;
	char *path;

	if (iter == NULL)
		return;

	dbus_message_iter_get_basic(iter, &path);

	if (path == NULL)
		return;

	if (g_strcmp0(path, "/") == 0)
		return;

	/* Update the network details based on scan BSS data */
	network = g_hash_table_lookup(interface->bss_mapping, path);
	if (network != NULL)
		callback_network_added(network);
}

static void scan_bss_data(const char *key, DBusMessageIter *iter,
				void *user_data)
{
	GSupplicantInterface *interface = user_data;

	if (iter)
		supplicant_dbus_array_foreach(iter, scan_network_update,
						interface);

	if (interface->scan_callback != NULL)
		interface->scan_callback(0, interface, interface->scan_data);

	interface->scan_callback = NULL;
	interface->scan_data = NULL;
}

static GSupplicantInterface *interface_alloc(const char *path)
{
	GSupplicantInterface *interface;

	interface = g_try_new0(GSupplicantInterface, 1);
	if (interface == NULL)
		return NULL;

	interface->path = g_strdup(path);

	interface->network_table = g_hash_table_new_full(g_str_hash,
					g_str_equal, NULL, remove_network);

	interface->net_mapping = g_hash_table_new_full(g_str_hash, g_str_equal,
								NULL, NULL);
	interface->bss_mapping = g_hash_table_new_full(g_str_hash, g_str_equal,
								NULL, NULL);

	g_hash_table_replace(interface_table, interface->path, interface);

	return interface;
}

static void interface_added(DBusMessageIter *iter, void *user_data)
{
	GSupplicantInterface *interface;
	const char *path = NULL;

	SUPPLICANT_DBG("");

	dbus_message_iter_get_basic(iter, &path);
	if (path == NULL)
		return;

	if (g_strcmp0(path, "/") == 0)
		return;

	interface = g_hash_table_lookup(interface_table, path);
	if (interface != NULL)
		return;

	interface = interface_alloc(path);
	if (interface == NULL)
		return;

	dbus_message_iter_next(iter);
	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_INVALID) {
		supplicant_dbus_property_foreach(iter, interface_property,
								interface);
		interface_property(NULL, NULL, interface);
		return;
	}

	supplicant_dbus_property_get_all(path,
					SUPPLICANT_INTERFACE ".Interface",
						interface_property, interface);
}

static void interface_removed(DBusMessageIter *iter, void *user_data)
{
	const char *path = NULL;

	dbus_message_iter_get_basic(iter, &path);
	if (path == NULL)
		return;

	g_hash_table_remove(interface_table, path);
}

static void eap_method(DBusMessageIter *iter, void *user_data)
{
	const char *str = NULL;
	int i;

	dbus_message_iter_get_basic(iter, &str);
	if (str == NULL)
		return;

	for (i = 0; eap_method_map[i].str != NULL; i++)
		if (strcmp(str, eap_method_map[i].str) == 0) {
			eap_methods |= eap_method_map[i].val;
			break;
		}
}

static void service_property(const char *key, DBusMessageIter *iter,
							void *user_data)
{
	if (key == NULL) {
		callback_system_ready();
		return;
	}

	if (g_strcmp0(key, "DebugLevel") == 0) {
		const char *str = NULL;
		int i;

		dbus_message_iter_get_basic(iter, &str);
		for (i = 0; debug_strings[i] != NULL; i++)
			if (g_strcmp0(debug_strings[i], str) == 0) {
				debug_level = i;
				break;
			}
		SUPPLICANT_DBG("Debug level %d", debug_level);
	} else if (g_strcmp0(key, "DebugTimestamp") == 0) {
		dbus_message_iter_get_basic(iter, &debug_timestamp);
		SUPPLICANT_DBG("Debug timestamp %u", debug_timestamp);
	} else if (g_strcmp0(key, "DebugShowKeys") == 0) {
		dbus_message_iter_get_basic(iter, &debug_showkeys);
		SUPPLICANT_DBG("Debug show keys %u", debug_showkeys);
	} else if (g_strcmp0(key, "Interfaces") == 0) {
		supplicant_dbus_array_foreach(iter, interface_added, NULL);
	} else if (g_strcmp0(key, "EapMethods") == 0) {
		supplicant_dbus_array_foreach(iter, eap_method, NULL);
		debug_strvalmap("EAP method", eap_method_map, eap_methods);
	} else
		SUPPLICANT_DBG("key %s type %c",
				key, dbus_message_iter_get_arg_type(iter));
}

static void signal_name_owner_changed(const char *path, DBusMessageIter *iter)
{
	const char *name = NULL, *old = NULL, *new = NULL;

	SUPPLICANT_DBG("");

	if (g_strcmp0(path, DBUS_PATH_DBUS) != 0)
		return;

	dbus_message_iter_get_basic(iter, &name);
	if (name == NULL)
		return;

	if (g_strcmp0(name, SUPPLICANT_SERVICE) != 0)
		return;

	dbus_message_iter_next(iter);
	dbus_message_iter_get_basic(iter, &old);
	dbus_message_iter_next(iter);
	dbus_message_iter_get_basic(iter, &new);

	if (old == NULL || new == NULL)
		return;

	if (strlen(old) > 0 && strlen(new) == 0) {
		system_available = FALSE;
		g_hash_table_remove_all(bss_mapping);
		g_hash_table_remove_all(interface_table);
		callback_system_killed();
	}

	if (strlen(new) > 0 && strlen(old) == 0) {
		system_available = TRUE;
		supplicant_dbus_property_get_all(SUPPLICANT_PATH,
							SUPPLICANT_INTERFACE,
							service_property, NULL);
	}
}

static void signal_properties_changed(const char *path, DBusMessageIter *iter)
{
	SUPPLICANT_DBG("");

	if (g_strcmp0(path, SUPPLICANT_PATH) != 0)
		return;

	supplicant_dbus_property_foreach(iter, service_property, NULL);
}

static void signal_interface_added(const char *path, DBusMessageIter *iter)
{
	SUPPLICANT_DBG("path %s %s", path, SUPPLICANT_PATH);

	if (g_strcmp0(path, SUPPLICANT_PATH) == 0)
		interface_added(iter, NULL);
}

static void signal_interface_removed(const char *path, DBusMessageIter *iter)
{
	SUPPLICANT_DBG("");

	if (g_strcmp0(path, SUPPLICANT_PATH) == 0)
		interface_removed(iter, NULL);
}

static void signal_interface_changed(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;

	SUPPLICANT_DBG("");

	interface = g_hash_table_lookup(interface_table, path);
	if (interface == NULL)
		return;

	supplicant_dbus_property_foreach(iter, interface_property, interface);
}

static void signal_scan_done(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;
	dbus_bool_t success = FALSE;

	SUPPLICANT_DBG("");

	interface = g_hash_table_lookup(interface_table, path);
	if (interface == NULL)
		return;

	dbus_message_iter_get_basic(iter, &success);

	/*
	 * If scan is unsuccessful return -EIO else get the scanned BSSs
	 * and update the network details accordingly
	 */
	if (success == FALSE) {
		if (interface->scan_callback != NULL)
			interface->scan_callback(-EIO, interface,
						interface->scan_data);

		interface->scan_callback = NULL;
		interface->scan_data = NULL;

		return;
	}

	supplicant_dbus_property_get(path, SUPPLICANT_INTERFACE ".Interface",
					"BSSs", scan_bss_data, interface);
}

static void signal_bss_added(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;

	SUPPLICANT_DBG("");

	interface = g_hash_table_lookup(interface_table, path);
	if (interface == NULL)
		return;

	interface_bss_added(iter, interface);
}

static void signal_bss_removed(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;

	SUPPLICANT_DBG("");

	interface = g_hash_table_lookup(interface_table, path);
	if (interface == NULL)
		return;

	interface_bss_removed(iter, interface);
}

static void signal_network_added(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;

	SUPPLICANT_DBG("");

	interface = g_hash_table_lookup(interface_table, path);
	if (interface == NULL)
		return;

	interface_network_added(iter, interface);
}

static void signal_network_removed(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;

	SUPPLICANT_DBG("");

	interface = g_hash_table_lookup(interface_table, path);
	if (interface == NULL)
		return;

	interface_network_removed(iter, interface);
}

static void signal_bss_changed(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;
	GSupplicantNetwork *network;
	struct g_supplicant_bss *bss;

	SUPPLICANT_DBG("");

	interface = g_hash_table_lookup(bss_mapping, path);
	if (interface == NULL)
		return;

	network = g_hash_table_lookup(interface->bss_mapping, path);
	if (network == NULL)
		return;

	bss = g_hash_table_lookup(network->bss_table, path);
	if (bss == NULL)
		return;

	supplicant_dbus_property_foreach(iter, bss_property, bss);
}

static struct {
	const char *interface;
	const char *member;
	void (*function) (const char *path, DBusMessageIter *iter);
} signal_map[] = {
	{ DBUS_INTERFACE_DBUS,  "NameOwnerChanged",  signal_name_owner_changed },

	{ SUPPLICANT_INTERFACE, "PropertiesChanged", signal_properties_changed },
	{ SUPPLICANT_INTERFACE, "InterfaceAdded",    signal_interface_added    },
	{ SUPPLICANT_INTERFACE, "InterfaceCreated",  signal_interface_added    },
	{ SUPPLICANT_INTERFACE, "InterfaceRemoved",  signal_interface_removed  },

	{ SUPPLICANT_INTERFACE ".Interface", "PropertiesChanged", signal_interface_changed },
	{ SUPPLICANT_INTERFACE ".Interface", "ScanDone",          signal_scan_done         },
	{ SUPPLICANT_INTERFACE ".Interface", "BSSAdded",          signal_bss_added         },
	{ SUPPLICANT_INTERFACE ".Interface", "BSSRemoved",        signal_bss_removed       },
	{ SUPPLICANT_INTERFACE ".Interface", "NetworkAdded",      signal_network_added     },
	{ SUPPLICANT_INTERFACE ".Interface", "NetworkRemoved",    signal_network_removed   },

	{ SUPPLICANT_INTERFACE ".Interface.BSS", "PropertiesChanged", signal_bss_changed   },

	{ }
};

static DBusHandlerResult g_supplicant_filter(DBusConnection *conn,
					DBusMessage *message, void *data)
{
	DBusMessageIter iter;
	const char *path;
	int i;

	path = dbus_message_get_path(message);
	if (path == NULL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (dbus_message_iter_init(message, &iter) == FALSE)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	for (i = 0; signal_map[i].interface != NULL; i++) {
		if (dbus_message_has_interface(message,
					signal_map[i].interface) == FALSE)
			continue;

		if (dbus_message_has_member(message,
					signal_map[i].member) == FALSE)
			continue;

		signal_map[i].function(path, &iter);
		break;
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

struct interface_data {
	GSupplicantInterface *interface;
	GSupplicantInterfaceCallback callback;
	void *user_data;
};

struct interface_create_data {
	const char *ifname;
	const char *driver;
	GSupplicantInterface *interface;
	GSupplicantInterfaceCallback callback;
	void *user_data;
};

struct interface_connect_data {
	GSupplicantInterface *interface;
	GSupplicantInterfaceCallback callback;
	GSupplicantSSID *ssid;
	void *user_data;
};

static void interface_create_property(const char *key, DBusMessageIter *iter,
							void *user_data)
{
	struct interface_create_data *data = user_data;
	GSupplicantInterface *interface = data->interface;

	if (key == NULL) {
		if (data->callback != NULL)
			data->callback(0, data->interface, data->user_data);

		dbus_free(data);
	}

	interface_property(key, iter, interface);
}

static void interface_create_result(const char *error,
				DBusMessageIter *iter, void *user_data)
{
	struct interface_create_data *data = user_data;
	const char *path = NULL;
	int err;

	SUPPLICANT_DBG("");

	if (error != NULL) {
		g_critical("error %s", error);
		err = -EIO;
		goto done;
	}

	dbus_message_iter_get_basic(iter, &path);
	if (path == NULL) {
		err = -EINVAL;
		goto done;
	}

	if (system_available == FALSE) {
		err = -EFAULT;
		goto done;
	}

	data->interface = g_hash_table_lookup(interface_table, path);
	if (data->interface == NULL) {
		data->interface = interface_alloc(path);
		if (data->interface == NULL) {
			err = -ENOMEM;
			goto done;
		}
	}

	err = supplicant_dbus_property_get_all(path,
					SUPPLICANT_INTERFACE ".Interface",
					interface_create_property, data);
	if (err == 0)
		return;

done:
	if (data->callback != NULL)
		data->callback(err, NULL, data->user_data);

	dbus_free(data);
}

static void interface_create_params(DBusMessageIter *iter, void *user_data)
{
	struct interface_create_data *data = user_data;
	DBusMessageIter dict;

	SUPPLICANT_DBG("");

	supplicant_dbus_dict_open(iter, &dict);

	supplicant_dbus_dict_append_basic(&dict, "Ifname",
					DBUS_TYPE_STRING, &data->ifname);

	if (data->driver != NULL)
		supplicant_dbus_dict_append_basic(&dict, "Driver",
					DBUS_TYPE_STRING, &data->driver);

	supplicant_dbus_dict_close(iter, &dict);
}

static void interface_get_result(const char *error,
				DBusMessageIter *iter, void *user_data)
{
	struct interface_create_data *data = user_data;
	GSupplicantInterface *interface;
	const char *path = NULL;
	int err;

	SUPPLICANT_DBG("");

	if (error != NULL) {
		g_warning("error %s", error);
		err = -EIO;
		goto create;
	}

	dbus_message_iter_get_basic(iter, &path);
	if (path == NULL) {
		err = -EINVAL;
		goto done;
	}

	interface = g_hash_table_lookup(interface_table, path);
	if (interface == NULL) {
		err = -ENOENT;
		goto done;
	}

	if (data->callback != NULL)
		data->callback(0, interface, data->user_data);

	dbus_free(data);

	return;

create:
	if (system_available == FALSE) {
		err = -EFAULT;
		goto done;
	}

	SUPPLICANT_DBG("Creating interface");

	err = supplicant_dbus_method_call(SUPPLICANT_PATH,
						SUPPLICANT_INTERFACE,
						"CreateInterface",
						interface_create_params,
						interface_create_result, data);
	if (err == 0)
		return;

done:
	if (data->callback != NULL)
		data->callback(err, NULL, data->user_data);

	dbus_free(data);
}

static void interface_get_params(DBusMessageIter *iter, void *user_data)
{
	struct interface_create_data *data = user_data;

	SUPPLICANT_DBG("");

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &data->ifname);
}

int g_supplicant_interface_create(const char *ifname, const char *driver,
					GSupplicantInterfaceCallback callback,
							void *user_data)
{
	struct interface_create_data *data;

	SUPPLICANT_DBG("ifname %s", ifname);

	if (ifname == NULL)
		return -EINVAL;

	if (system_available == FALSE)
		return -EFAULT;

	data = dbus_malloc0(sizeof(*data));
	if (data == NULL)
		return -ENOMEM;

	data->ifname = ifname;
	data->driver = driver;
	data->callback = callback;
	data->user_data = user_data;

	return supplicant_dbus_method_call(SUPPLICANT_PATH,
						SUPPLICANT_INTERFACE,
						"GetInterface",
						interface_get_params,
						interface_get_result, data);
}

static void interface_remove_result(const char *error,
				DBusMessageIter *iter, void *user_data)
{
	struct interface_data *data = user_data;
	int err;

	if (error != NULL) {
		err = -EIO;
		goto done;
	}

	if (system_available == FALSE) {
		err = -EFAULT;
		goto done;
	}

	g_hash_table_remove(interface_table, data->interface->path);
	err = 0;

done:
	if (data->callback != NULL)
		data->callback(err, data->interface, data->user_data);

	dbus_free(data);
}


static void interface_remove_params(DBusMessageIter *iter, void *user_data)
{
	struct interface_data *data = user_data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH,
							&data->interface->path);
}


int g_supplicant_interface_remove(GSupplicantInterface *interface,
			GSupplicantInterfaceCallback callback,
							void *user_data)
{
	struct interface_data *data;

	if (interface == NULL)
		return -EINVAL;

	if (system_available == FALSE)
		return -EFAULT;

	data = dbus_malloc0(sizeof(*data));
	if (data == NULL)
		return -ENOMEM;

	data->interface = interface;
	data->callback = callback;
	data->user_data = user_data;

	return supplicant_dbus_method_call(SUPPLICANT_PATH,
						SUPPLICANT_INTERFACE,
						"RemoveInterface",
						interface_remove_params,
						interface_remove_result, data);
}

static void interface_scan_result(const char *error,
				DBusMessageIter *iter, void *user_data)
{
	struct interface_data *data = user_data;

	if (error != NULL) {
		if (data->callback != NULL)
			data->callback(-EIO, data->interface, data->user_data);
	} else {
		data->interface->scan_callback = data->callback;
		data->interface->scan_data = data->user_data;
	}

	dbus_free(data);
}

static void interface_scan_params(DBusMessageIter *iter, void *user_data)
{
	DBusMessageIter dict;
	const char *type = "passive";

	supplicant_dbus_dict_open(iter, &dict);

	supplicant_dbus_dict_append_basic(&dict, "Type",
						DBUS_TYPE_STRING, &type);

	supplicant_dbus_dict_close(iter, &dict);
}

int g_supplicant_interface_scan(GSupplicantInterface *interface,
				GSupplicantInterfaceCallback callback,
							void *user_data)
{
	struct interface_data *data;

	if (interface == NULL)
		return -EINVAL;

	if (system_available == FALSE)
		return -EFAULT;

	if (interface->scanning == TRUE)
		return -EALREADY;

	data = dbus_malloc0(sizeof(*data));
	if (data == NULL)
		return -ENOMEM;

	data->interface = interface;
	data->callback = callback;
	data->user_data = user_data;

	return supplicant_dbus_method_call(interface->path,
			SUPPLICANT_INTERFACE ".Interface", "Scan",
			interface_scan_params, interface_scan_result, data);
}

static void interface_select_network_result(const char *error,
				DBusMessageIter *iter, void *user_data)
{
	SUPPLICANT_DBG("");
}

static void interface_select_network_params(DBusMessageIter *iter,
							void *user_data)
{
	char *path = user_data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &path);
}

static void interface_add_network_result(const char *error,
				DBusMessageIter *iter, void *user_data)
{
	struct interface_connect_data *data = user_data;
	char *path = NULL;

	if (error != NULL)
		goto done;

	dbus_message_iter_get_basic(iter, &path);
	if (path == NULL)
		goto done;

	SUPPLICANT_DBG("PATH: %s", path);

	supplicant_dbus_method_call(data->interface->path,
			SUPPLICANT_INTERFACE ".Interface", "SelectNetwork",
			interface_select_network_params,
			interface_select_network_result, path);

done:
	dbus_free(data);
}

static void add_network_security_wep(DBusMessageIter *dict,
					GSupplicantSSID *ssid)
{
	const char *auth_alg = "OPEN SHARED";
	const char *key_index = "0";

	supplicant_dbus_dict_append_basic(dict, "auth_alg",
					DBUS_TYPE_STRING, &auth_alg);

	if (ssid->passphrase) {
		int size = strlen(ssid->passphrase);
		if (size == 10 || size == 26) {
			unsigned char *key = g_try_malloc(13);
			char tmp[3];
			int i;

			memset(tmp, 0, sizeof(tmp));
			if (key == NULL)
				size = 0;

			for (i = 0; i < size / 2; i++) {
				memcpy(tmp, ssid->passphrase + (i * 2), 2);
				key[i] = (unsigned char) strtol(tmp, NULL, 16);
			}

			supplicant_dbus_dict_append_fixed_array(dict,
							"wep_key0",
							DBUS_TYPE_BYTE,
							&key, size / 2);
			g_free(key);
		} else if (size == 5 || size == 13) {
			unsigned char *key = g_try_malloc(13);
			int i;

			if (key == NULL)
				size = 0;

			for (i = 0; i < size; i++)
				key[i] = (unsigned char) ssid->passphrase[i];

			supplicant_dbus_dict_append_fixed_array(dict,
								"wep_key0",
								DBUS_TYPE_BYTE,
								&key, size);
			g_free(key);
		} else
			supplicant_dbus_dict_append_basic(dict,
							"wep_key0",
							DBUS_TYPE_STRING,
							&ssid->passphrase);

		supplicant_dbus_dict_append_basic(dict, "wep_tx_keyidx",
					DBUS_TYPE_STRING, &key_index);
	}
}

static void add_network_security_psk(DBusMessageIter *dict,
					GSupplicantSSID *ssid)
{
	if (ssid->passphrase && strlen(ssid->passphrase) > 0)
			supplicant_dbus_dict_append_basic(dict, "psk",
						DBUS_TYPE_STRING,
							&ssid->passphrase);
}

static void add_network_security_tls(DBusMessageIter *dict,
					GSupplicantSSID *ssid)
{
	/*
	 * For TLS, we at least need:
	 *              The client certificate
	 *              The client private key file
	 *              The client private key file password
	 *
	 * The Authority certificate is optional.
	 */
	if (ssid->client_cert_path == NULL)
		return;

	if (ssid->private_key_path == NULL)
		return;

	if (ssid->private_key_passphrase == NULL)
		return;

	if (ssid->ca_cert_path)
		supplicant_dbus_dict_append_basic(dict, "ca_cert",
					DBUS_TYPE_STRING, &ssid->ca_cert_path);

	supplicant_dbus_dict_append_basic(dict, "private_key",
						DBUS_TYPE_STRING,
						&ssid->private_key_path);
	supplicant_dbus_dict_append_basic(dict, "private_key_passwd",
						DBUS_TYPE_STRING,
						&ssid->private_key_passphrase);
	supplicant_dbus_dict_append_basic(dict, "client_cert",
						DBUS_TYPE_STRING,
						&ssid->client_cert_path);
}

static void add_network_security_peap(DBusMessageIter *dict,
					GSupplicantSSID *ssid)
{
	char *phase2_auth;

	/*
	 * For PEAP/TTLS, we at least need
	 *              The authority certificate
	 *              The 2nd phase authentication method
	 *              The 2nd phase passphrase
	 *
	 * The Client certificate is optional although strongly required
	 * When setting it, we need in addition
	 *              The Client private key file
	 *              The Client private key file password
	 */
	if (ssid->passphrase == NULL)
		return;

	if (ssid->ca_cert_path == NULL)
		return;

	if (ssid->phase2_auth == NULL)
		return;

	if (ssid->client_cert_path) {
		if (ssid->private_key_path == NULL)
			return;

		if (ssid->private_key_passphrase == NULL)
			return;

		supplicant_dbus_dict_append_basic(dict, "client_cert",
						DBUS_TYPE_STRING,
						&ssid->client_cert_path);

		supplicant_dbus_dict_append_basic(dict, "private_key",
						DBUS_TYPE_STRING,
						&ssid->private_key_path);

		supplicant_dbus_dict_append_basic(dict, "private_key_passwd",
						DBUS_TYPE_STRING,
						&ssid->private_key_passphrase);

	}

	phase2_auth = g_strdup_printf("\"auth=%s\"", ssid->phase2_auth);

	supplicant_dbus_dict_append_basic(dict, "password",
						DBUS_TYPE_STRING,
						&ssid->passphrase);

	supplicant_dbus_dict_append_basic(dict, "ca_cert",
						DBUS_TYPE_STRING,
						&ssid->ca_cert_path);

	supplicant_dbus_dict_append_basic(dict, "phase2",
						DBUS_TYPE_STRING,
						&ssid->phase2_auth);

	g_free(phase2_auth);
}

static void add_network_security_eap(DBusMessageIter *dict,
					GSupplicantSSID *ssid)
{
	char *eap_value;

	if (ssid->eap == NULL || ssid->identity == NULL)
		return;

	if (g_strcmp0(ssid->eap, "tls") == 0) {
		add_network_security_tls(dict, ssid);
	} else if (g_strcmp0(ssid->eap, "peap") == 0 ||
				g_strcmp0(ssid->eap, "ttls") == 0) {
		add_network_security_peap(dict, ssid);
	} else
		return;

	eap_value = g_ascii_strup(ssid->eap, -1);

	supplicant_dbus_dict_append_basic(dict, "eap",
						DBUS_TYPE_STRING,
						&eap_value);
	supplicant_dbus_dict_append_basic(dict, "identity",
						DBUS_TYPE_STRING,
						&ssid->identity);

	g_free(eap_value);
}

static void add_network_security(DBusMessageIter *dict, GSupplicantSSID *ssid)
{
	char *key_mgmt;

	switch (ssid->security) {
	case G_SUPPLICANT_SECURITY_UNKNOWN:
	case G_SUPPLICANT_SECURITY_NONE:
	case G_SUPPLICANT_SECURITY_WEP:
		key_mgmt = "NONE";
		add_network_security_wep(dict, ssid);
		break;
	case G_SUPPLICANT_SECURITY_PSK:
		key_mgmt = "WPA-PSK";
		add_network_security_psk(dict, ssid);
		break;
	case G_SUPPLICANT_SECURITY_IEEE8021X:
		key_mgmt = "WPA-EAP";
		add_network_security_eap(dict, ssid);
		break;
	}

	supplicant_dbus_dict_append_basic(dict, "key_mgmt",
				DBUS_TYPE_STRING, &key_mgmt);
}

static void interface_add_network_params(DBusMessageIter *iter, void *user_data)
{
	DBusMessageIter dict;
	dbus_uint32_t scan_ssid = 1;
	struct interface_connect_data *data = user_data;
	GSupplicantSSID *ssid = data->ssid;

	supplicant_dbus_dict_open(iter, &dict);

	supplicant_dbus_dict_append_basic(&dict, "scan_ssid",
					 DBUS_TYPE_UINT32, &scan_ssid);

	add_network_security(&dict, ssid);

	supplicant_dbus_dict_append_fixed_array(&dict, "ssid",
					DBUS_TYPE_BYTE, &ssid->ssid,
						ssid->ssid_len);

	supplicant_dbus_dict_close(iter, &dict);
}

int g_supplicant_interface_connect(GSupplicantInterface *interface,
				GSupplicantSSID *ssid,
				GSupplicantInterfaceCallback callback,
							void *user_data)
{
	struct interface_connect_data *data;
	int ret;

	if (interface == NULL)
		return -EINVAL;

	if (system_available == FALSE)
		return -EFAULT;

	/* TODO: Check if we're already connected and switch */

	data = dbus_malloc0(sizeof(*data));
	if (data == NULL)
		return -ENOMEM;

	data->interface = interface;
	data->callback = callback;
	data->ssid = ssid;
	data->user_data = user_data;

	ret = supplicant_dbus_method_call(interface->path,
			SUPPLICANT_INTERFACE ".Interface", "AddNetwork",
			interface_add_network_params,
			interface_add_network_result, data);
	if (ret < 0)
		return ret;

	return -EINPROGRESS;
}

static void interface_disconnect_result(const char *error,
				DBusMessageIter *iter, void *user_data)
{
	struct interface_data *data = user_data;
	int result = 0;

	SUPPLICANT_DBG("");

	if (error != NULL)
		result = -EIO;

	if (data->callback != NULL)
		data->callback(result, data->interface, data->user_data);

	dbus_free(data);
}

int g_supplicant_interface_disconnect(GSupplicantInterface *interface,
					GSupplicantInterfaceCallback callback,
							void *user_data)
{
	struct interface_data *data;

	SUPPLICANT_DBG("");

	if (interface == NULL)
		return -EINVAL;

	if (system_available == FALSE)
		return -EFAULT;

	data = dbus_malloc0(sizeof(*data));
	if (data == NULL)
		return -ENOMEM;

	data->interface = interface;
	data->callback = callback;
	data->user_data = user_data;

	return supplicant_dbus_method_call(interface->path,
			SUPPLICANT_INTERFACE ".Interface", "Disconnect",
				NULL, interface_disconnect_result, data);
}


static const char *g_supplicant_rule0 = "type=signal,"
					"path=" DBUS_PATH_DBUS ","
					"sender=" DBUS_SERVICE_DBUS ","
					"interface=" DBUS_INTERFACE_DBUS ","
					"member=NameOwnerChanged,"
					"arg0=" SUPPLICANT_SERVICE;
static const char *g_supplicant_rule1 = "type=signal,"
			"interface=" SUPPLICANT_INTERFACE;
static const char *g_supplicant_rule2 = "type=signal,"
			"interface=" SUPPLICANT_INTERFACE ".Interface";
static const char *g_supplicant_rule3 = "type=signal,"
			"interface=" SUPPLICANT_INTERFACE ".Interface.WPS";
static const char *g_supplicant_rule4 = "type=signal,"
			"interface=" SUPPLICANT_INTERFACE ".Interface.BSS";
static const char *g_supplicant_rule5 = "type=signal,"
			"interface=" SUPPLICANT_INTERFACE ".Interface.Network";
static const char *g_supplicant_rule6 = "type=signal,"
			"interface=" SUPPLICANT_INTERFACE ".Interface.Blob";

static void invoke_introspect_method(void)
{
	DBusMessage *message;

	message = dbus_message_new_method_call(SUPPLICANT_SERVICE,
					SUPPLICANT_PATH,
					DBUS_INTERFACE_INTROSPECTABLE,
					"Introspect");

	if (message == NULL)
		return;

	dbus_message_set_no_reply(message, TRUE);
	dbus_connection_send(connection, message, NULL);
	dbus_message_unref(message);
}

int g_supplicant_register(const GSupplicantCallbacks *callbacks)
{
	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (connection == NULL)
		return -EIO;

	if (dbus_connection_add_filter(connection,
				g_supplicant_filter, NULL, NULL) == FALSE) {
		dbus_connection_unref(connection);
		connection = NULL;
		return -EIO;
	}

	callbacks_pointer = callbacks;
	eap_methods = 0;

	interface_table = g_hash_table_new_full(g_str_hash, g_str_equal,
						NULL, remove_interface);

	bss_mapping = g_hash_table_new_full(g_str_hash, g_str_equal,
								NULL, NULL);

	supplicant_dbus_setup(connection);

	dbus_bus_add_match(connection, g_supplicant_rule0, NULL);
	dbus_bus_add_match(connection, g_supplicant_rule1, NULL);
	dbus_bus_add_match(connection, g_supplicant_rule2, NULL);
	dbus_bus_add_match(connection, g_supplicant_rule3, NULL);
	dbus_bus_add_match(connection, g_supplicant_rule4, NULL);
	dbus_bus_add_match(connection, g_supplicant_rule5, NULL);
	dbus_bus_add_match(connection, g_supplicant_rule6, NULL);
	dbus_connection_flush(connection);

	if (dbus_bus_name_has_owner(connection,
					SUPPLICANT_SERVICE, NULL) == TRUE) {
		system_available = TRUE;
		supplicant_dbus_property_get_all(SUPPLICANT_PATH,
						SUPPLICANT_INTERFACE,
						service_property, NULL);
	} else
		invoke_introspect_method();

	return 0;
}

static void unregister_interface_remove_params(DBusMessageIter *iter,
						void *user_data)
{
	const char *path = user_data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH,
							&path);
}


static void unregister_remove_interface(gpointer key, gpointer value,
						gpointer user_data)
{
	GSupplicantInterface *interface = value;

	supplicant_dbus_method_call(SUPPLICANT_PATH,
					SUPPLICANT_INTERFACE,
					"RemoveInterface",
					unregister_interface_remove_params,
						NULL, interface->path);
}

void g_supplicant_unregister(const GSupplicantCallbacks *callbacks)
{
	SUPPLICANT_DBG("");

	if (connection != NULL) {
		dbus_bus_remove_match(connection, g_supplicant_rule6, NULL);
		dbus_bus_remove_match(connection, g_supplicant_rule5, NULL);
		dbus_bus_remove_match(connection, g_supplicant_rule4, NULL);
		dbus_bus_remove_match(connection, g_supplicant_rule3, NULL);
		dbus_bus_remove_match(connection, g_supplicant_rule2, NULL);
		dbus_bus_remove_match(connection, g_supplicant_rule1, NULL);
		dbus_bus_remove_match(connection, g_supplicant_rule0, NULL);
		dbus_connection_flush(connection);

		dbus_connection_remove_filter(connection,
						g_supplicant_filter, NULL);
	}

	if (bss_mapping != NULL) {
		g_hash_table_destroy(bss_mapping);
		bss_mapping = NULL;
	}

	if (interface_table != NULL) {
		g_hash_table_foreach(interface_table,	
					unregister_remove_interface, NULL);
		g_hash_table_destroy(interface_table);
		interface_table = NULL;
	}

	if (system_available == TRUE)
		callback_system_killed();

	if (connection != NULL) {
		dbus_connection_unref(connection);
		connection = NULL;
	}

	callbacks_pointer = NULL;
	eap_methods = 0;
}
