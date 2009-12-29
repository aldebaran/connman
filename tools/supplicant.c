/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2009  Intel Corporation. All rights reserved.
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
#include <string.h>
#include <syslog.h>

#include <glib.h>
#include <gdbus.h>

#include "supplicant-dbus.h"
#include "supplicant.h"

#define DBG(fmt, arg...) do { \
	syslog(LOG_DEBUG, "%s() " fmt, __FUNCTION__ , ## arg); \
} while (0)

#define TIMEOUT 5000

static DBusConnection *connection;

static const struct supplicant_callbacks *callbacks_pointer;

static unsigned int eap_methods;

static struct {
	const char *str;
	unsigned int val;
} eap_method_map[] = {
	{ "MD5",	SUPPLICANT_EAP_METHOD_MD5	},
	{ "TLS",	SUPPLICANT_EAP_METHOD_TLS	},
	{ "MSCHAPV2",	SUPPLICANT_EAP_METHOD_MSCHAPV2	},
	{ "PEAP",	SUPPLICANT_EAP_METHOD_PEAP	},
	{ "TTLS",	SUPPLICANT_EAP_METHOD_TTLS	},
	{ "GTC",	SUPPLICANT_EAP_METHOD_GTC	},
	{ "OTP",	SUPPLICANT_EAP_METHOD_OTP	},
	{ "LEAP",	SUPPLICANT_EAP_METHOD_LEAP	},
	{ }
};

static struct {
	const char *str;
	unsigned int val;
} scan_capa_map[] = {
	{ "active",	SUPPLICANT_CAPABILITY_SCAN_ACTIVE	},
	{ "passive",	SUPPLICANT_CAPABILITY_SCAN_PASSIVE	},
	{ "ssid",	SUPPLICANT_CAPABILITY_SCAN_SSID		},
	{ }
};

static GHashTable *interface_table;

struct supplicant_interface {
	char *path;
	unsigned int scan_capa;
	enum supplicant_state state;
	dbus_bool_t scanning;
	int apscan;
	char *ifname;
	char *driver;
	char *bridge;
	GHashTable *network_table;
	GHashTable *bss_mapping;
};

struct supplicant_network {
	struct supplicant_interface *interface;
	char *group;
	char *name;
	enum supplicant_network_mode mode;
	GHashTable *bss_table;
};

struct supplicant_bss {
	struct supplicant_interface *interface;
	char *path;
	unsigned char bssid[6];
	unsigned char ssid[32];
	unsigned int ssid_len;
	unsigned int frequency;
};

static enum supplicant_state string2state(const char *state)
{
	if (state == NULL)
		return SUPPLICANT_STATE_UNKNOWN;

	if (g_str_equal(state, "unknown") == TRUE)
		return SUPPLICANT_STATE_UNKNOWN;
	else if (g_str_equal(state, "disconnected") == TRUE)
		return SUPPLICANT_STATE_DISCONNECTED;
	else if (g_str_equal(state, "inactive") == TRUE)
		return SUPPLICANT_STATE_INACTIVE;
	else if (g_str_equal(state, "scanning") == TRUE)
		return SUPPLICANT_STATE_SCANNING;
	else if (g_str_equal(state, "authenticating") == TRUE)
		return SUPPLICANT_STATE_AUTHENTICATING;
	else if (g_str_equal(state, "associating") == TRUE)
		return SUPPLICANT_STATE_ASSOCIATING;
	else if (g_str_equal(state, "associated") == TRUE)
		return SUPPLICANT_STATE_ASSOCIATED;
	else if (g_str_equal(state, "group_handshake") == TRUE)
		return SUPPLICANT_STATE_GROUP_HANDSHAKE;
	else if (g_str_equal(state, "4way_handshake") == TRUE)
		return SUPPLICANT_STATE_4WAY_HANDSHAKE;
	else if (g_str_equal(state, "completed") == TRUE)
		return SUPPLICANT_STATE_COMPLETED;

	return SUPPLICANT_STATE_UNKNOWN;
}

static void callback_interface_added(struct supplicant_interface *interface)
{
	if (callbacks_pointer == NULL)
		return;

	if (callbacks_pointer->interface_added == NULL)
		return;

	callbacks_pointer->interface_added(interface);
}

static void callback_interface_removed(struct supplicant_interface *interface)
{
	if (callbacks_pointer == NULL)
		return;

	if (callbacks_pointer->interface_removed == NULL)
		return;

	callbacks_pointer->interface_removed(interface);
}

static void callback_network_added(struct supplicant_network *network)
{
	if (callbacks_pointer == NULL)
		return;

	if (callbacks_pointer->network_added == NULL)
		return;

	callbacks_pointer->network_added(network);
}

static void callback_network_removed(struct supplicant_network *network)
{
	if (callbacks_pointer == NULL)
		return;

	if (callbacks_pointer->network_removed == NULL)
		return;

	callbacks_pointer->network_removed(network);
}

static void remove_interface(gpointer data)
{
	struct supplicant_interface *interface = data;

	callback_interface_removed(interface);

	g_hash_table_destroy(interface->bss_mapping);
	g_hash_table_destroy(interface->network_table);

	g_free(interface->path);
	g_free(interface->ifname);
	g_free(interface->driver);
	g_free(interface->bridge);
	g_free(interface);
}

static void remove_network(gpointer data)
{
	struct supplicant_network *network = data;

	callback_network_removed(network);

	g_free(network->group);
	g_free(network->name);
	g_free(network);
}

static void remove_bss(gpointer data)
{
	struct supplicant_bss *bss = data;

	g_free(bss->path);
	g_free(bss);
}

static void debug_eap_methods(void)
{
	int i;

	for (i = 0; eap_method_map[i].str != NULL; i++) {
		if (eap_methods & eap_method_map[i].val)
			DBG("EAP Method: %s", eap_method_map[i].str);
	}
}

static void debug_scan_capabilities(struct supplicant_interface *interface)
{
	int i;

	for (i = 0; scan_capa_map[i].str != NULL; i++) {
		if (interface->scan_capa & scan_capa_map[i].val)
			DBG("Scan Capability: %s", scan_capa_map[i].str);
	}
}

static void interface_capability_scan(DBusMessageIter *iter, void *user_data)
{
	struct supplicant_interface *interface = user_data;
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

static void interface_capability(const char *key, DBusMessageIter *iter,
							void *user_data)
{
	struct supplicant_interface *interface = user_data;

	if (key == NULL)
		return;

	if (g_strcmp0(key, "Scan") == 0)
		supplicant_dbus_array_foreach(iter, interface_capability_scan,
								interface);
	else
		DBG("key %s type %c",
				key, dbus_message_iter_get_arg_type(iter));
}

const char *supplicant_interface_get_ifname(struct supplicant_interface *interface)
{
	if (interface == NULL)
		return NULL;

	return interface->ifname;
}

struct supplicant_interface *supplicant_network_get_interface(struct supplicant_network *network)
{
	if (network == NULL)
		return NULL;

	return network->interface;
}

const char *supplicant_network_get_name(struct supplicant_network *network)
{
	if (network == NULL || network->name == NULL)
		return "";

	return network->name;
}

enum supplicant_network_mode supplicant_network_get_mode(struct supplicant_network *network)
{
	if (network == NULL)
		return SUPPLICANT_NETWORK_MODE_UNKNOWN;

	return network->mode;
}

static void network_property(const char *key, DBusMessageIter *iter,
							void *user_data)
{
	if (key == NULL)
		return;

	DBG("key %s type %c", key, dbus_message_iter_get_arg_type(iter));
}

static void interface_network_added(DBusMessageIter *iter, void *user_data)
{
	const char *path = NULL;

	dbus_message_iter_get_basic(iter, &path);
	if (path == NULL)
		return;

	supplicant_dbus_property_get_all(path,
				SUPPLICANT_INTERFACE ".Interface.Network",
						network_property, NULL);
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

static void add_bss_to_network(struct supplicant_bss *bss)
{
	struct supplicant_interface *interface = bss->interface;
	struct supplicant_network *network;
	GString *str;
	char *group;
	unsigned int i;

	str = g_string_sized_new((bss->ssid_len * 2) + 24);
	if (str == NULL)
		return;

	if (bss->ssid_len > 0 && bss->ssid[0] != '\0') {
		for (i = 0; i < bss->ssid_len; i++)
			g_string_append_printf(str, "%02x", bss->ssid[i]);
	} else
		g_string_append_printf(str, "hidden");

	group = g_string_free(str, FALSE);

	network = g_hash_table_lookup(interface->network_table, group);
	if (network != NULL) {
		g_free(group);
		goto done;
	}

	network = g_try_new0(struct supplicant_network, 1);
	if (network == NULL) {
		g_free(group);
		return;
	}

	network->group = group;
	network->name = create_name(bss->ssid, bss->ssid_len);

	network->bss_table = g_hash_table_new_full(g_str_hash, g_str_equal,
							NULL, remove_bss);

	g_hash_table_replace(interface->network_table,
						network->group, network);

	callback_network_added(network);

done:
	g_hash_table_replace(interface->bss_mapping, bss->path, network);
	g_hash_table_replace(network->bss_table, bss->path, bss);
}

static void bss_property(const char *key, DBusMessageIter *iter,
							void *user_data)
{
	struct supplicant_bss *bss = user_data;

	if (bss->interface == NULL)
		return;

	if (key == NULL) {
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
		unsigned char capabilities = 0x00;

		dbus_message_iter_get_basic(iter, &capabilities);
	} else if (g_strcmp0(key, "Frequency") == 0) {
		dbus_int32_t frequency = 0;

		dbus_message_iter_get_basic(iter, &frequency);
		bss->frequency = frequency;
	} else if (g_strcmp0(key, "Level") == 0) {
		dbus_int32_t level = 0;

		dbus_message_iter_get_basic(iter, &level);
	} else if (g_strcmp0(key, "MaxRate") == 0) {
		dbus_int32_t maxrate = 0;

		dbus_message_iter_get_basic(iter, &maxrate);
	} else if (g_strcmp0(key, "RSNIE") == 0) {
		DBusMessageIter array;
		unsigned char *ie;
		int ie_len;

		dbus_message_iter_recurse(iter, &array);
		dbus_message_iter_get_fixed_array(&array, &ie, &ie_len);
	} else if (g_strcmp0(key, "WPAIE") == 0) {
		DBusMessageIter array;
		unsigned char *ie;
		int ie_len;

		dbus_message_iter_recurse(iter, &array);
		dbus_message_iter_get_fixed_array(&array, &ie, &ie_len);
	} else if (g_strcmp0(key, "WPSIE") == 0) {
		DBusMessageIter array;
		unsigned char *ie;
		int ie_len;

		dbus_message_iter_recurse(iter, &array);
		dbus_message_iter_get_fixed_array(&array, &ie, &ie_len);
	} else
		DBG("key %s type %c",
				key, dbus_message_iter_get_arg_type(iter));
}

static void interface_bss_added(DBusMessageIter *iter, void *user_data)
{
	struct supplicant_interface *interface = user_data;
	struct supplicant_network *network;
	struct supplicant_bss *bss;
	const char *path = NULL;

	dbus_message_iter_get_basic(iter, &path);
	if (path == NULL)
		return;

	network = g_hash_table_lookup(interface->bss_mapping, path);
	if (network != NULL) {
		bss = g_hash_table_lookup(network->bss_table, path);
		if (bss != NULL)
			return;
	}

	bss = g_try_new0(struct supplicant_bss, 1);
	if (bss == NULL)
		return;

	bss->interface = interface;
	bss->path = g_strdup(path);

	supplicant_dbus_property_get_all(path,
					SUPPLICANT_INTERFACE ".Interface.BSS",
							bss_property, bss);
}

static void interface_bss_removed(DBusMessageIter *iter, void *user_data)
{
	struct supplicant_interface *interface = user_data;
	struct supplicant_network *network;
	const char *path = NULL;

	dbus_message_iter_get_basic(iter, &path);
	if (path == NULL)
		return;

	network = g_hash_table_lookup(interface->bss_mapping, path);
	if (network == NULL)
		return;

	g_hash_table_remove(interface->bss_mapping, path);
	g_hash_table_remove(network->bss_table, path);

	if (g_hash_table_size(network->bss_table) == 0)
		g_hash_table_remove(interface->network_table, network->group);
}

static void interface_property(const char *key, DBusMessageIter *iter,
							void *user_data)
{
	struct supplicant_interface *interface = user_data;

	if (interface == NULL)
		return;

	if (key == NULL) {
		debug_scan_capabilities(interface);

		g_hash_table_replace(interface_table,
					interface->path, interface);

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
			interface->state = string2state(str);
	} else if (g_strcmp0(key, "Scanning") == 0) {
		dbus_bool_t scanning = FALSE;

		dbus_message_iter_get_basic(iter, &scanning);
		interface->scanning = scanning;
	} else if (g_strcmp0(key, "ApScan") == 0) {
		int apscan;

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
	} else if (g_strcmp0(key, "Networks") == 0) {
		supplicant_dbus_array_foreach(iter, interface_network_added,
								interface);
	} else
		DBG("key %s type %c",
				key, dbus_message_iter_get_arg_type(iter));
}

static void interface_path(DBusMessageIter *iter, void *user_data)
{
	struct supplicant_interface *interface;
	const char *path = NULL;

	dbus_message_iter_get_basic(iter, &path);
	if (path == NULL)
		return;

	interface = g_hash_table_lookup(interface_table, path);
	if (interface != NULL)
		return;

	interface = g_try_new0(struct supplicant_interface, 1);
	if (interface == NULL)
		return;

	interface->path = g_strdup(path);

	interface->network_table = g_hash_table_new_full(g_str_hash, g_str_equal,
							NULL, remove_network);

	interface->bss_mapping = g_hash_table_new_full(g_str_hash, g_str_equal,
								NULL, NULL);

	supplicant_dbus_property_get_all(path,
					SUPPLICANT_INTERFACE ".Interface",
						interface_property, interface);
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
	if (key == NULL)
		return;

	if (g_strcmp0(key, "Interfaces") == 0)
		supplicant_dbus_array_foreach(iter, interface_path, user_data);
	else if (g_strcmp0(key, "EapMethods") == 0) {
		supplicant_dbus_array_foreach(iter, eap_method, user_data);
		debug_eap_methods();
	} else if (g_strcmp0(key, "DebugParams") == 0) {
	}
}

static void signal_interface_added(const char *path, DBusMessageIter *iter)
{
	interface_path(iter, NULL);
}

static void signal_interface_removed(const char *path, DBusMessageIter *iter)
{
	DBG("path %s", path);
}

static void signal_bss_added(const char *path, DBusMessageIter *iter)
{
	struct supplicant_interface *interface;

	interface = g_hash_table_lookup(interface_table, path);
	if (interface == NULL)
		return;

	interface_bss_added(iter, interface);
}

static void signal_bss_removed(const char *path, DBusMessageIter *iter)
{
	struct supplicant_interface *interface;

	interface = g_hash_table_lookup(interface_table, path);
	if (interface == NULL)
		return;

	interface_bss_removed(iter, interface);
}

static struct {
	const char *interface;
	const char *member;
	void (*function) (const char *path, DBusMessageIter *iter);
} signal_map[] = {
	{ SUPPLICANT_INTERFACE, "InterfaceAdded",   signal_interface_added    },
	{ SUPPLICANT_INTERFACE, "InterfaceRemoved", signal_interface_removed  },
	{ SUPPLICANT_INTERFACE ".Interface", "BSSAdded",   signal_bss_added   },
	{ SUPPLICANT_INTERFACE ".Interface", "BSSRemoved", signal_bss_removed },
	{ }
};

static DBusHandlerResult supplicant_filter(DBusConnection *conn,
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

static const char *supplicant_rule1 = "type=signal,"
			"interface=" SUPPLICANT_INTERFACE;
static const char *supplicant_rule2 = "type=signal,"
			"interface=" SUPPLICANT_INTERFACE ".Interface";
static const char *supplicant_rule3 = "type=signal,"
			"interface=" SUPPLICANT_INTERFACE ".Interface.WPS";
static const char *supplicant_rule4 = "type=signal,"
			"interface=" SUPPLICANT_INTERFACE ".Interface.BSS";
static const char *supplicant_rule5 = "type=signal,"
			"interface=" SUPPLICANT_INTERFACE ".Interface.Network";
static const char *supplicant_rule6 = "type=signal,"
			"interface=" SUPPLICANT_INTERFACE ".Interface.Blob";

int supplicant_register(const struct supplicant_callbacks *callbacks)
{
	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (connection == NULL)
		return -EIO;

	if (dbus_connection_add_filter(connection,
				supplicant_filter, NULL, NULL) == FALSE) {
		dbus_connection_unref(connection);
		connection = NULL;
		return -EIO;
	}

	callbacks_pointer = callbacks;
	eap_methods = 0;

	interface_table = g_hash_table_new_full(g_str_hash, g_str_equal,
						NULL, remove_interface);

	supplicant_dbus_setup(connection);

	dbus_bus_add_match(connection, supplicant_rule1, NULL);
	dbus_bus_add_match(connection, supplicant_rule2, NULL);
	dbus_bus_add_match(connection, supplicant_rule3, NULL);
	dbus_bus_add_match(connection, supplicant_rule4, NULL);
	dbus_bus_add_match(connection, supplicant_rule5, NULL);
	dbus_bus_add_match(connection, supplicant_rule6, NULL);
	dbus_connection_flush(connection);

	supplicant_dbus_property_get_all(SUPPLICANT_PATH,
						SUPPLICANT_INTERFACE,
						service_property, NULL);

	return 0;
}

void supplicant_unregister(const struct supplicant_callbacks *callbacks)
{
	if (connection != NULL) {
		dbus_bus_remove_match(connection, supplicant_rule6, NULL);
		dbus_bus_remove_match(connection, supplicant_rule5, NULL);
		dbus_bus_remove_match(connection, supplicant_rule4, NULL);
		dbus_bus_remove_match(connection, supplicant_rule3, NULL);
		dbus_bus_remove_match(connection, supplicant_rule2, NULL);
		dbus_bus_remove_match(connection, supplicant_rule1, NULL);
		dbus_connection_flush(connection);

		dbus_connection_remove_filter(connection,
						supplicant_filter, NULL);
	}

	if (interface_table != NULL) {
		g_hash_table_destroy(interface_table);
		interface_table = NULL;
	}

	if (connection != NULL) {
		dbus_connection_unref(connection);
		connection = NULL;
	}

	callbacks_pointer = NULL;
	eap_methods = 0;
}
