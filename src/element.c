/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2008  Intel Corporation. All rights reserved.
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
#include <stdarg.h>
#include <string.h>

#include <glib.h>
#include <gdbus.h>

#include "connman.h"

static DBusConnection *connection;

static GNode *element_root = NULL;
static GSList *driver_list = NULL;
static gchar *device_filter = NULL;

static struct {
	enum connman_property_id id;
	int type;
	const char *name;
	const void *value;
} propid_table[] = {
	{ CONNMAN_PROPERTY_ID_IPV4_METHOD,
		DBUS_TYPE_STRING, "IPv4.Method", "dhcp" },
	{ CONNMAN_PROPERTY_ID_IPV4_ADDRESS,
		DBUS_TYPE_STRING, "IPv4.Address" },
	{ CONNMAN_PROPERTY_ID_IPV4_NETMASK,
		DBUS_TYPE_STRING, "IPv4.Netmask" },
	{ CONNMAN_PROPERTY_ID_IPV4_GATEWAY,
		DBUS_TYPE_STRING, "IPv4.Gateway" },
	{ CONNMAN_PROPERTY_ID_IPV4_BROADCAST,
		DBUS_TYPE_STRING, "IPv4.Broadcast" },
	{ CONNMAN_PROPERTY_ID_IPV4_NAMESERVER,
		DBUS_TYPE_STRING, "IPv4.Nameserver" },

	{ CONNMAN_PROPERTY_ID_WIFI_SECURITY,
		DBUS_TYPE_STRING, "WiFi.Security" },
	{ CONNMAN_PROPERTY_ID_WIFI_PASSPHRASE,
		DBUS_TYPE_STRING, "WiFi.Passphrase" },

	{ }
};

static int propid2type(enum connman_property_id id)
{
	int i;

	for (i = 0; propid_table[i].name; i++) {
		if (propid_table[i].id == id)
			return propid_table[i].type;
	}

	return DBUS_TYPE_INVALID;
}

static const char *propid2name(enum connman_property_id id)
{
	int i;

	for (i = 0; propid_table[i].name; i++) {
		if (propid_table[i].id == id)
			return propid_table[i].name;
	}

	return NULL;
}

static const char *type2string(enum connman_element_type type)
{
	switch (type) {
	case CONNMAN_ELEMENT_TYPE_UNKNOWN:
		return "unknown";
	case CONNMAN_ELEMENT_TYPE_ROOT:
		return "root";
	case CONNMAN_ELEMENT_TYPE_PROFILE:
		return "profile";
	case CONNMAN_ELEMENT_TYPE_DEVICE:
		return "device";
	case CONNMAN_ELEMENT_TYPE_NETWORK:
		return "network";
	case CONNMAN_ELEMENT_TYPE_SERVICE:
		return "service";
	case CONNMAN_ELEMENT_TYPE_IPV4:
		return "ipv4";
	case CONNMAN_ELEMENT_TYPE_IPV6:
		return "ipv6";
	case CONNMAN_ELEMENT_TYPE_DHCP:
		return "dhcp";
	case CONNMAN_ELEMENT_TYPE_BOOTP:
		return "bootp";
	case CONNMAN_ELEMENT_TYPE_ZEROCONF:
		return "zeroconf";
	case CONNMAN_ELEMENT_TYPE_CONNECTION:
		return "connection";
	}

	return NULL;
}

static const char *subtype2string(enum connman_element_subtype type)
{
	switch (type) {
	case CONNMAN_ELEMENT_SUBTYPE_UNKNOWN:
		return "unknown";
	case CONNMAN_ELEMENT_SUBTYPE_FAKE:
		return "fake";
	case CONNMAN_ELEMENT_SUBTYPE_NETWORK:
		return "network";
	case CONNMAN_ELEMENT_SUBTYPE_ETHERNET:
		return "ethernet";
	case CONNMAN_ELEMENT_SUBTYPE_WIFI:
		return "wifi";
	case CONNMAN_ELEMENT_SUBTYPE_WIMAX:
		return "wimax";
	case CONNMAN_ELEMENT_SUBTYPE_MODEM:
		return "modem";
	case CONNMAN_ELEMENT_SUBTYPE_BLUETOOTH:
		return "bluetooth";
	}

	return NULL;
}

static const char *subtype2description(enum connman_element_subtype type)
{
	switch (type) {
	case CONNMAN_ELEMENT_SUBTYPE_UNKNOWN:
	case CONNMAN_ELEMENT_SUBTYPE_FAKE:
	case CONNMAN_ELEMENT_SUBTYPE_NETWORK:
		return NULL;
	case CONNMAN_ELEMENT_SUBTYPE_ETHERNET:
		return "Ethernet";
	case CONNMAN_ELEMENT_SUBTYPE_WIFI:
		return "Wireless";
	case CONNMAN_ELEMENT_SUBTYPE_WIMAX:
		return "WiMAX";
	case CONNMAN_ELEMENT_SUBTYPE_MODEM:
		return "Modem";
	case CONNMAN_ELEMENT_SUBTYPE_BLUETOOTH:
		return "Bluetooth";
	}

	return NULL;
}

const char *__connman_element_policy2string(enum connman_element_policy policy)
{
	switch (policy) {
	case CONNMAN_ELEMENT_POLICY_UNKNOWN:
		return "unknown";
	case CONNMAN_ELEMENT_POLICY_IGNORE:
		return "ignore";
	case CONNMAN_ELEMENT_POLICY_AUTO:
		return "auto";
	case CONNMAN_ELEMENT_POLICY_ASK:
		return "ask";
	}

	return NULL;
}

enum connman_element_policy __connman_element_string2policy(const char *policy)
{
	if (strcasecmp(policy, "ignore") == 0)
		return CONNMAN_ELEMENT_POLICY_IGNORE;
	else if (strcasecmp(policy, "auto") == 0)
		return CONNMAN_ELEMENT_POLICY_AUTO;
	else if (strcasecmp(policy, "ask") == 0)
		return CONNMAN_ELEMENT_POLICY_ASK;
	else
		return CONNMAN_ELEMENT_POLICY_UNKNOWN;
}

const char *__connman_ipv4_method2string(enum connman_ipv4_method method)
{
	switch (method) {
	case CONNMAN_IPV4_METHOD_UNKNOWN:
		return "unknown";
	case CONNMAN_IPV4_METHOD_OFF:
		return "off";
	case CONNMAN_IPV4_METHOD_STATIC:
		return "static";
	case CONNMAN_IPV4_METHOD_DHCP:
		return "dhcp";
	}

	return "unknown";
}

enum connman_ipv4_method __connman_ipv4_string2method(const char *method)
{
	if (strcasecmp(method, "off") == 0)
		return CONNMAN_IPV4_METHOD_OFF;
	else if (strcasecmp(method, "static") == 0)
		return CONNMAN_IPV4_METHOD_STATIC;
	else if (strcasecmp(method, "dhcp") == 0)
		return CONNMAN_IPV4_METHOD_DHCP;
	else
		return CONNMAN_IPV4_METHOD_UNKNOWN;
}

static void append_property(DBusMessageIter *dict,
				struct connman_property *property)
{
	if (property->value == NULL)
		return;

	switch (property->type) {
	case DBUS_TYPE_ARRAY:
		connman_dbus_dict_append_array(dict, property->name,
			property->subtype, &property->value, property->size);
		break;
	case DBUS_TYPE_STRING:
		connman_dbus_dict_append_variant(dict, property->name,
					property->type, &property->value);
		break;
	default:
		connman_dbus_dict_append_variant(dict, property->name,
					property->type, property->value);
		break;
	}
}

static void add_common_properties(struct connman_element *element,
						DBusMessageIter *dict)
{
	const char *address = NULL, *netmask = NULL, *gateway = NULL;
	GSList *list;

	connman_element_get_value(element,
				CONNMAN_PROPERTY_ID_IPV4_ADDRESS, &address);
	connman_element_get_value(element,
				CONNMAN_PROPERTY_ID_IPV4_NETMASK, &netmask);
	connman_element_get_value(element,
				CONNMAN_PROPERTY_ID_IPV4_GATEWAY, &gateway);

	if (element->priority > 0)
		connman_dbus_dict_append_variant(dict, "Priority",
					DBUS_TYPE_UINT16, &element->priority);

	if (address != NULL)
		connman_dbus_dict_append_variant(dict, "IPv4.Address",
						DBUS_TYPE_STRING, &address);
	if (netmask != NULL)
		connman_dbus_dict_append_variant(dict, "IPv4.Netmask",
						DBUS_TYPE_STRING, &netmask);
	if (gateway != NULL)
		connman_dbus_dict_append_variant(dict, "IPv4.Gateway",
						DBUS_TYPE_STRING, &gateway);

	if (element->wifi.security != NULL) {
		const char *passphrase = "";

		connman_dbus_dict_append_variant(dict, "WiFi.Security",
				DBUS_TYPE_STRING, &element->wifi.security);

		if (element->wifi.passphrase != NULL)
			passphrase = element->wifi.passphrase;

		connman_dbus_dict_append_variant(dict, "WiFi.Passphrase",
				DBUS_TYPE_STRING, &passphrase);
	}

	__connman_element_lock(element);

	for (list = element->properties; list; list = list->next) {
		struct connman_property *property = list->data;

		append_property(dict, property);
	}

	__connman_element_unlock(element);
}

static void set_common_property(struct connman_element *element,
				const char *name, DBusMessageIter *value)
{
	GSList *list;

	if (g_str_equal(name, "Priority") == TRUE) {
		dbus_message_iter_get_basic(value, &element->priority);
		return;
	}

	__connman_element_lock(element);

	for (list = element->properties; list; list = list->next) {
		struct connman_property *property = list->data;
		const char *str;

		if (g_str_equal(property->name, name) == FALSE)
			continue;

		if (property->flags & CONNMAN_PROPERTY_FLAG_STATIC)
			continue;

		property->flags &= ~CONNMAN_PROPERTY_FLAG_REFERENCE;

		if (property->type == DBUS_TYPE_STRING) {
			dbus_message_iter_get_basic(value, &str);
			g_free(property->value);
			property->value = g_strdup(str);
		} else
			property->value = NULL;
	}

	__connman_element_unlock(element);
}

static void emit_enabled_signal(DBusConnection *conn,
					struct connman_element *element)
{
	DBusMessage *signal;
	DBusMessageIter entry, value;
	const char *iface, *key;

	DBG("conn %p", conn);

	if (element == NULL)
		return;

	switch (element->type) {
	case CONNMAN_ELEMENT_TYPE_DEVICE:
		iface = CONNMAN_DEVICE_INTERFACE;
		key = "Powered";
		break;
	case CONNMAN_ELEMENT_TYPE_NETWORK:
		iface = CONNMAN_NETWORK_INTERFACE;
		key = "Connected";
		break;
	case CONNMAN_ELEMENT_TYPE_CONNECTION:
		iface = CONNMAN_CONNECTION_INTERFACE;
		key = "Default";
		break;
	default:
		return;
	}

	signal = dbus_message_new_signal(element->path,
						iface, "PropertyChanged");
	if (signal == NULL)
		return;

	dbus_message_iter_init_append(signal, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
					DBUS_TYPE_BOOLEAN_AS_STRING, &value);
	dbus_message_iter_append_basic(&value, DBUS_TYPE_BOOLEAN,
							&element->enabled);
	dbus_message_iter_close_container(&entry, &value);

	g_dbus_send_message(conn, signal);
}

static void emit_scanning_signal(DBusConnection *conn,
					struct connman_element *element)
{
	DBusMessage *signal;
	DBusMessageIter entry, value;
	const char *key = "Scanning";

	DBG("conn %p", conn);

	if (element == NULL)
		return;

	if (element->type != CONNMAN_ELEMENT_TYPE_DEVICE)
		return;

	signal = dbus_message_new_signal(element->path,
				CONNMAN_DEVICE_INTERFACE, "PropertyChanged");
	if (signal == NULL)
		return;

	dbus_message_iter_init_append(signal, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
					DBUS_TYPE_BOOLEAN_AS_STRING, &value);
	dbus_message_iter_append_basic(&value, DBUS_TYPE_BOOLEAN,
							&element->scanning);
	dbus_message_iter_close_container(&entry, &value);

	g_dbus_send_message(conn, signal);
}

static DBusMessage *do_update(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_element *element = data;

	DBG("conn %p", conn);

	if (element->enabled == FALSE)
		return __connman_error_failed(msg);

	if (element->driver && element->driver->update) {
		DBG("Calling update callback");
		if (element->driver->update(element) < 0)
			return __connman_error_failed(msg);

	}

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *do_enable(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_element *element = data;

	DBG("conn %p", conn);

	if (element->enabled == TRUE)
		return __connman_error_failed(msg);

	if (element->driver && element->driver->enable) {
		DBG("Calling enable callback");
		if (element->driver->enable(element) < 0)
			return __connman_error_failed(msg);
	}

	element->enabled = TRUE;

	emit_enabled_signal(connection, element);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *do_disable(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_element *element = data;

	DBG("conn %p", conn);

	if (element->enabled == FALSE)
		return __connman_error_failed(msg);

	if (element->driver && element->driver->disable) {
		DBG("Calling disable callback");
		if (element->driver->disable(element) < 0)
			return __connman_error_failed(msg);
	}

	element->enabled = FALSE;

	emit_enabled_signal(connection, element);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static void append_networks(struct connman_element *element,
						DBusMessageIter *entry)
{
	DBusMessageIter value, iter;
	const char *key = "Networks";

	dbus_message_iter_append_basic(entry, DBUS_TYPE_STRING, &key);

	dbus_message_iter_open_container(entry, DBUS_TYPE_VARIANT,
		DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_OBJECT_PATH_AS_STRING,
								&value);

	dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY,
				DBUS_TYPE_OBJECT_PATH_AS_STRING, &iter);

	__connman_element_list(element, CONNMAN_ELEMENT_TYPE_NETWORK, &iter);

	dbus_message_iter_close_container(&value, &iter);

	dbus_message_iter_close_container(entry, &value);
}

static DBusMessage *device_get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_element *element = data;
	DBusMessage *reply;
	DBusMessageIter array, dict, entry;
	const char *str;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &array);

	dbus_message_iter_open_container(&array, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	str = subtype2description(element->subtype);
	if (str != NULL && element->devname != NULL) {
		char *name = g_strdup_printf("%s (%s)", str, element->devname);
		if (name != NULL)
			connman_dbus_dict_append_variant(&dict, "Name",
						DBUS_TYPE_STRING, &name);
		g_free(name);
	}

	str = subtype2string(element->subtype);
	if (str != NULL)
		connman_dbus_dict_append_variant(&dict, "Type",
						DBUS_TYPE_STRING, &str);

	str = __connman_element_policy2string(element->policy);
	if (str != NULL)
		connman_dbus_dict_append_variant(&dict, "Policy",
						DBUS_TYPE_STRING, &str);

	connman_dbus_dict_append_variant(&dict, "Powered",
					DBUS_TYPE_BOOLEAN, &element->enabled);

	if (element->subtype == CONNMAN_ELEMENT_SUBTYPE_WIFI ||
			element->subtype == CONNMAN_ELEMENT_SUBTYPE_WIMAX ||
			element->subtype == CONNMAN_ELEMENT_SUBTYPE_BLUETOOTH) {
		connman_dbus_dict_append_variant(&dict, "Scanning",
					DBUS_TYPE_BOOLEAN, &element->scanning);

		dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY,
								NULL, &entry);
		append_networks(element, &entry);
		dbus_message_iter_close_container(&dict, &entry);
	}

	add_common_properties(element, &dict);

	dbus_message_iter_close_container(&array, &dict);

	return reply;
}

static DBusMessage *device_set_property(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_element *element = data;
	DBusMessageIter iter, value;
	const char *name;

	DBG("conn %p", conn);

	if (dbus_message_iter_init(msg, &iter) == FALSE)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &name);
	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &value);

	if (__connman_security_check_privileges(msg) < 0)
		return __connman_error_permission_denied(msg);

	if (g_str_equal(name, "Powered") == TRUE) {
		dbus_bool_t powered;

		dbus_message_iter_get_basic(&value, &powered);

		if (powered == TRUE)
			do_enable(conn, msg, element);
		else
			do_disable(conn, msg, element);
	} else
		set_common_property(element, name, &value);

	__connman_element_store(element);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static int parse_network_dict(DBusMessageIter *iter, const char **ssid,
				const char **security, const char **passphrase)
{
	while (dbus_message_iter_get_arg_type(iter) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;

		dbus_message_iter_recurse(iter, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		switch (dbus_message_iter_get_arg_type(&value)) {
		case DBUS_TYPE_STRING:
			if (g_str_equal(key, "WiFi.SSID") == TRUE)
				dbus_message_iter_get_basic(&value, ssid);
			else if (g_str_equal(key, "WiFi.Security") == TRUE)
				dbus_message_iter_get_basic(&value, security);
			else if (g_str_equal(key, "WiFi.Passphrase") == TRUE)
				dbus_message_iter_get_basic(&value, passphrase);
			break;
		}

		dbus_message_iter_next(iter);
	}

	return 0;
}

static DBusMessage *device_create_network(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_element *element = data;
	struct connman_element *network;
	DBusMessageIter iter, array;
	const char *ssid = NULL, *security = NULL, *passphrase = NULL;

	DBG("conn %p", conn);

	if (element->subtype != CONNMAN_ELEMENT_SUBTYPE_WIFI)
		return __connman_error_invalid_arguments(msg);

	if (dbus_message_iter_init(msg, &iter) == FALSE)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_recurse(&iter, &array);
	parse_network_dict(&array, &ssid, &security, &passphrase);
	if (ssid == NULL)
		return __connman_error_invalid_arguments(msg);

	DBG("ssid %s security %s passphrase %s", ssid, security, passphrase);

	network = connman_element_create(ssid);

	network->type = CONNMAN_ELEMENT_TYPE_NETWORK;
	network->index = element->index;

	network->remember = TRUE;

	connman_element_add_static_property(network, "Name",
						DBUS_TYPE_STRING, &ssid);

	connman_element_add_static_array_property(element, "WiFi.SSID",
					DBUS_TYPE_BYTE, &ssid, strlen(ssid));

	network->wifi.security = g_strdup(security);
	network->wifi.passphrase = g_strdup(passphrase);

	connman_element_register(network, element);

	return g_dbus_create_reply(msg, DBUS_TYPE_OBJECT_PATH, &network->path,
							DBUS_TYPE_INVALID);
}

static DBusMessage *device_remove_network(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *network_get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_element *element = data;
	DBusMessage *reply;
	DBusMessageIter array, dict;
	const char *str;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &array);

	dbus_message_iter_open_container(&array, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	if (element->parent)
		connman_dbus_dict_append_variant(&dict, "Device",
				DBUS_TYPE_OBJECT_PATH, &element->parent->path);

	str = __connman_element_policy2string(element->policy);
	if (str != NULL)
		connman_dbus_dict_append_variant(&dict, "Policy",
						DBUS_TYPE_STRING, &str);

	connman_dbus_dict_append_variant(&dict, "Available",
					DBUS_TYPE_BOOLEAN, &element->available);

	connman_dbus_dict_append_variant(&dict, "Connected",
					DBUS_TYPE_BOOLEAN, &element->enabled);

	connman_dbus_dict_append_variant(&dict, "Remember",
					DBUS_TYPE_BOOLEAN, &element->remember);

	add_common_properties(element, &dict);

	dbus_message_iter_close_container(&array, &dict);

	return reply;
}

static DBusMessage *network_set_property(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_element *element = data;
	DBusMessageIter iter;
	DBusMessageIter value;
	const char *name;

	DBG("conn %p", conn);

	if (dbus_message_iter_init(msg, &iter) == FALSE)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &name);
	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &value);

	if (__connman_security_check_privileges(msg) < 0)
		return __connman_error_permission_denied(msg);

	if (g_str_equal(name, "Remember") == TRUE) {
		dbus_message_iter_get_basic(&value, &element->remember);
	} else if (g_str_equal(name, "WiFi.Passphrase") == TRUE) {
		const char *str;

		dbus_message_iter_get_basic(&value, &str);
		g_free(element->wifi.passphrase);
		element->wifi.passphrase = g_strdup(str);
	} else
		set_common_property(element, name, &value);

	__connman_element_store(element);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *connection_get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_element *element = data;
	DBusMessage *reply;
	DBusMessageIter array, dict;
	const char *str;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &array);

	dbus_message_iter_open_container(&array, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	str = subtype2string(element->subtype);
	if (str != NULL)
		connman_dbus_dict_append_variant(&dict, "Type",
						DBUS_TYPE_STRING, &str);

	if (element->subtype == CONNMAN_ELEMENT_SUBTYPE_WIFI ||
			element->subtype == CONNMAN_ELEMENT_SUBTYPE_WIMAX)
		connman_dbus_dict_append_variant(&dict, "Strength",
					DBUS_TYPE_BYTE, &element->strength);

	connman_dbus_dict_append_variant(&dict, "Default",
					DBUS_TYPE_BOOLEAN, &element->enabled);

	add_common_properties(element, &dict);

	dbus_message_iter_close_container(&array, &dict);

	return reply;
}

static DBusMessage *connection_set_property(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_element *element = data;
	DBusMessageIter iter, value;
	const char *name;

	DBG("conn %p", conn);

	if (dbus_message_iter_init(msg, &iter) == FALSE)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &name);
	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &value);

	if (__connman_security_check_privileges(msg) < 0)
		return __connman_error_permission_denied(msg);

	if (g_str_equal(name, "Default") == TRUE) {
		dbus_bool_t enabled;

		dbus_message_iter_get_basic(&value, &enabled);

		if (enabled == TRUE)
			return do_enable(conn, msg, element);
		else
			return do_disable(conn, msg, element);
	}

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static GDBusMethodTable device_methods[] = {
	{ "GetProperties", "",      "a{sv}", device_get_properties },
	{ "SetProperty",   "sv",    "",      device_set_property   },
	{ "CreateNetwork", "a{sv}", "o",     device_create_network },
	{ "RemoveNetwork", "o",     "",      device_remove_network },
	{ "ProposeScan",   "",      "",      do_update             },
	{ },
};

static GDBusMethodTable network_methods[] = {
	{ "GetProperties", "",   "a{sv}", network_get_properties },
	{ "SetProperty",   "sv", "",      network_set_property   },
	{ "Connect",       "",   "",      do_enable              },
	{ "Disconnect",    "",   "",      do_disable             },
	{ },
};

static GDBusMethodTable connection_methods[] = {
	{ "GetProperties", "",   "a{sv}", connection_get_properties },
	{ "SetProperty",   "sv", "",      connection_set_property   },
	{ },
};

static GDBusSignalTable element_signals[] = {
	{ "PropertyChanged", "sv" },
	{ },
};

struct append_filter {
	enum connman_element_type type;
	DBusMessageIter *iter;
};

static gboolean append_path(GNode *node, gpointer user_data)
{
	struct connman_element *element = node->data;
	struct append_filter *filter = user_data;

	DBG("element %p name %s", element, element->name);

	if (element->type == CONNMAN_ELEMENT_TYPE_ROOT)
		return FALSE;

	if (filter->type != CONNMAN_ELEMENT_TYPE_UNKNOWN &&
					filter->type != element->type)
		return FALSE;

	if (filter->type == CONNMAN_ELEMENT_TYPE_DEVICE &&
			element->subtype == CONNMAN_ELEMENT_SUBTYPE_NETWORK)
		return FALSE;

	dbus_message_iter_append_basic(filter->iter,
				DBUS_TYPE_OBJECT_PATH, &element->path);

	return FALSE;
}

void __connman_element_list(struct connman_element *element,
					enum connman_element_type type,
							DBusMessageIter *iter)
{
	struct append_filter filter = { type, iter };
	GNode *node;

	DBG("");

	if (element != NULL) {
		node = g_node_find(element_root, G_PRE_ORDER,
						G_TRAVERSE_ALL, element);
		if (node == NULL)
			return;
	} else
		node = element_root;

	g_node_traverse(node, G_PRE_ORDER, G_TRAVERSE_ALL, -1,
						append_path, &filter);
}

struct count_data {
	enum connman_element_type type;
	int count;
};

static gboolean count_element(GNode *node, gpointer user_data)
{
	struct connman_element *element = node->data;
	struct count_data *data = user_data;

	DBG("element %p name %s", element, element->name);

	if (element->type == CONNMAN_ELEMENT_TYPE_ROOT)
		return FALSE;

	if (data->type != CONNMAN_ELEMENT_TYPE_UNKNOWN &&
					data->type != element->type)
		return FALSE;

	data->count++;

	return FALSE;
}

int __connman_element_count(struct connman_element *element,
					enum connman_element_type type)
{
	struct count_data data = { type, 0 };
	GNode *node;

	DBG("");

	if (element != NULL) {
		node = g_node_find(element_root, G_PRE_ORDER,
						G_TRAVERSE_ALL, element);
		if (node == NULL)
			return 0;
	} else
		node = element_root;

	g_node_traverse(node, G_PRE_ORDER, G_TRAVERSE_ALL, -1,
						count_element, &data);

	return data.count;
}

static gint compare_priority(gconstpointer a, gconstpointer b)
{
	const struct connman_driver *driver1 = a;
	const struct connman_driver *driver2 = b;

	return driver2->priority - driver1->priority;
}

static gboolean match_driver(struct connman_element *element,
					struct connman_driver *driver)
{
	if (element->type == CONNMAN_ELEMENT_TYPE_ROOT)
		return FALSE;

	if (element->type != driver->type &&
			driver->type != CONNMAN_ELEMENT_TYPE_UNKNOWN)
		return FALSE;

	if (element->subtype == driver->subtype ||
			driver->subtype == CONNMAN_ELEMENT_SUBTYPE_UNKNOWN)
		return TRUE;

	return FALSE;
}

static void enable_element(struct connman_element *element)
{
	if (element->type != CONNMAN_ELEMENT_TYPE_DEVICE)
		return;

	if (element->policy != CONNMAN_ELEMENT_POLICY_AUTO)
		return;

	if (element->driver && element->driver->enable) {
		if (element->driver->enable(element) == 0) {
			element->enabled = TRUE;
			emit_enabled_signal(connection, element);
		}
	}
}

static gboolean probe_driver(GNode *node, gpointer data)
{
	struct connman_element *element = node->data;
	struct connman_driver *driver = data;

	DBG("element %p name %s", element, element->name);

	if (!element->driver && match_driver(element, driver) == TRUE) {
		if (driver->probe(element) < 0)
			return FALSE;

		__connman_element_lock(element);
		element->driver = driver;
		__connman_element_unlock(element);

		enable_element(element);
	}

	return FALSE;
}

void __connman_driver_rescan(struct connman_driver *driver)
{
	DBG("driver %p name %s", driver, driver->name);

	if (!driver->probe)
		return;

	if (element_root != NULL)
		g_node_traverse(element_root, G_PRE_ORDER,
				G_TRAVERSE_ALL, -1, probe_driver, driver);
}

/**
 * connman_driver_register:
 * @driver: driver definition
 *
 * Register a new driver
 *
 * Returns: %0 on success
 */
int connman_driver_register(struct connman_driver *driver)
{
	DBG("driver %p name %s", driver, driver->name);

	if (driver->type == CONNMAN_ELEMENT_TYPE_ROOT)
		return -EINVAL;

	if (!driver->probe)
		return -EINVAL;

	driver_list = g_slist_insert_sorted(driver_list, driver,
							compare_priority);

	if (element_root != NULL)
		g_node_traverse(element_root, G_PRE_ORDER,
				G_TRAVERSE_ALL, -1, probe_driver, driver);

	return 0;
}

static void disable_element(struct connman_element *element)
{
	if (element->policy != CONNMAN_ELEMENT_POLICY_AUTO)
		return;

	if (element->enabled == FALSE)
		return;

	if (element->driver && element->driver->disable) {
		if (element->driver->disable(element) == 0) {
			element->enabled = FALSE;
			emit_enabled_signal(connection, element);
		}
	}
}

static gboolean remove_driver(GNode *node, gpointer data)
{
	struct connman_element *element = node->data;
	struct connman_driver *driver = data;

	DBG("element %p name %s", element, element->name);

	if (element->driver == driver) {
		disable_element(element);

		if (driver->remove)
			driver->remove(element);

		__connman_element_lock(element);
		element->driver = NULL;
		__connman_element_unlock(element);
	}

	return FALSE;
}

/**
 * connman_driver_unregister:
 * @driver: driver definition
 *
 * Remove a previously registered driver
 */
void connman_driver_unregister(struct connman_driver *driver)
{
	DBG("driver %p name %s", driver, driver->name);

	driver_list = g_slist_remove(driver_list, driver);

	if (element_root != NULL)
		g_node_traverse(element_root, G_POST_ORDER,
				G_TRAVERSE_ALL, -1, remove_driver, driver);
}

/**
 * connman_element_create:
 * @name: element name
 *
 * Allocate a new element and assign the given #name to it. If the name
 * is #NULL, it will be later on created based on the element type.
 *
 * Returns: a newly-allocated #connman_element structure
 */
struct connman_element *connman_element_create(const char *name)
{
	struct connman_element *element;

	element = g_try_new0(struct connman_element, 1);
	if (element == NULL)
		return NULL;

	DBG("element %p", element);

	element->refcount = 1;

	element->name    = g_strdup(name);
	element->type    = CONNMAN_ELEMENT_TYPE_UNKNOWN;
	element->subtype = CONNMAN_ELEMENT_SUBTYPE_UNKNOWN;
	element->state   = CONNMAN_ELEMENT_STATE_CLOSED;
	element->policy  = CONNMAN_ELEMENT_POLICY_AUTO;
	element->index   = -1;
	element->enabled = FALSE;

	return element;
}

struct connman_element *connman_element_ref(struct connman_element *element)
{
	DBG("element %p name %s refcount %d", element, element->name,
				g_atomic_int_get(&element->refcount) + 1);

	g_atomic_int_inc(&element->refcount);

	return element;
}

static void free_properties(struct connman_element *element)
{
	GSList *list;

	DBG("element %p name %s", element, element->name);

	__connman_element_lock(element);

	for (list = element->properties; list; list = list->next) {
		struct connman_property *property = list->data;

		if (!(property->flags & CONNMAN_PROPERTY_FLAG_REFERENCE))
			g_free(property->value);

		g_free(property->name);
		g_free(property);
	}

	g_slist_free(element->properties);

	element->properties = NULL;

	__connman_element_unlock(element);
}

void connman_element_unref(struct connman_element *element)
{
	DBG("element %p name %s refcount %d", element, element->name,
				g_atomic_int_get(&element->refcount) - 1);

	if (g_atomic_int_dec_and_test(&element->refcount) == TRUE) {
		free_properties(element);
		g_free(element->ipv4.address);
		g_free(element->ipv4.netmask);
		g_free(element->ipv4.gateway);
		g_free(element->ipv4.network);
		g_free(element->ipv4.broadcast);
		g_free(element->ipv4.nameserver);
		g_free(element->devname);
		g_free(element->devpath);
		g_free(element->path);
		g_free(element->name);
		g_free(element);
	}
}

int connman_element_add_static_property(struct connman_element *element,
				const char *name, int type, const void *value)
{
	struct connman_property *property;

	DBG("element %p name %s", element, element->name);

	if (type != DBUS_TYPE_STRING && type != DBUS_TYPE_BYTE)
		return -EINVAL;

	property = g_try_new0(struct connman_property, 1);
	if (property == NULL)
		return -ENOMEM;

	property->flags = CONNMAN_PROPERTY_FLAG_STATIC;
	property->id    = CONNMAN_PROPERTY_ID_INVALID;
	property->name  = g_strdup(name);
	property->type  = type;

	DBG("name %s type %d value %p", name, type, value);

	switch (type) {
	case DBUS_TYPE_STRING:
		property->value = g_strdup(*((const char **) value));
		break;
	case DBUS_TYPE_BYTE:
		property->value = g_try_malloc(1);
		if (property->value != NULL)
			memcpy(property->value, value, 1);
		break;
	}

	__connman_element_lock(element);
	element->properties = g_slist_append(element->properties, property);
	__connman_element_unlock(element);

	return 0;
}

static void emit_property_changed(DBusConnection *conn,
				struct connman_element *element,
				const char *name, int type, const void *data)
{
	DBusMessage *signal;
	DBusMessageIter entry, value;
	const char *iface, *sig;

	DBG("conn %p", conn);

	switch (element->type) {
	case CONNMAN_ELEMENT_TYPE_DEVICE:
		iface = CONNMAN_DEVICE_INTERFACE;
		break;
	case CONNMAN_ELEMENT_TYPE_NETWORK:
		iface = CONNMAN_NETWORK_INTERFACE;
		break;
	case CONNMAN_ELEMENT_TYPE_CONNECTION:
		iface = CONNMAN_CONNECTION_INTERFACE;
		break;
	default:
		return;
	}

	signal = dbus_message_new_signal(element->path,
						iface, "PropertyChanged");
	if (signal == NULL)
		return;

	dbus_message_iter_init_append(signal, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &name);

	switch (type) {
	case DBUS_TYPE_STRING:
		sig = DBUS_TYPE_STRING_AS_STRING;
		break;
	case DBUS_TYPE_BYTE:
		sig = DBUS_TYPE_BYTE_AS_STRING;
		break;
	default:
		sig = DBUS_TYPE_VARIANT_AS_STRING;
		break;
	}

	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
							sig, &value);
	dbus_message_iter_append_basic(&value, type, data);
	dbus_message_iter_close_container(&entry, &value);

	g_dbus_send_message(conn, signal);
}

int connman_element_set_static_property(struct connman_element *element,
				const char *name, int type, const void *value)
{
	GSList *list;

	DBG("element %p name %s", element, element->name);

	if (type != DBUS_TYPE_STRING && type != DBUS_TYPE_BYTE)
		return -EINVAL;

	__connman_element_lock(element);

	for (list = element->properties; list; list = list->next) {
		struct connman_property *property = list->data;

		if (g_str_equal(property->name, name) == FALSE)
			continue;

		if (!(property->flags & CONNMAN_PROPERTY_FLAG_STATIC))
			continue;

		property->type = type;
		g_free(property->value);

		switch (type) {
		case DBUS_TYPE_STRING:
			property->value = g_strdup(*((const char **) value));
			break;
		case DBUS_TYPE_BYTE:
			property->value = g_try_malloc(1);
			if (property->value != NULL)
				memcpy(property->value, value, 1);
			break;
		}
	}

	__connman_element_unlock(element);

	emit_property_changed(connection, element, name, type, value);

	return 0;
}

int connman_element_add_static_array_property(struct connman_element *element,
			const char *name, int type, const void *value, int len)
{
	struct connman_property *property;

	DBG("element %p name %s", element, element->name);

	if (type != DBUS_TYPE_BYTE)
		return -EINVAL;

	property = g_try_new0(struct connman_property, 1);
	if (property == NULL)
		return -ENOMEM;

	property->flags   = CONNMAN_PROPERTY_FLAG_STATIC;
	property->id      = CONNMAN_PROPERTY_ID_INVALID;
	property->name    = g_strdup(name);
	property->type    = DBUS_TYPE_ARRAY;
	property->subtype = type;

	DBG("name %s type %d value %p", name, type, value);

	switch (type) {
	case DBUS_TYPE_BYTE:
		property->value = g_try_malloc(len);
		if (property->value != NULL) {
			memcpy(property->value,
				*((const unsigned char **) value), len);
			property->size = len;
		}
		break;
	}

	__connman_element_lock(element);
	element->properties = g_slist_append(element->properties, property);
	__connman_element_unlock(element);

	return 0;
}

static void *get_reference_value(struct connman_element *element,
						enum connman_property_id id)
{
	GSList *list;

	DBG("element %p name %s", element, element->name);

	for (list = element->properties; list; list = list->next) {
		struct connman_property *property = list->data;

		if (property->id != id)
			continue;

		if (!(property->flags & CONNMAN_PROPERTY_FLAG_REFERENCE))
			return property->value;
	}

	if (element->parent == NULL)
		return NULL;

	return get_reference_value(element->parent, id);
}

static void set_reference_properties(struct connman_element *element)
{
	GSList *list;

	DBG("element %p name %s", element, element->name);

	for (list = element->properties; list; list = list->next) {
		struct connman_property *property = list->data;

		if (!(property->flags & CONNMAN_PROPERTY_FLAG_REFERENCE))
			continue;

		property->value = get_reference_value(element->parent,
								property->id);
	}
}

static struct connman_property *create_property(struct connman_element *element,
						enum connman_property_id id)
{
	struct connman_property *property;
	GSList *list;

	DBG("element %p name %s", element, element->name);

	__connman_element_lock(element);

	for (list = element->properties; list; list = list->next) {
		property = list->data;

		if (property->id == id)
			goto unlock;
	}

	property = g_try_new0(struct connman_property, 1);
	if (property == NULL)
		goto unlock;

	property->flags = CONNMAN_PROPERTY_FLAG_REFERENCE;
	property->id    = id;
	property->name  = g_strdup(propid2name(id));
	property->type  = propid2type(id);

	if (property->name == NULL) {
		g_free(property);
		property = NULL;
		goto unlock;
	}

	element->properties = g_slist_append(element->properties, property);

unlock:
	__connman_element_unlock(element);

	return property;
}

static void create_default_properties(struct connman_element *element)
{
	struct connman_property *property;
	int i;

	DBG("element %p name %s", element, element->name);

	for (i = 0; propid_table[i].name; i++) {
		DBG("property %s", propid_table[i].name);

		property = create_property(element, propid_table[i].id);

		property->flags &= ~CONNMAN_PROPERTY_FLAG_REFERENCE;

		if (propid_table[i].type != DBUS_TYPE_STRING)
			continue;

		if (propid_table[i].value)
			property->value = g_strdup(propid_table[i].value);
		else
			property->value = g_strdup("");
	}
}

static int define_properties_valist(struct connman_element *element,
								va_list args)
{
	enum connman_property_id id;

	DBG("element %p name %s", element, element->name);

	id = va_arg(args, enum connman_property_id);

	while (id != CONNMAN_PROPERTY_ID_INVALID) {

		DBG("property %d", id);

		create_property(element, id);

		id = va_arg(args, enum connman_property_id);
	}

	return 0;
}

/**
 * connman_element_define_properties:
 * @element: an element
 * @varargs: list of property identifiers
 *
 * Define the valid properties for an element.
 *
 * Returns: %0 on success
 */
int connman_element_define_properties(struct connman_element *element, ...)
{
	va_list args;
	int err;

	DBG("element %p name %s", element, element->name);

	va_start(args, element);

	err = define_properties_valist(element, args);

	va_end(args);

	return err;
}

int connman_element_create_property(struct connman_element *element,
						const char *name, int type)
{
	return -EIO;
}

int connman_element_set_property(struct connman_element *element,
				enum connman_property_id id, const void *value)
{
	switch (id) {
	case CONNMAN_PROPERTY_ID_IPV4_ADDRESS:
		__connman_element_lock(element);
		g_free(element->ipv4.address);
		element->ipv4.address = g_strdup(*((const char **) value));
		__connman_element_unlock(element);
		break;
	case CONNMAN_PROPERTY_ID_IPV4_NETMASK:
		__connman_element_lock(element);
		g_free(element->ipv4.netmask);
		element->ipv4.netmask = g_strdup(*((const char **) value));
		__connman_element_unlock(element);
		break;
	case CONNMAN_PROPERTY_ID_IPV4_GATEWAY:
		__connman_element_lock(element);
		g_free(element->ipv4.gateway);
		element->ipv4.gateway = g_strdup(*((const char **) value));
		__connman_element_unlock(element);
		break;
	case CONNMAN_PROPERTY_ID_IPV4_BROADCAST:
		__connman_element_lock(element);
		g_free(element->ipv4.broadcast);
		element->ipv4.broadcast = g_strdup(*((const char **) value));
		__connman_element_unlock(element);
		break;
	case CONNMAN_PROPERTY_ID_IPV4_NAMESERVER:
		__connman_element_lock(element);
		g_free(element->ipv4.nameserver);
		element->ipv4.nameserver = g_strdup(*((const char **) value));
		__connman_element_unlock(element);
		break;
	case CONNMAN_PROPERTY_ID_WIFI_SECURITY:
		__connman_element_lock(element);
		g_free(element->wifi.security);
		element->wifi.security = g_strdup(*((const char **) value));
		__connman_element_unlock(element);
		break;
	case CONNMAN_PROPERTY_ID_WIFI_PASSPHRASE:
		__connman_element_lock(element);
		g_free(element->wifi.passphrase);
		element->wifi.passphrase = g_strdup(*((const char **) value));
		__connman_element_unlock(element);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

int connman_element_get_value(struct connman_element *element,
				enum connman_property_id id, void *value)
{
	if (element->type == CONNMAN_ELEMENT_TYPE_ROOT)
		return -EINVAL;

	switch (id) {
	case CONNMAN_PROPERTY_ID_IPV4_ADDRESS:
		if (element->ipv4.address == NULL)
			return connman_element_get_value(element->parent,
								id, value);
		__connman_element_lock(element);
		*((char **) value) = element->ipv4.address;
		__connman_element_unlock(element);
		break;
	case CONNMAN_PROPERTY_ID_IPV4_NETMASK:
		if (element->ipv4.netmask == NULL)
			return connman_element_get_value(element->parent,
								id, value);
		__connman_element_lock(element);
		*((char **) value) = element->ipv4.netmask;
		__connman_element_unlock(element);
		break;
	case CONNMAN_PROPERTY_ID_IPV4_GATEWAY:
		if (element->ipv4.gateway == NULL)
			return connman_element_get_value(element->parent,
								id, value);
		__connman_element_lock(element);
		*((char **) value) = element->ipv4.gateway;
		__connman_element_unlock(element);
		break;
	case CONNMAN_PROPERTY_ID_IPV4_BROADCAST:
		if (element->ipv4.broadcast == NULL)
			return connman_element_get_value(element->parent,
								id, value);
		__connman_element_lock(element);
		*((char **) value) = element->ipv4.broadcast;
		__connman_element_unlock(element);
		break;
	case CONNMAN_PROPERTY_ID_IPV4_NAMESERVER:
		if (element->ipv4.nameserver == NULL)
			return connman_element_get_value(element->parent,
								id, value);
		__connman_element_lock(element);
		*((char **) value) = element->ipv4.nameserver;
		__connman_element_unlock(element);
		break;
	case CONNMAN_PROPERTY_ID_WIFI_SECURITY:
		if (element->wifi.security == NULL)
			return connman_element_get_value(element->parent,
								id, value);
		__connman_element_lock(element);
		*((char **) value) = element->wifi.security;
		__connman_element_unlock(element);
		break;
	case CONNMAN_PROPERTY_ID_WIFI_PASSPHRASE:
		if (element->wifi.passphrase == NULL)
			return connman_element_get_value(element->parent,
								id, value);
		__connman_element_lock(element);
		*((char **) value) = element->wifi.passphrase;
		__connman_element_unlock(element);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

gboolean connman_element_get_static_property(struct connman_element *element,
						const char *name, void *value)
{
	GSList *list;
	gboolean found = FALSE;

	DBG("element %p name %s", element, element->name);

	__connman_element_lock(element);

	for (list = element->properties; list; list = list->next) {
		struct connman_property *property = list->data;

		if (!(property->flags & CONNMAN_PROPERTY_FLAG_STATIC))
			continue;

		if (g_str_equal(property->name, name) == TRUE) {
			switch (property->type) {
			case DBUS_TYPE_STRING:
				*((char **) value) = property->value;
				found = TRUE;
				break;
			}
			break;
		}
	}

	__connman_element_unlock(element);

	return found;
}

gboolean connman_element_get_static_array_property(struct connman_element *element,
					const char *name, void *value, int *len)
{
	GSList *list;
	gboolean found = FALSE;

	DBG("element %p name %s", element, element->name);

	__connman_element_lock(element);

	for (list = element->properties; list; list = list->next) {
		struct connman_property *property = list->data;

		if (!(property->flags & CONNMAN_PROPERTY_FLAG_STATIC))
			continue;

		if (g_str_equal(property->name, name) == TRUE) {
			*((char **) value) = property->value;
			*len = property->size;
			found = TRUE;
			break;
		}
	}

	__connman_element_unlock(element);

	return found;
}

gboolean connman_element_match_static_property(struct connman_element *element,
					const char *name, const void *value)
{
	GSList *list;
	gboolean result = FALSE;

	DBG("element %p name %s", element, element->name);

	__connman_element_lock(element);

	for (list = element->properties; list; list = list->next) {
		struct connman_property *property = list->data;

		if (!(property->flags & CONNMAN_PROPERTY_FLAG_STATIC))
			continue;

		if (g_str_equal(property->name, name) == FALSE)
			continue;

		if (property->type == DBUS_TYPE_STRING)
			result = g_str_equal(property->value,
						*((const char **) value));

		if (result == TRUE)
			break;
	}

	__connman_element_unlock(element);

	return result;
}

static void append_devices(DBusMessageIter *entry)
{
	DBusMessageIter value, iter;
	const char *key = "Devices";

	dbus_message_iter_append_basic(entry, DBUS_TYPE_STRING, &key);

	dbus_message_iter_open_container(entry, DBUS_TYPE_VARIANT,
		DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_OBJECT_PATH_AS_STRING,
								&value);

	dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY,
				DBUS_TYPE_OBJECT_PATH_AS_STRING, &iter);
	__connman_element_list(NULL, CONNMAN_ELEMENT_TYPE_DEVICE, &iter);
	dbus_message_iter_close_container(&value, &iter);

	dbus_message_iter_close_container(entry, &value);
}

static void emit_devices_signal(DBusConnection *conn)
{
	DBusMessage *signal;
	DBusMessageIter entry;

	DBG("conn %p", conn);

	signal = dbus_message_new_signal(CONNMAN_MANAGER_PATH,
				CONNMAN_MANAGER_INTERFACE, "PropertyChanged");
	if (signal == NULL)
		return;

	dbus_message_iter_init_append(signal, &entry);

	append_devices(&entry);

	g_dbus_send_message(conn, signal);
}

static void emit_networks_signal(DBusConnection *conn,
					struct connman_element *device)
{
	DBusMessage *signal;
	DBusMessageIter entry;

	DBG("conn %p", conn);

	if (device == NULL)
		return;

	signal = dbus_message_new_signal(device->path,
				CONNMAN_DEVICE_INTERFACE, "PropertyChanged");
	if (signal == NULL)
		return;

	dbus_message_iter_init_append(signal, &entry);

	append_networks(device, &entry);

	g_dbus_send_message(conn, signal);
}

static void append_connections(DBusMessageIter *entry)
{
	DBusMessageIter value, iter;
	const char *key = "Connections";

	dbus_message_iter_append_basic(entry, DBUS_TYPE_STRING, &key);

	dbus_message_iter_open_container(entry, DBUS_TYPE_VARIANT,
		DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_OBJECT_PATH_AS_STRING,
								&value);

	dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY,
				DBUS_TYPE_OBJECT_PATH_AS_STRING, &iter);
	__connman_element_list(NULL, CONNMAN_ELEMENT_TYPE_CONNECTION, &iter);
	dbus_message_iter_close_container(&value, &iter);

	dbus_message_iter_close_container(entry, &value);
}

static void emit_connections_signal(DBusConnection *conn)
{
	DBusMessage *signal;
	DBusMessageIter entry;

	DBG("conn %p", conn);

	signal = dbus_message_new_signal(CONNMAN_MANAGER_PATH,
				CONNMAN_MANAGER_INTERFACE, "PropertyChanged");
	if (signal == NULL)
		return;

	dbus_message_iter_init_append(signal, &entry);

	append_connections(&entry);

	g_dbus_send_message(conn, signal);
}

static void append_state(DBusMessageIter *entry, const char *state)
{
	DBusMessageIter value;
	const char *key = "State";

	dbus_message_iter_append_basic(entry, DBUS_TYPE_STRING, &key);

	dbus_message_iter_open_container(entry, DBUS_TYPE_VARIANT,
					DBUS_TYPE_STRING_AS_STRING, &value);
	dbus_message_iter_append_basic(&value, DBUS_TYPE_STRING, &state);
	dbus_message_iter_close_container(entry, &value);
}

static void emit_state_change(DBusConnection *conn, const char *state)
{
	DBusMessage *signal;
	DBusMessageIter entry;

	DBG("conn %p", conn);

	signal = dbus_message_new_signal(CONNMAN_MANAGER_PATH,
				CONNMAN_MANAGER_INTERFACE, "PropertyChanged");
	if (signal == NULL)
		return;

	dbus_message_iter_init_append(signal, &entry);

	append_state(&entry, state);

	g_dbus_send_message(conn, signal);
}

static void set_signal_strength(struct connman_element *connection)
{
	struct connman_element *element = connection;

	while (element != NULL) {
		if (element->type == CONNMAN_ELEMENT_TYPE_NETWORK) {
			connection->strength = element->strength;
			break;
		}

		element = element->parent;
	}
}

static void register_element(gpointer data, gpointer user_data)
{
	struct connman_element *element = data;
	const gchar *basepath;
	GSList *list;
	GNode *node;

	__connman_element_lock(element);

	if (element->parent) {
		node = g_node_find(element_root, G_PRE_ORDER,
					G_TRAVERSE_ALL, element->parent);
		basepath = element->parent->path;

		if (element->subtype == CONNMAN_ELEMENT_SUBTYPE_UNKNOWN)
			element->subtype = element->parent->subtype;
	} else {
		element->parent = element_root->data;

		node = element_root;
		basepath = "";
	}

	element->path = g_strdup_printf("%s/%s", basepath, element->name);

	set_reference_properties(element);

	__connman_element_unlock(element);

	DBG("element %p path %s", element, element->path);

	__connman_element_load(element);

	g_node_append_data(node, element);

	if (element->type == CONNMAN_ELEMENT_TYPE_DEVICE &&
			element->subtype != CONNMAN_ELEMENT_SUBTYPE_NETWORK) {
		if (g_dbus_register_interface(connection, element->path,
					CONNMAN_DEVICE_INTERFACE,
					device_methods, element_signals,
					NULL, element, NULL) == FALSE)
			connman_error("Failed to register %s device",
								element->path);
		else
			emit_devices_signal(connection);
	}

	if (element->type == CONNMAN_ELEMENT_TYPE_NETWORK) {
		if (g_dbus_register_interface(connection, element->path,
					CONNMAN_NETWORK_INTERFACE,
					network_methods, element_signals,
					NULL, element, NULL) == FALSE)
			connman_error("Failed to register %s network",
								element->path);
		else
			emit_networks_signal(connection, element->parent);
	}

	if (element->type == CONNMAN_ELEMENT_TYPE_CONNECTION) {
		if (g_dbus_register_interface(connection, element->path,
					CONNMAN_CONNECTION_INTERFACE,
					connection_methods, element_signals,
					NULL, element, NULL) == FALSE)
			connman_error("Failed to register %s connection",
								element->path);
		else {
			set_signal_strength(element);
			emit_connections_signal(connection);
			emit_state_change(connection, "online");
		}
	}

	__connman_element_store(element);

	for (list = driver_list; list; list = list->next) {
		struct connman_driver *driver = list->data;

		if (match_driver(element, driver) == FALSE)
			continue;

		DBG("driver %p name %s", driver, driver->name);

		if (driver->probe(element) == 0) {
			__connman_element_lock(element);
			element->driver = driver;
			__connman_element_unlock(element);

			enable_element(element);
			break;
		}
	}
}

/**
 * connman_element_register:
 * @element: the element to register
 * @parent: the parent to register the element with
 *
 * Register an element with the core. It will be register under the given
 * parent of if %NULL is provided under the root element.
 *
 * Returns: %0 on success
 */
int connman_element_register(struct connman_element *element,
					struct connman_element *parent)
{
	DBG("element %p name %s parent %p", element, element->name, parent);

	if (element->devname == NULL)
		element->devname = g_strdup(element->name);

	if (device_filter && element->type == CONNMAN_ELEMENT_TYPE_DEVICE &&
			element->subtype != CONNMAN_ELEMENT_SUBTYPE_NETWORK) {
		if (g_pattern_match_simple(device_filter,
						element->devname) == FALSE) {
			DBG("ignoring %s [%s] device", element->name,
							element->devname);
			return -EPERM;
		}
	}

	if (connman_element_ref(element) == NULL)
		return -EINVAL;

	__connman_element_lock(element);

	if (element->name == NULL) {
		element->name = g_strdup(type2string(element->type));
		if (element->name == NULL) {
			__connman_element_unlock(element);
			return -EINVAL;
		}
	}

	element->parent = parent;

	__connman_element_unlock(element);

	register_element(element, NULL);

	return 0;
}

static gboolean remove_element(GNode *node, gpointer user_data)
{
	struct connman_element *element = node->data;
	struct connman_element *root = user_data;

	DBG("element %p name %s", element, element->name);

	if (element == root)
		return FALSE;

	if (element->driver) {
		disable_element(element);

		if (element->driver->remove)
			element->driver->remove(element);

		__connman_element_lock(element);
		element->driver = NULL;
		__connman_element_unlock(element);
	}

	if (node != NULL) {
		g_node_unlink(node);
		g_node_destroy(node);
	}

	if (element->type == CONNMAN_ELEMENT_TYPE_CONNECTION) {
		if (__connman_element_count(NULL,
					CONNMAN_ELEMENT_TYPE_CONNECTION) == 0)
			emit_state_change(connection, "offline");
		emit_connections_signal(connection);

		g_dbus_unregister_interface(connection, element->path,
						CONNMAN_CONNECTION_INTERFACE);
	}

	if (element->type == CONNMAN_ELEMENT_TYPE_NETWORK) {
		emit_networks_signal(connection, element->parent);

		g_dbus_unregister_interface(connection, element->path,
						CONNMAN_NETWORK_INTERFACE);
	}

	if (element->type == CONNMAN_ELEMENT_TYPE_DEVICE &&
			element->subtype != CONNMAN_ELEMENT_SUBTYPE_NETWORK) {
		emit_devices_signal(connection);

		g_dbus_unregister_interface(connection, element->path,
						CONNMAN_DEVICE_INTERFACE);
	}

	connman_element_unref(element);

	return FALSE;
}

void connman_element_unregister(struct connman_element *element)
{
	GNode *node;

	DBG("element %p name %s", element, element->name);

	node = g_node_find(element_root, G_PRE_ORDER, G_TRAVERSE_ALL, element);

	if (node != NULL)
		g_node_traverse(node, G_POST_ORDER,
				G_TRAVERSE_ALL, -1, remove_element, NULL);
}

void connman_element_unregister_children(struct connman_element *element)
{
	GNode *node;

	DBG("element %p name %s", element, element->name);

	node = g_node_find(element_root, G_PRE_ORDER, G_TRAVERSE_ALL, element);

	if (node != NULL)
		g_node_traverse(node, G_POST_ORDER,
				G_TRAVERSE_ALL, -1, remove_element, element);
}

static gboolean update_element(GNode *node, gpointer user_data)
{
	struct connman_element *element = node->data;
	struct connman_element *root = user_data;

	DBG("element %p name %s", element, element->name);

	if (element->driver && element->driver->update)
		element->driver->update(element);

	if (element->type == CONNMAN_ELEMENT_TYPE_CONNECTION &&
				root->type == CONNMAN_ELEMENT_TYPE_NETWORK) {
		if (element->strength != root->strength) {
			element->strength = root->strength;
			emit_property_changed(connection, element, "Strength",
					DBUS_TYPE_BYTE, &element->strength);
		}
	}

	return FALSE;
}

void connman_element_update(struct connman_element *element)
{
	GNode *node;

	DBG("element %p name %s", element, element->name);

	node = g_node_find(element_root, G_PRE_ORDER, G_TRAVERSE_ALL, element);

	if (node != NULL)
		g_node_traverse(node, G_PRE_ORDER,
				G_TRAVERSE_ALL, -1, update_element, element);
}

int connman_element_set_enabled(struct connman_element *element,
							gboolean enabled)
{
	if (element->enabled == enabled)
		return 0;

	element->enabled = enabled;

	emit_enabled_signal(connection, element);

	return 0;
}

int connman_element_set_scanning(struct connman_element *element,
							gboolean scanning)
{
	if (element->scanning == scanning)
		return 0;

	element->scanning = scanning;

	emit_scanning_signal(connection, element);

	return 0;
}

int __connman_element_init(DBusConnection *conn, const char *device)
{
	struct connman_element *element;

	DBG("conn %p", conn);

	connection = dbus_connection_ref(conn);
	if (connection == NULL)
		return -EIO;

	device_filter = g_strdup(device);

	element = connman_element_create("root");

	element->path = g_strdup("/");
	element->type = CONNMAN_ELEMENT_TYPE_ROOT;

	create_default_properties(element);

	element_root = g_node_new(element);

	__connman_device_init();

	return 0;
}

static gboolean free_driver(GNode *node, gpointer data)
{
	struct connman_element *element = node->data;

	DBG("element %p name %s", element, element->name);

	if (element->driver) {
		disable_element(element);

		if (element->driver->remove)
			element->driver->remove(element);

		__connman_element_lock(element);
		element->driver = NULL;
		__connman_element_unlock(element);
	}

	return FALSE;
}

static gboolean free_node(GNode *node, gpointer data)
{
	struct connman_element *element = node->data;

	DBG("element %p name %s", element, element->name);

	if (g_node_depth(node) > 1)
		connman_element_unregister(element);

	return FALSE;
}

void __connman_element_cleanup(void)
{
	DBG("");

	__connman_device_cleanup();

	g_node_traverse(element_root, G_POST_ORDER, G_TRAVERSE_ALL, -1,
							free_driver, NULL);

	g_node_traverse(element_root, G_POST_ORDER, G_TRAVERSE_ALL, -1,
							free_node, NULL);

	g_node_destroy(element_root);
	element_root = NULL;

	g_free(device_filter);

	dbus_connection_unref(connection);
}
