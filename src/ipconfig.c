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

#include <net/if.h>
#include <net/if_arp.h>

#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP	0x10000
#endif

#include <gdbus.h>

#include "connman.h"

struct connman_ipaddress {
	unsigned char prefixlen;
	char *address;
};

struct connman_ipdevice {
	int index;
	char *ifname;
	unsigned short type;
	unsigned int flags;

	GSList *address_list;
	char *gateway;
};

struct connman_ipconfig {
	gint refcount;
	int index;

	const struct connman_ipconfig_ops *ops;
	void *ops_data;

	enum connman_ipconfig_method method;
};

static GHashTable *ipdevice_hash = NULL;
static GList *ipconfig_list = NULL;

static void free_address_list(struct connman_ipdevice *ipdevice)
{
	GSList *list;

	for (list = ipdevice->address_list; list; list = list->next) {
		struct connman_ipaddress *ipaddress = list->data;

		g_free(ipaddress->address);
		g_free(ipaddress);
		list->data = NULL;
	}

	g_slist_free(ipdevice->address_list);
	ipdevice->address_list = NULL;
}

static struct connman_ipaddress *find_ipaddress(struct connman_ipdevice *ipdevice,
				unsigned char prefixlen, const char *address)
{
	GSList *list;

	for (list = ipdevice->address_list; list; list = list->next) {
		struct connman_ipaddress *ipaddress = list->data;

		if (g_strcmp0(ipaddress->address, address) == 0 &&
					ipaddress->prefixlen == prefixlen)
			return ipaddress;
	}

	return NULL;
}

static const char *type2str(unsigned short type)
{
	switch (type) {
	case ARPHRD_ETHER:
		return "ETHER";
	case ARPHRD_LOOPBACK:
		return "LOOPBACK";
	case ARPHRD_PPP:
		return "PPP";
	case ARPHRD_NONE:
		return "NONE";
	case ARPHRD_VOID:
		return "VOID";
	}

	return "";
}

static const char *scope2str(unsigned char scope)
{
	switch (scope) {
	case 0:
		return "UNIVERSE";
	case 253:
		return "LINK";
	}

	return "";
}

static void free_ipdevice(gpointer data)
{
	struct connman_ipdevice *ipdevice = data;

	connman_info("%s {remove} index %d", ipdevice->ifname,
							ipdevice->index);

	free_address_list(ipdevice);
	g_free(ipdevice->gateway);

	g_free(ipdevice->ifname);
	g_free(ipdevice);
}

void __connman_ipconfig_newlink(int index, unsigned short type,
							unsigned int flags)
{
	struct connman_ipdevice *ipdevice;
	GList *list;
	GString *str;
	gboolean up = FALSE, down = FALSE;
	gboolean lower_up = FALSE, lower_down = FALSE;

	DBG("index %d", index);

	ipdevice = g_hash_table_lookup(ipdevice_hash, GINT_TO_POINTER(index));
	if (ipdevice != NULL)
		goto update;

	ipdevice = g_try_new0(struct connman_ipdevice, 1);
	if (ipdevice == NULL)
		return;

	ipdevice->index = index;
	ipdevice->ifname = connman_inet_ifname(index);
	ipdevice->type = type;

	g_hash_table_insert(ipdevice_hash, GINT_TO_POINTER(index), ipdevice);

	connman_info("%s {create} index %d type %d <%s>", ipdevice->ifname,
						index, type, type2str(type));

update:
	if (flags == ipdevice->flags)
		return;

	if ((ipdevice->flags & IFF_UP) != (flags & IFF_UP)) {
		if (flags & IFF_UP)
			up = TRUE;
		else
			down = TRUE;
	}

	if ((ipdevice->flags & (IFF_RUNNING | IFF_LOWER_UP)) !=
				(flags & (IFF_RUNNING | IFF_LOWER_UP))) {
		if ((flags & (IFF_RUNNING | IFF_LOWER_UP)) ==
					(IFF_RUNNING | IFF_LOWER_UP))
			lower_up = TRUE;
		else if ((flags & (IFF_RUNNING | IFF_LOWER_UP)) == 0)
			lower_down = TRUE;
	}

	ipdevice->flags = flags;

	str = g_string_new(NULL);
	if (str == NULL)
		return;

	if (flags & IFF_UP)
		g_string_append(str, "UP");
	else
		g_string_append(str, "DOWN");

	if (flags & IFF_RUNNING)
		g_string_append(str, ",RUNNING");

	if (flags & IFF_LOWER_UP)
		g_string_append(str, ",LOWER_UP");

	connman_info("%s {update} flags %u <%s>", ipdevice->ifname,
							flags, str->str);

	g_string_free(str, TRUE);

	for (list = g_list_first(ipconfig_list); list;
						list = g_list_next(list)) {
		struct connman_ipconfig *ipconfig = list->data;

		if (index != ipconfig->index)
			continue;

		if (ipconfig->ops) {
			if (up == TRUE && ipconfig->ops->up)
				ipconfig->ops->up(ipconfig);
			if (lower_up == TRUE && ipconfig->ops->lower_up)
				ipconfig->ops->lower_up(ipconfig);

			if (lower_down == TRUE && ipconfig->ops->lower_down)
				ipconfig->ops->lower_down(ipconfig);
			if (down == TRUE && ipconfig->ops->down)
				ipconfig->ops->down(ipconfig);
		}
	}
}

void __connman_ipconfig_dellink(int index)
{
	GList *list;

	DBG("index %d", index);

	for (list = g_list_first(ipconfig_list); list;
						list = g_list_next(list)) {
		struct connman_ipconfig *ipconfig = list->data;

		if (index != ipconfig->index)
			continue;

		ipconfig->index = -1;

		if (ipconfig->ops && ipconfig->ops->lower_down)
			ipconfig->ops->lower_down(ipconfig);
		if (ipconfig->ops && ipconfig->ops->down)
			ipconfig->ops->down(ipconfig);
	}

	g_hash_table_remove(ipdevice_hash, GINT_TO_POINTER(index));
}

void __connman_ipconfig_newaddr(int index, const char *label,
				unsigned char prefixlen, const char *address)
{
	struct connman_ipdevice *ipdevice;
	struct connman_ipaddress *ipaddress;

	DBG("index %d", index);

	ipdevice = g_hash_table_lookup(ipdevice_hash, GINT_TO_POINTER(index));
	if (ipdevice == NULL)
		return;

	ipaddress = g_try_new0(struct connman_ipaddress, 1);
	if (ipaddress == NULL)
		return;

	ipaddress->prefixlen = prefixlen;
	ipaddress->address = g_strdup(address);

	ipdevice->address_list = g_slist_append(ipdevice->address_list,
								ipaddress);

	connman_info("%s {add} address %s/%u label %s", ipdevice->ifname,
						address, prefixlen, label);
}

void __connman_ipconfig_deladdr(int index, const char *label,
				unsigned char prefixlen, const char *address)
{
	struct connman_ipdevice *ipdevice;
	struct connman_ipaddress *ipaddress;

	DBG("index %d", index);

	ipdevice = g_hash_table_lookup(ipdevice_hash, GINT_TO_POINTER(index));
	if (ipdevice == NULL)
		return;

	ipaddress = find_ipaddress(ipdevice, prefixlen, address);
	if (ipaddress == NULL)
		return;

	ipdevice->address_list = g_slist_remove(ipdevice->address_list,
								ipaddress);

	g_free(ipaddress->address);
	g_free(ipaddress);

	connman_info("%s {del} address %s/%u label %s", ipdevice->ifname,
						address, prefixlen, label);
}

void __connman_ipconfig_newroute(int index, unsigned char scope,
					const char *dst, const char *gateway)
{
	struct connman_ipdevice *ipdevice;

	DBG("index %d", index);

	ipdevice = g_hash_table_lookup(ipdevice_hash, GINT_TO_POINTER(index));
	if (ipdevice == NULL)
		return;

	if (scope == 0 && g_strcmp0(dst, "0.0.0.0") == 0) {
		g_free(ipdevice->gateway);
		ipdevice->gateway = g_strdup(gateway);
	}

	connman_info("%s {add} route %s gw %s scope %u <%s>",
					ipdevice->ifname, dst, gateway,
						scope, scope2str(scope));
}

void __connman_ipconfig_delroute(int index, unsigned char scope,
					const char *dst, const char *gateway)
{
	struct connman_ipdevice *ipdevice;

	DBG("index %d", index);

	ipdevice = g_hash_table_lookup(ipdevice_hash, GINT_TO_POINTER(index));
	if (ipdevice == NULL)
		return;

	if (scope == 0 && g_strcmp0(dst, "0.0.0.0") == 0) {
		g_free(ipdevice->gateway);
		ipdevice->gateway = NULL;
	}

	connman_info("%s {del} route %s gw %s scope %u <%s>",
					ipdevice->ifname, dst, gateway,
						scope, scope2str(scope));
}

void __connman_ipconfig_foreach(void (*function) (int index, void *user_data),
							void *user_data)
{
	GList *list, *keys;

	keys = g_hash_table_get_keys(ipdevice_hash);
	if (keys == NULL)
		return;

	for (list = g_list_first(keys); list; list = g_list_next(list)) {
		int index = GPOINTER_TO_INT(list->data);

		function(index, user_data);
	}

	g_list_free(keys);
}

unsigned short __connman_ipconfig_get_type(int index)
{
	struct connman_ipdevice *ipdevice;

	ipdevice = g_hash_table_lookup(ipdevice_hash, GINT_TO_POINTER(index));
	if (ipdevice == NULL)
		return ARPHRD_VOID;

	return ipdevice->type;
}

unsigned int __connman_ipconfig_get_flags(int index)
{
	struct connman_ipdevice *ipdevice;

	ipdevice = g_hash_table_lookup(ipdevice_hash, GINT_TO_POINTER(index));
	if (ipdevice == NULL)
		return 0;

	return ipdevice->flags;
}

const char *__connman_ipconfig_get_gateway(int index)
{
	struct connman_ipdevice *ipdevice;

	ipdevice = g_hash_table_lookup(ipdevice_hash, GINT_TO_POINTER(index));
	if (ipdevice == NULL)
		return NULL;

	return ipdevice->gateway;
}

/**
 * connman_ipconfig_create:
 *
 * Allocate a new ipconfig structure.
 *
 * Returns: a newly-allocated #connman_ipconfig structure
 */
struct connman_ipconfig *connman_ipconfig_create(int index)
{
	struct connman_ipconfig *ipconfig;

	DBG("index %d", index);

	ipconfig = g_try_new0(struct connman_ipconfig, 1);
	if (ipconfig == NULL)
		return NULL;

	ipconfig->refcount = 1;

	ipconfig->index = index;

	DBG("ipconfig %p", ipconfig);

	ipconfig_list = g_list_append(ipconfig_list, ipconfig);

	return ipconfig;
}

/**
 * connman_ipconfig_ref:
 * @ipconfig: ipconfig structure
 *
 * Increase reference counter of ipconfig
 */
struct connman_ipconfig *connman_ipconfig_ref(struct connman_ipconfig *ipconfig)
{
	g_atomic_int_inc(&ipconfig->refcount);

	return ipconfig;
}

/**
 * connman_ipconfig_unref:
 * @ipconfig: ipconfig structure
 *
 * Decrease reference counter of ipconfig
 */
void connman_ipconfig_unref(struct connman_ipconfig *ipconfig)
{
	if (g_atomic_int_dec_and_test(&ipconfig->refcount) == TRUE) {
		ipconfig_list = g_list_remove(ipconfig_list, ipconfig);

		g_free(ipconfig);
	}
}

/**
 * connman_ipconfig_get_data:
 * @ipconfig: ipconfig structure
 *
 * Get private data pointer
 */
void *connman_ipconfig_get_data(struct connman_ipconfig *ipconfig)
{
	return ipconfig->ops_data;
}

/**
 * connman_ipconfig_set_data:
 * @ipconfig: ipconfig structure
 * @data: data pointer
 *
 * Set private data pointer
 */
void connman_ipconfig_set_data(struct connman_ipconfig *ipconfig, void *data)
{
	ipconfig->ops_data = data;
}

/**
 * connman_ipconfig_get_index:
 * @ipconfig: ipconfig structure
 *
 * Get interface index
 */
int connman_ipconfig_get_index(struct connman_ipconfig *ipconfig)
{
	return ipconfig->index;
}

/**
 * connman_ipconfig_get_ifname:
 * @ipconfig: ipconfig structure
 *
 * Get interface name
 */
const char *connman_ipconfig_get_ifname(struct connman_ipconfig *ipconfig)
{
	struct connman_ipdevice *ipdevice;

	if (ipconfig->index < 0)
		return NULL;

	ipdevice = g_hash_table_lookup(ipdevice_hash,
					GINT_TO_POINTER(ipconfig->index));
	if (ipdevice == NULL)
		return NULL;

	return ipdevice->ifname;
}

/**
 * connman_ipconfig_set_ops:
 * @ipconfig: ipconfig structure
 * @ops: operation callbacks
 *
 * Set the operation callbacks
 */
void connman_ipconfig_set_ops(struct connman_ipconfig *ipconfig,
				const struct connman_ipconfig_ops *ops)
{
	ipconfig->ops = ops;
}

/**
 * connman_ipconfig_set_method:
 * @ipconfig: ipconfig structure
 * @method: configuration method
 *
 * Set the configuration method
 */
int connman_ipconfig_set_method(struct connman_ipconfig *ipconfig,
					enum connman_ipconfig_method method)
{
	ipconfig->method = method;

	return 0;
}

const char *__connman_ipconfig_method2string(enum connman_ipconfig_method method)
{
	switch (method) {
	case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
		break;
	case CONNMAN_IPCONFIG_METHOD_IGNORE:
		return "ignore";
	case CONNMAN_IPCONFIG_METHOD_STATIC:
		return "static";
	case CONNMAN_IPCONFIG_METHOD_DHCP:
		return "dhcp";
	}

	return NULL;
}

enum connman_ipconfig_method __connman_ipconfig_string2method(const char *method)
{
	if (g_strcmp0(method, "ignore") == 0)
		return CONNMAN_IPCONFIG_METHOD_IGNORE;
	else if (g_strcmp0(method, "static") == 0)
		return CONNMAN_IPCONFIG_METHOD_STATIC;
	else if (g_strcmp0(method, "dhcp") == 0)
		return CONNMAN_IPCONFIG_METHOD_DHCP;
	else
		return CONNMAN_IPCONFIG_METHOD_UNKNOWN;
}

static void append_variant(DBusMessageIter *iter, const char *prefix,
					const char *key, int type, void *val)
{
	char *str;

	if (prefix == NULL) {
		connman_dbus_dict_append_variant(iter, key, type, val);
		return;
	}

	str = g_strdup_printf("%s%s", prefix, key);
	if (str != NULL)
		connman_dbus_dict_append_variant(iter, str, type, val);

	g_free(str);
}

void __connman_ipconfig_append_ipv4(struct connman_ipconfig *ipconfig,
				DBusMessageIter *iter, const char *prefix)
{
	const char *str;

	str = __connman_ipconfig_method2string(ipconfig->method);
	if (str == NULL)
		return;

	append_variant(iter, prefix, "Method", DBUS_TYPE_STRING, &str);
}

int __connman_ipconfig_set_ipv4(struct connman_ipconfig *ipconfig,
				const char *key, DBusMessageIter *value)
{
	int type = dbus_message_iter_get_arg_type(value);

	DBG("ipconfig %p key %s type %d", ipconfig, key, type);

	if (g_strcmp0(key, "Method") == 0) {
		const char *method;

		if (type != DBUS_TYPE_STRING)
			return -EINVAL;

		dbus_message_iter_get_basic(value, &method);

		ipconfig->method = __connman_ipconfig_string2method(method);
	} else
		return -EINVAL;

	return 0;
}

int __connman_ipconfig_load(struct connman_ipconfig *ipconfig,
		GKeyFile *keyfile, const char *identifier, const char *prefix)
{
	DBG("ipconfig %p identifier %s", ipconfig, identifier);

	return 0;
}

int __connman_ipconfig_save(struct connman_ipconfig *ipconfig,
		GKeyFile *keyfile, const char *identifier, const char *prefix)
{
	DBG("ipconfig %p identifier %s", ipconfig, identifier);

	return 0;
}

static GSList *driver_list = NULL;

static gint compare_priority(gconstpointer a, gconstpointer b)
{
	const struct connman_ipconfig_driver *driver1 = a;
	const struct connman_ipconfig_driver *driver2 = b;

	return driver2->priority - driver1->priority;
}

/**
 * connman_ipconfig_driver_register:
 * @driver: IP configuration driver
 *
 * Register a new IP configuration driver
 *
 * Returns: %0 on success
 */
int connman_ipconfig_driver_register(struct connman_ipconfig_driver *driver)
{
	DBG("driver %p name %s", driver, driver->name);

	driver_list = g_slist_insert_sorted(driver_list, driver,
							compare_priority);

	return 0;
}

/**
 * connman_ipconfig_driver_unregister:
 * @driver: IP configuration driver
 *
 * Remove a previously registered IP configuration driver.
 */
void connman_ipconfig_driver_unregister(struct connman_ipconfig_driver *driver)
{
	DBG("driver %p name %s", driver, driver->name);

	driver_list = g_slist_remove(driver_list, driver);
}

int __connman_ipconfig_init(void)
{
	DBG("");

	ipdevice_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal,
							NULL, free_ipdevice);

	return 0;
}

void __connman_ipconfig_cleanup(void)
{
	DBG("");

	g_hash_table_destroy(ipdevice_hash);
	ipdevice_hash = NULL;
}
