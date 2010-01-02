/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2010  Intel Corporation. All rights reserved.
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

struct connman_ipconfig {
	gint refcount;
	int index;

	struct connman_ipconfig *origin;

	const struct connman_ipconfig_ops *ops;
	void *ops_data;

	enum connman_ipconfig_method method;
	struct connman_ipaddress *address;
	struct connman_ipaddress *system;

	char *eth;
	uint16_t mtu;
};

struct connman_ipdevice {
	int index;
	char *ifname;
	unsigned short type;
	unsigned int flags;

	GSList *address_list;
	char *gateway;

	struct connman_ipconfig *config;

	struct connman_ipconfig_driver *driver;
	struct connman_ipconfig *driver_config;
};

static GHashTable *ipdevice_hash = NULL;
static GList *ipconfig_list = NULL;

struct connman_ipaddress *connman_ipaddress_alloc(void)
{
	struct connman_ipaddress *ipaddress;

	ipaddress = g_try_new0(struct connman_ipaddress, 1);
	if (ipaddress == NULL)
		return NULL;

	return ipaddress;
}

void connman_ipaddress_free(struct connman_ipaddress *ipaddress)
{
	if (ipaddress == NULL)
		return;

	g_free(ipaddress->broadcast);
	g_free(ipaddress->peer);
	g_free(ipaddress->local);
	g_free(ipaddress);
}

static unsigned char netmask2prefixlen(const char *netmask)
{
	unsigned char bits = 0;
	in_addr_t mask = inet_network(netmask);
	in_addr_t host = ~mask;

	/* a valid netmask must be 2^n - 1 */
	if ((host & (host + 1)) != 0)
		return -1;

	for (; mask; mask <<= 1)
		++bits;

	return bits;
}

void connman_ipaddress_set(struct connman_ipaddress *ipaddress,
				const char *address, const char *netmask)
{
	if (ipaddress == NULL)
		return;

	if (netmask != NULL)
		ipaddress->prefixlen = netmask2prefixlen(netmask);
	else
		ipaddress->prefixlen = 32;

	g_free(ipaddress->local);
	ipaddress->local = g_strdup(address);
}

void connman_ipaddress_clear(struct connman_ipaddress *ipaddress)
{
	if (ipaddress == NULL)
		return;

	ipaddress->prefixlen = 0;

	g_free(ipaddress->local);
	ipaddress->local = NULL;

	g_free(ipaddress->peer);
	ipaddress->peer = NULL;

	g_free(ipaddress->broadcast);
	ipaddress->broadcast = NULL;
}

void connman_ipaddress_copy(struct connman_ipaddress *ipaddress,
					struct connman_ipaddress *source)
{
	if (ipaddress == NULL || source == NULL)
		return;

	ipaddress->prefixlen = source->prefixlen;

	g_free(ipaddress->local);
	ipaddress->local = g_strdup(source->local);

	g_free(ipaddress->peer);
	ipaddress->peer = g_strdup(source->peer);

	g_free(ipaddress->broadcast);
	ipaddress->broadcast = g_strdup(source->broadcast);
}

static void free_address_list(struct connman_ipdevice *ipdevice)
{
	GSList *list;

	for (list = ipdevice->address_list; list; list = list->next) {
		struct connman_ipaddress *ipaddress = list->data;

		connman_ipaddress_free(ipaddress);
		list->data = NULL;
	}

	g_slist_free(ipdevice->address_list);
	ipdevice->address_list = NULL;
}

static struct connman_ipaddress *find_ipaddress(struct connman_ipdevice *ipdevice,
				unsigned char prefixlen, const char *local)
{
	GSList *list;

	for (list = ipdevice->address_list; list; list = list->next) {
		struct connman_ipaddress *ipaddress = list->data;

		if (g_strcmp0(ipaddress->local, local) == 0 &&
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

	if (ipdevice->config != NULL)
		connman_ipconfig_unref(ipdevice->config);

	free_address_list(ipdevice);
	g_free(ipdevice->gateway);

	g_free(ipdevice->ifname);
	g_free(ipdevice);
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

static void __connman_ipconfig_lower_up(struct connman_ipdevice *ipdevice)
{
	GSList *list;

	DBG("ipconfig %p", ipdevice->config);

	if (ipdevice->config == NULL)
		return;

	switch (ipdevice->config->method) {
	case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
	case CONNMAN_IPCONFIG_METHOD_OFF:
	case CONNMAN_IPCONFIG_METHOD_FIXED:
	case CONNMAN_IPCONFIG_METHOD_MANUAL:
		return;
	case CONNMAN_IPCONFIG_METHOD_DHCP:
		break;
	}

	if (ipdevice->driver != NULL)
		return;

	ipdevice->driver_config = connman_ipconfig_clone(ipdevice->config);
	if (ipdevice->driver_config == NULL)
		return;

	for (list = driver_list; list; list = list->next) {
		struct connman_ipconfig_driver *driver = list->data;

		if (driver->request(ipdevice->driver_config) == 0) {
			ipdevice->driver = driver;
			break;
		}
	}

	if (ipdevice->driver == NULL) {
		connman_ipconfig_unref(ipdevice->driver_config);
		ipdevice->driver_config = NULL;
	}
}

static void __connman_ipconfig_lower_down(struct connman_ipdevice *ipdevice)
{
	DBG("ipconfig %p", ipdevice->config);

	if (ipdevice->config == NULL)
		return;

	if (ipdevice->driver == NULL)
		return;

	ipdevice->driver->release(ipdevice->driver_config);

	ipdevice->driver = NULL;

	connman_ipconfig_unref(ipdevice->driver_config);
	ipdevice->driver_config = NULL;

	connman_inet_clear_address(ipdevice->index);
}

void __connman_ipconfig_newlink(int index, unsigned short type,
				unsigned int flags, const char *address,
							unsigned short mtu)
{
	struct connman_ipdevice *ipdevice;
	GList *list;
	GString *str;
	gboolean up = FALSE, down = FALSE;
	gboolean lower_up = FALSE, lower_down = FALSE;
	char *ifname;

	DBG("index %d", index);

	if (type == ARPHRD_LOOPBACK)
		return;

	ipdevice = g_hash_table_lookup(ipdevice_hash, GINT_TO_POINTER(index));
	if (ipdevice != NULL)
		goto update;

	ifname = connman_inet_ifname(index);

	if (__connman_element_device_isfiltered(ifname) == TRUE) {
		connman_info("Ignoring interface %s (filtered)", ifname);
		g_free(ifname);
		return;
	}

	ipdevice = g_try_new0(struct connman_ipdevice, 1);
	if (ipdevice == NULL) {
		g_free(ifname);
		return;
	}

	ipdevice->index = index;
	ipdevice->ifname = ifname;
	ipdevice->type = type;

	g_hash_table_insert(ipdevice_hash, GINT_TO_POINTER(index), ipdevice);

	connman_info("%s {create} index %d type %d <%s>", ipdevice->ifname,
						index, type, type2str(type));

update:
	if (ipdevice->config != NULL) {
		g_free(ipdevice->config->eth);
		ipdevice->config->eth = g_strdup(address);
		ipdevice->config->mtu = mtu;
	}

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

		if (ipconfig->ops == NULL)
			continue;

		if (up == TRUE && ipconfig->ops->up)
			ipconfig->ops->up(ipconfig);
		if (lower_up == TRUE && ipconfig->ops->lower_up)
			ipconfig->ops->lower_up(ipconfig);

		if (lower_down == TRUE && ipconfig->ops->lower_down)
			ipconfig->ops->lower_down(ipconfig);
		if (down == TRUE && ipconfig->ops->down)
			ipconfig->ops->down(ipconfig);
	}

	if (lower_up)
		__connman_ipconfig_lower_up(ipdevice);
	if (lower_down)
		__connman_ipconfig_lower_down(ipdevice);
}

void __connman_ipconfig_dellink(int index)
{
	struct connman_ipdevice *ipdevice;
	GList *list;

	DBG("index %d", index);

	ipdevice = g_hash_table_lookup(ipdevice_hash, GINT_TO_POINTER(index));
	if (ipdevice == NULL)
		return;

	for (list = g_list_first(ipconfig_list); list;
						list = g_list_next(list)) {
		struct connman_ipconfig *ipconfig = list->data;

		if (index != ipconfig->index)
			continue;

		ipconfig->index = -1;

		if (ipconfig->ops == NULL)
			continue;

		if (ipconfig->ops->lower_down)
			ipconfig->ops->lower_down(ipconfig);
		if (ipconfig->ops->down)
			ipconfig->ops->down(ipconfig);
	}

	__connman_ipconfig_lower_down(ipdevice);

	g_hash_table_remove(ipdevice_hash, GINT_TO_POINTER(index));
}

void __connman_ipconfig_newaddr(int index, const char *label,
				unsigned char prefixlen, const char *address)
{
	struct connman_ipdevice *ipdevice;
	struct connman_ipaddress *ipaddress;
	GList *list;

	DBG("index %d", index);

	ipdevice = g_hash_table_lookup(ipdevice_hash, GINT_TO_POINTER(index));
	if (ipdevice == NULL)
		return;

	ipaddress = connman_ipaddress_alloc();
	if (ipaddress == NULL)
		return;

	ipaddress->prefixlen = prefixlen;
	ipaddress->local = g_strdup(address);

	ipdevice->address_list = g_slist_append(ipdevice->address_list,
								ipaddress);

	connman_info("%s {add} address %s/%u label %s", ipdevice->ifname,
						address, prefixlen, label);

	if (ipdevice->config != NULL)
		connman_ipaddress_copy(ipdevice->config->system, ipaddress);

	if ((ipdevice->flags & (IFF_RUNNING | IFF_LOWER_UP)) != (IFF_RUNNING | IFF_LOWER_UP))
		return;

	if (g_slist_length(ipdevice->address_list) > 1)
		return;

	for (list = g_list_first(ipconfig_list); list;
						list = g_list_next(list)) {
		struct connman_ipconfig *ipconfig = list->data;

		if (index != ipconfig->index)
			continue;

		if (ipconfig->ops == NULL)
			continue;

		if (ipconfig->ops->ip_bound)
			ipconfig->ops->ip_bound(ipconfig);
	}
}

void __connman_ipconfig_deladdr(int index, const char *label,
				unsigned char prefixlen, const char *address)
{
	struct connman_ipdevice *ipdevice;
	struct connman_ipaddress *ipaddress;
	GList *list;

	DBG("index %d", index);

	ipdevice = g_hash_table_lookup(ipdevice_hash, GINT_TO_POINTER(index));
	if (ipdevice == NULL)
		return;

	ipaddress = find_ipaddress(ipdevice, prefixlen, address);
	if (ipaddress == NULL)
		return;

	ipdevice->address_list = g_slist_remove(ipdevice->address_list,
								ipaddress);

	connman_ipaddress_free(ipaddress);

	connman_info("%s {del} address %s/%u label %s", ipdevice->ifname,
						address, prefixlen, label);

	if ((ipdevice->flags & (IFF_RUNNING | IFF_LOWER_UP)) != (IFF_RUNNING | IFF_LOWER_UP))
		return;

	if (g_slist_length(ipdevice->address_list) > 0)
		return;

	for (list = g_list_first(ipconfig_list); list;
						list = g_list_next(list)) {
		struct connman_ipconfig *ipconfig = list->data;

		if (index != ipconfig->index)
			continue;

		if (ipconfig->ops == NULL)
			continue;

		if (ipconfig->ops->ip_release)
			ipconfig->ops->ip_release(ipconfig);
	}
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

	ipconfig->address = connman_ipaddress_alloc();
	if (ipconfig->address == NULL) {
		g_free(ipconfig);
		return NULL;
	}

	ipconfig->system = connman_ipaddress_alloc();

	DBG("ipconfig %p", ipconfig);

	return ipconfig;
}

/**
 * connman_ipconfig_clone:
 *
 * Clone an ipconfig structure and create new reference.
 *
 * Returns: a newly-allocated #connman_ipconfig structure
 */
struct connman_ipconfig *connman_ipconfig_clone(struct connman_ipconfig *ipconfig)
{
	struct connman_ipconfig *ipconfig_clone;

	DBG("ipconfig %p", ipconfig);

	ipconfig_clone = g_try_new0(struct connman_ipconfig, 1);
	if (ipconfig_clone == NULL)
		return NULL;

	ipconfig_clone->refcount = 1;

	ipconfig_clone->origin = connman_ipconfig_ref(ipconfig);

	ipconfig_clone->index = -1;

	return ipconfig_clone;
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
		__connman_ipconfig_disable(ipconfig);

		connman_ipconfig_set_ops(ipconfig, NULL);

		if (ipconfig->origin != NULL) {
			connman_ipconfig_unref(ipconfig->origin);
			ipconfig->origin = NULL;
		}

		connman_ipaddress_free(ipconfig->system);
		connman_ipaddress_free(ipconfig->address);
		g_free(ipconfig->eth);
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
	if (ipconfig->origin != NULL)
		return ipconfig->origin->index;

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

/**
 * connman_ipconfig_bind:
 * @ipconfig: ipconfig structure
 * @ipaddress: ipaddress structure
 *
 * Bind IP address details to configuration
 */
void connman_ipconfig_bind(struct connman_ipconfig *ipconfig,
					struct connman_ipaddress *ipaddress)
{
	struct connman_ipconfig *origin;

	origin = ipconfig->origin ? ipconfig->origin : ipconfig;

	connman_ipaddress_copy(origin->address, ipaddress);

	connman_inet_set_address(origin->index, origin->address);
}

int __connman_ipconfig_enable(struct connman_ipconfig *ipconfig)
{
	struct connman_ipdevice *ipdevice;

	DBG("ipconfig %p", ipconfig);

	if (ipconfig == NULL || ipconfig->index < 0)
		return -ENODEV;

	ipdevice = g_hash_table_lookup(ipdevice_hash,
					GINT_TO_POINTER(ipconfig->index));
	if (ipdevice == NULL)
		return -ENXIO;

	if (ipdevice->config != NULL) {
		ipconfig_list = g_list_remove(ipconfig_list, ipconfig);

		connman_ipaddress_clear(ipdevice->config->system);

		connman_ipconfig_unref(ipdevice->config);
	}

	ipdevice->config = connman_ipconfig_ref(ipconfig);

	ipconfig_list = g_list_append(ipconfig_list, ipconfig);

	return 0;
}

int __connman_ipconfig_disable(struct connman_ipconfig *ipconfig)
{
	struct connman_ipdevice *ipdevice;

	DBG("ipconfig %p", ipconfig);

	if (ipconfig == NULL || ipconfig->index < 0)
		return -ENODEV;

	ipdevice = g_hash_table_lookup(ipdevice_hash,
					GINT_TO_POINTER(ipconfig->index));
	if (ipdevice == NULL)
		return -ENXIO;

	if (ipdevice->config == NULL || ipdevice->config != ipconfig)
		return -EINVAL;

	ipconfig_list = g_list_remove(ipconfig_list, ipconfig);

	connman_ipaddress_clear(ipdevice->config->system);

	connman_ipconfig_unref(ipdevice->config);
	ipdevice->config = NULL;

	return 0;
}

const char *__connman_ipconfig_method2string(enum connman_ipconfig_method method)
{
	switch (method) {
	case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
		break;
	case CONNMAN_IPCONFIG_METHOD_OFF:
		return "off";
	case CONNMAN_IPCONFIG_METHOD_FIXED:
		return "fixed";
	case CONNMAN_IPCONFIG_METHOD_MANUAL:
		return "manual";
	case CONNMAN_IPCONFIG_METHOD_DHCP:
		return "dhcp";
	}

	return NULL;
}

enum connman_ipconfig_method __connman_ipconfig_string2method(const char *method)
{
	if (g_strcmp0(method, "off") == 0)
		return CONNMAN_IPCONFIG_METHOD_OFF;
	else if (g_strcmp0(method, "fixed") == 0)
		return CONNMAN_IPCONFIG_METHOD_FIXED;
	else if (g_strcmp0(method, "manual") == 0)
		return CONNMAN_IPCONFIG_METHOD_MANUAL;
	else if (g_strcmp0(method, "dhcp") == 0)
		return CONNMAN_IPCONFIG_METHOD_DHCP;
	else
		return CONNMAN_IPCONFIG_METHOD_UNKNOWN;
}

void __connman_ipconfig_append_ipv4(struct connman_ipconfig *ipconfig,
							DBusMessageIter *iter)
{
	const char *str;

	str = __connman_ipconfig_method2string(ipconfig->method);
	if (str == NULL)
		return;

	connman_dbus_dict_append_basic(iter, "Method", DBUS_TYPE_STRING, &str);

	if (ipconfig->system == NULL)
		return;

	if (ipconfig->system->local != NULL) {
		in_addr_t addr;
		struct in_addr netmask;
		char *mask;

		connman_dbus_dict_append_basic(iter, "Address",
				DBUS_TYPE_STRING, &ipconfig->system->local);

		addr = 0xffffffff << (32 - ipconfig->system->prefixlen);
		netmask.s_addr = htonl(addr);
		mask = inet_ntoa(netmask);
		connman_dbus_dict_append_basic(iter, "Netmask",
						DBUS_TYPE_STRING, &mask);
	}
}

void __connman_ipconfig_append_ipv4config(struct connman_ipconfig *ipconfig,
							DBusMessageIter *iter)
{
	const char *str;

	str = __connman_ipconfig_method2string(ipconfig->method);
	if (str == NULL)
		return;

	connman_dbus_dict_append_basic(iter, "Method", DBUS_TYPE_STRING, &str);

	switch (ipconfig->method) {
	case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
	case CONNMAN_IPCONFIG_METHOD_OFF:
	case CONNMAN_IPCONFIG_METHOD_FIXED:
	case CONNMAN_IPCONFIG_METHOD_DHCP:
		return;
	case CONNMAN_IPCONFIG_METHOD_MANUAL:
		break;
	}

	if (ipconfig->address == NULL)
		return;

	if (ipconfig->address->local != NULL) {
		in_addr_t addr;
		struct in_addr netmask;
		char *mask;

		connman_dbus_dict_append_basic(iter, "Address",
				DBUS_TYPE_STRING, &ipconfig->address->local);

		addr = 0xffffffff << (32 - ipconfig->address->prefixlen);
		netmask.s_addr = htonl(addr);
		mask = inet_ntoa(netmask);
		connman_dbus_dict_append_basic(iter, "Netmask",
						DBUS_TYPE_STRING, &mask);
	}
}

int __connman_ipconfig_set_ipv4config(struct connman_ipconfig *ipconfig,
							DBusMessageIter *array)
{
	enum connman_ipconfig_method method = CONNMAN_IPCONFIG_METHOD_UNKNOWN;
	const char *address = NULL, *netmask = NULL;
	DBusMessageIter dict;

	DBG("ipconfig %p", ipconfig);

	if (dbus_message_iter_get_arg_type(array) != DBUS_TYPE_ARRAY)
		return -EINVAL;

	dbus_message_iter_recurse(array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry;
		const char *key;
		int type;

		dbus_message_iter_recurse(&dict, &entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			return -EINVAL;

		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);

		type = dbus_message_iter_get_arg_type(&entry);

		if (g_str_equal(key, "Method") == TRUE) {
			const char *str;

			if (type != DBUS_TYPE_STRING)
				return -EINVAL;

			dbus_message_iter_get_basic(&entry, &str);
			method = __connman_ipconfig_string2method(str);
		} else if (g_str_equal(key, "Address") == TRUE) {
			if (type != DBUS_TYPE_STRING)
				return -EINVAL;

			dbus_message_iter_get_basic(&entry, &address);
		} else if (g_str_equal(key, "Netmask") == TRUE) {
			if (type != DBUS_TYPE_STRING)
				return -EINVAL;

			dbus_message_iter_get_basic(&entry, &netmask);
		}

		dbus_message_iter_next(&dict);
	}

	DBG("method %d address %s netmask %s", method, address, netmask);

	switch (method) {
	case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
	case CONNMAN_IPCONFIG_METHOD_OFF:
	case CONNMAN_IPCONFIG_METHOD_FIXED:
		return -EINVAL;

	case CONNMAN_IPCONFIG_METHOD_MANUAL:
		if (address == NULL)
			return -EINVAL;

		ipconfig->method = method;
		connman_ipaddress_set(ipconfig->address, address, netmask);
		break;

	case CONNMAN_IPCONFIG_METHOD_DHCP:
		if (ipconfig->method == method)
			return 0;

		ipconfig->method = method;
		break;
	}

	return 0;
}

int __connman_ipconfig_append_ethernet(struct connman_ipconfig *ipconfig,
							DBusMessageIter *iter)
{
	const char *method = "auto";

	connman_dbus_dict_append_basic(iter, "Method",
						DBUS_TYPE_STRING, &method);

	if (ipconfig->eth != NULL)
		connman_dbus_dict_append_basic(iter, "Address",
					DBUS_TYPE_STRING, &ipconfig->eth);

	if (ipconfig->mtu > 0)
		connman_dbus_dict_append_basic(iter, "MTU",
					DBUS_TYPE_UINT16, &ipconfig->mtu);

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
