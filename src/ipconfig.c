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
#include <linux/if_link.h>
#include <string.h>
#include <stdlib.h>

#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP	0x10000
#endif

#include <gdbus.h>

#include "connman.h"

struct connman_ipconfig {
	gint refcount;
	int index;
	enum connman_ipconfig_type type;

	struct connman_ipconfig *origin;

	const struct connman_ipconfig_ops *ops;
	void *ops_data;

	enum connman_ipconfig_method method;
	struct connman_ipaddress *address;
	struct connman_ipaddress *system;
};

struct connman_ipdevice {
	int index;
	char *ifname;
	unsigned short type;
	unsigned int flags;
	char *address;
	uint16_t mtu;
	uint32_t rx_packets;
	uint32_t tx_packets;
	uint32_t rx_bytes;
	uint32_t tx_bytes;
	uint32_t rx_errors;
	uint32_t tx_errors;
	uint32_t rx_dropped;
	uint32_t tx_dropped;

	GSList *address_list;
	char *ipv4_gateway;
	char *ipv6_gateway;

	char *pac;

	struct connman_ipconfig *config_ipv4;
	struct connman_ipconfig *config_ipv6;

	struct connman_ipconfig_driver *driver_ipv4;
	struct connman_ipconfig *driver_config_ipv4;

	struct connman_ipconfig_driver *driver_ipv6;
	struct connman_ipconfig *driver_config_ipv6;
};

static GHashTable *ipdevice_hash = NULL;
static GList *ipconfig_list = NULL;

struct connman_ipaddress *connman_ipaddress_alloc(int family)
{
	struct connman_ipaddress *ipaddress;

	ipaddress = g_try_new0(struct connman_ipaddress, 1);
	if (ipaddress == NULL)
		return NULL;

	ipaddress->family = family;
	ipaddress->prefixlen = 0;
	ipaddress->local = NULL;
	ipaddress->peer = NULL;
	ipaddress->broadcast = NULL;
	ipaddress->gateway = NULL;

	return ipaddress;
}

void connman_ipaddress_free(struct connman_ipaddress *ipaddress)
{
	if (ipaddress == NULL)
		return;

	g_free(ipaddress->broadcast);
	g_free(ipaddress->peer);
	g_free(ipaddress->local);
	g_free(ipaddress->gateway);
	g_free(ipaddress);
}

unsigned char __connman_ipconfig_netmask_prefix_len(const char *netmask)
{
	unsigned char bits;
	in_addr_t mask;
	in_addr_t host;

	if (netmask == NULL)
		return 32;

	mask = inet_network(netmask);
	host = ~mask;

	/* a valid netmask must be 2^n - 1 */
	if ((host & (host + 1)) != 0)
		return -1;

	bits = 0;
	for (; mask; mask <<= 1)
		++bits;

	return bits;
}

static gboolean check_ipv6_address(const char *address)
{
	unsigned char buf[sizeof(struct in6_addr)];
	int err;

	err = inet_pton(AF_INET6, address, buf);
	if (err > 0)
		return TRUE;

	return FALSE;
}

int connman_ipaddress_set_ipv6(struct connman_ipaddress *ipaddress,
				const char *address, const char *gateway,
						unsigned char prefix_length)
{
	if (ipaddress == NULL)
		return -EINVAL;

	if (check_ipv6_address(address) == FALSE)
		return -EINVAL;

	if (check_ipv6_address(gateway) == FALSE)
		return -EINVAL;

	DBG("prefix_len %d address %s gateway %s",
			prefix_length, address, gateway);

	ipaddress->prefixlen = prefix_length;

	g_free(ipaddress->local);
	ipaddress->local = g_strdup(address);

	g_free(ipaddress->gateway);
	ipaddress->gateway = g_strdup(gateway);

	return 0;
}

void connman_ipaddress_set_ipv4(struct connman_ipaddress *ipaddress,
		const char *address, const char *netmask, const char *gateway)
{
	if (ipaddress == NULL)
		return;

	ipaddress->prefixlen = __connman_ipconfig_netmask_prefix_len(netmask);

	g_free(ipaddress->local);
	ipaddress->local = g_strdup(address);

	g_free(ipaddress->gateway);
	ipaddress->gateway = g_strdup(gateway);
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

	g_free(ipaddress->gateway);
	ipaddress->gateway = NULL;
}

void connman_ipaddress_copy(struct connman_ipaddress *ipaddress,
					struct connman_ipaddress *source)
{
	if (ipaddress == NULL || source == NULL)
		return;

	ipaddress->family = source->family;
	ipaddress->prefixlen = source->prefixlen;

	g_free(ipaddress->local);
	ipaddress->local = g_strdup(source->local);

	g_free(ipaddress->peer);
	ipaddress->peer = g_strdup(source->peer);

	g_free(ipaddress->broadcast);
	ipaddress->broadcast = g_strdup(source->broadcast);

	g_free(ipaddress->gateway);
	ipaddress->gateway = g_strdup(source->gateway);
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

	if (ipdevice->config_ipv4 != NULL) {
		connman_ipconfig_unref(ipdevice->config_ipv4);
		ipdevice->config_ipv4 = NULL;
	}

	if (ipdevice->config_ipv6 != NULL) {
		connman_ipconfig_unref(ipdevice->config_ipv6);
		ipdevice->config_ipv6 = NULL;
	}

	free_address_list(ipdevice);
	g_free(ipdevice->ipv4_gateway);
	g_free(ipdevice->ipv6_gateway);
	g_free(ipdevice->pac);

	g_free(ipdevice->address);
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
	int is_dhcpv4 = 0, is_dhcpv6 = 0;
	int found = 0;

	DBG("ipconfig ipv4 %p ipv6 %p", ipdevice->config_ipv4,
					ipdevice->config_ipv6);

	if (ipdevice->config_ipv4 == NULL && ipdevice->config_ipv6 == NULL)
		return;

	if (ipdevice->driver_ipv4 != NULL && ipdevice->driver_ipv6 != NULL)
		return;

	if (ipdevice->config_ipv4) {
		switch (ipdevice->config_ipv4->method) {
		case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
		case CONNMAN_IPCONFIG_METHOD_OFF:
		case CONNMAN_IPCONFIG_METHOD_FIXED:
		case CONNMAN_IPCONFIG_METHOD_MANUAL:
			break;
		case CONNMAN_IPCONFIG_METHOD_DHCP:
			is_dhcpv4 = 1;
			break;
		}
	}

	if (ipdevice->config_ipv6) {
		switch (ipdevice->config_ipv6->method) {
		case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
		case CONNMAN_IPCONFIG_METHOD_OFF:
		case CONNMAN_IPCONFIG_METHOD_FIXED:
		case CONNMAN_IPCONFIG_METHOD_MANUAL:
			break;
		case CONNMAN_IPCONFIG_METHOD_DHCP:
			is_dhcpv6 = 1;
			break;
		}
	}

	if (is_dhcpv4 && ipdevice->config_ipv4) {
		ipdevice->driver_config_ipv4 = connman_ipconfig_clone(
							ipdevice->config_ipv4);
		if (ipdevice->driver_config_ipv4 == NULL)
			return;
	}

	if (is_dhcpv6 && ipdevice->config_ipv6) {
		ipdevice->driver_config_ipv6 = connman_ipconfig_clone(
							ipdevice->config_ipv6);
		if (ipdevice->driver_config_ipv6 == NULL)
			return;
	}

	for (list = driver_list; list; list = list->next) {
		struct connman_ipconfig_driver *driver = list->data;

		if (is_dhcpv4 && ipdevice->driver_ipv4 != NULL) {
			if (!driver->request(ipdevice->driver_config_ipv4)) {
				ipdevice->driver_ipv4 = driver;
				found++;
			}
		}

		if (is_dhcpv6 && ipdevice->driver_ipv6 != NULL) {
			if (!driver->request(ipdevice->driver_config_ipv6)) {
				ipdevice->driver_ipv6 = driver;
				found++;
			}
		}

		if (found > 1)
			break;
	}

	if (ipdevice->driver_ipv4 == NULL) {
		connman_ipconfig_unref(ipdevice->driver_config_ipv4);
		ipdevice->driver_config_ipv4 = NULL;
	}

	if (ipdevice->driver_ipv6 == NULL) {
		connman_ipconfig_unref(ipdevice->driver_config_ipv6);
		ipdevice->driver_config_ipv6 = NULL;
	}
}

static void __connman_ipconfig_lower_down(struct connman_ipdevice *ipdevice)
{
	DBG("ipconfig ipv4 %p ipv6 %p", ipdevice->config_ipv4,
					ipdevice->config_ipv6);

	if (ipdevice->config_ipv4 == NULL && ipdevice->config_ipv6 == NULL)
		return;

	if (ipdevice->driver_ipv4 == NULL && ipdevice->driver_ipv6 == NULL)
		return;

	if (ipdevice->driver_ipv4) {
		ipdevice->driver_ipv4->release(ipdevice->driver_config_ipv4);
		ipdevice->driver_ipv4 = NULL;
	}

	if (ipdevice->driver_ipv6) {
		ipdevice->driver_ipv6->release(ipdevice->driver_config_ipv6);
		ipdevice->driver_ipv6 = NULL;
	}

	if (ipdevice->driver_config_ipv4) {
		connman_ipconfig_unref(ipdevice->driver_config_ipv4);
		ipdevice->driver_config_ipv4 = NULL;
	}

	if (ipdevice->driver_config_ipv6) {
		connman_ipconfig_unref(ipdevice->driver_config_ipv6);
		ipdevice->driver_config_ipv6 = NULL;
	}

	if (ipdevice->config_ipv4)
		connman_inet_clear_address(ipdevice->index,
					ipdevice->config_ipv4->address);

	if (ipdevice->config_ipv6)
		connman_inet_clear_ipv6_address(ipdevice->index,
				ipdevice->config_ipv6->address->local,
				ipdevice->config_ipv6->address->prefixlen);
}

static void update_stats(struct connman_ipdevice *ipdevice,
						struct rtnl_link_stats *stats)
{
	struct connman_service *service;

	if (stats->rx_packets == 0 && stats->tx_packets == 0)
		return;

	connman_info("%s {RX} %u packets %u bytes", ipdevice->ifname,
					stats->rx_packets, stats->rx_bytes);
	connman_info("%s {TX} %u packets %u bytes", ipdevice->ifname,
					stats->tx_packets, stats->tx_bytes);

	if (ipdevice->config_ipv4 == NULL && ipdevice->config_ipv6 == NULL)
		return;

	if (ipdevice->config_ipv4)
		service = connman_ipconfig_get_data(ipdevice->config_ipv4);
	else if (ipdevice->config_ipv6)
		service = connman_ipconfig_get_data(ipdevice->config_ipv6);
	else
		return;

	if (service == NULL)
		return;

	ipdevice->rx_packets = stats->rx_packets;
	ipdevice->tx_packets = stats->tx_packets;
	ipdevice->rx_bytes = stats->rx_bytes;
	ipdevice->tx_bytes = stats->tx_bytes;
	ipdevice->rx_errors = stats->rx_errors;
	ipdevice->tx_errors = stats->tx_errors;
	ipdevice->rx_dropped = stats->rx_dropped;
	ipdevice->tx_dropped = stats->tx_dropped;

	__connman_service_notify(service,
				ipdevice->rx_packets, ipdevice->tx_packets,
				ipdevice->rx_bytes, ipdevice->tx_bytes,
				ipdevice->rx_errors, ipdevice->tx_errors,
				ipdevice->rx_dropped, ipdevice->tx_dropped);
}

void __connman_ipconfig_newlink(int index, unsigned short type,
				unsigned int flags, const char *address,
							unsigned short mtu,
						struct rtnl_link_stats *stats)
{
	struct connman_ipdevice *ipdevice;
	GList *list;
	GString *str;
	gboolean up = FALSE, down = FALSE;
	gboolean lower_up = FALSE, lower_down = FALSE;

	DBG("index %d", index);

	if (type == ARPHRD_LOOPBACK)
		return;

	ipdevice = g_hash_table_lookup(ipdevice_hash, GINT_TO_POINTER(index));
	if (ipdevice != NULL)
		goto update;

	ipdevice = g_try_new0(struct connman_ipdevice, 1);
	if (ipdevice == NULL)
		return;

	ipdevice->index = index;
	ipdevice->ifname = connman_inet_ifname(index);
	ipdevice->type = type;

	ipdevice->address = g_strdup(address);

	g_hash_table_insert(ipdevice_hash, GINT_TO_POINTER(index), ipdevice);

	connman_info("%s {create} index %d type %d <%s>", ipdevice->ifname,
						index, type, type2str(type));

update:
	ipdevice->mtu = mtu;

	update_stats(ipdevice, stats);

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

void __connman_ipconfig_dellink(int index, struct rtnl_link_stats *stats)
{
	struct connman_ipdevice *ipdevice;
	GList *list;

	DBG("index %d", index);

	ipdevice = g_hash_table_lookup(ipdevice_hash, GINT_TO_POINTER(index));
	if (ipdevice == NULL)
		return;

	update_stats(ipdevice, stats);

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

static inline gint check_duplicate_address(gconstpointer a, gconstpointer b)
{
	const struct connman_ipaddress *addr1 = a;
	const struct connman_ipaddress *addr2 = b;

	if (addr1->prefixlen != addr2->prefixlen)
		return addr2->prefixlen - addr1->prefixlen;

	return g_strcmp0(addr1->local, addr2->local);
}

void __connman_ipconfig_newaddr(int index, int family, const char *label,
				unsigned char prefixlen, const char *address)
{
	struct connman_ipdevice *ipdevice;
	struct connman_ipaddress *ipaddress;
	GList *list;

	DBG("index %d", index);

	ipdevice = g_hash_table_lookup(ipdevice_hash, GINT_TO_POINTER(index));
	if (ipdevice == NULL)
		return;

	ipaddress = connman_ipaddress_alloc(family);
	if (ipaddress == NULL)
		return;

	ipaddress->prefixlen = prefixlen;
	ipaddress->local = g_strdup(address);

	if (g_slist_find_custom(ipdevice->address_list, ipaddress,
					check_duplicate_address)) {
		connman_ipaddress_free(ipaddress);
		return;
	}

	ipdevice->address_list = g_slist_append(ipdevice->address_list,
								ipaddress);

	connman_info("%s {add} address %s/%u label %s family %d",
		ipdevice->ifname, address, prefixlen, label, family);

	if (ipdevice->config_ipv4 != NULL && family == AF_INET)
		connman_ipaddress_copy(ipdevice->config_ipv4->system,
					ipaddress);

	else if (ipdevice->config_ipv6 != NULL && family == AF_INET6)
		connman_ipaddress_copy(ipdevice->config_ipv6->system,
					ipaddress);
	else
		return;

	if ((ipdevice->flags & (IFF_RUNNING | IFF_LOWER_UP)) != (IFF_RUNNING | IFF_LOWER_UP))
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

void __connman_ipconfig_deladdr(int index, int family, const char *label,
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

void __connman_ipconfig_newroute(int index, int family, unsigned char scope,
					const char *dst, const char *gateway)
{
	struct connman_ipdevice *ipdevice;

	DBG("index %d", index);

	ipdevice = g_hash_table_lookup(ipdevice_hash, GINT_TO_POINTER(index));
	if (ipdevice == NULL)
		return;

	if (scope == 0 && g_strcmp0(dst, "0.0.0.0") == 0) {
		GSList *list;
		GList *config_list;

		if (family == AF_INET6) {
			g_free(ipdevice->ipv6_gateway);
			ipdevice->ipv6_gateway = g_strdup(gateway);

			if (ipdevice->config_ipv6 != NULL &&
				ipdevice->config_ipv6->system != NULL) {
				g_free(ipdevice->config_ipv6->system->gateway);
				ipdevice->config_ipv6->system->gateway =
					g_strdup(gateway);
			}
		} else {
			g_free(ipdevice->ipv4_gateway);
			ipdevice->ipv4_gateway = g_strdup(gateway);

			if (ipdevice->config_ipv4 != NULL &&
				ipdevice->config_ipv4->system != NULL) {
				g_free(ipdevice->config_ipv4->system->gateway);
				ipdevice->config_ipv4->system->gateway =
					g_strdup(gateway);
			}
		}

		for (list = ipdevice->address_list; list; list = list->next) {
			struct connman_ipaddress *ipaddress = list->data;

			g_free(ipaddress->gateway);
			ipaddress->gateway = g_strdup(gateway);
		}

		for (config_list = g_list_first(ipconfig_list); config_list;
					config_list = g_list_next(config_list)) {
			struct connman_ipconfig *ipconfig = config_list->data;

			if (index != ipconfig->index)
				continue;

			if (ipconfig->ops == NULL)
				continue;

			if (ipconfig->ops->ip_bound)
				ipconfig->ops->ip_bound(ipconfig);
		}
	}

	connman_info("%s {add} route %s gw %s scope %u <%s>",
					ipdevice->ifname, dst, gateway,
						scope, scope2str(scope));
}

void __connman_ipconfig_delroute(int index, int family, unsigned char scope,
					const char *dst, const char *gateway)
{
	struct connman_ipdevice *ipdevice;

	DBG("index %d", index);

	ipdevice = g_hash_table_lookup(ipdevice_hash, GINT_TO_POINTER(index));
	if (ipdevice == NULL)
		return;

	if (scope == 0 && g_strcmp0(dst, "0.0.0.0") == 0) {
		GSList *list;
		GList *config_list;

		if (family == AF_INET6) {
			g_free(ipdevice->ipv6_gateway);
			ipdevice->ipv6_gateway = NULL;

			if (ipdevice->config_ipv6 != NULL &&
				ipdevice->config_ipv6->system != NULL) {
				g_free(ipdevice->config_ipv6->system->gateway);
				ipdevice->config_ipv6->system->gateway = NULL;
			}
		} else {
			g_free(ipdevice->ipv4_gateway);
			ipdevice->ipv4_gateway = NULL;

			if (ipdevice->config_ipv4 != NULL &&
				ipdevice->config_ipv4->system != NULL) {
				g_free(ipdevice->config_ipv4->system->gateway);
				ipdevice->config_ipv4->system->gateway = NULL;
			}
		}

		for (list = ipdevice->address_list; list; list = list->next) {
			struct connman_ipaddress *ipaddress = list->data;

			g_free(ipaddress->gateway);
			ipaddress->gateway = NULL;
		}

		for (config_list = g_list_first(ipconfig_list); config_list;
					config_list = g_list_next(config_list)) {
			struct connman_ipconfig *ipconfig = config_list->data;

			if (index != ipconfig->index)
				continue;

			if (ipconfig->ops == NULL)
				continue;

			if (ipconfig->ops->ip_release)
				ipconfig->ops->ip_release(ipconfig);
		}
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

	if (ipdevice->ipv4_gateway != NULL)
		return ipdevice->ipv4_gateway;

	if (ipdevice->config_ipv4 != NULL &&
			ipdevice->config_ipv4->address != NULL)
		return ipdevice->config_ipv4->address->gateway;

	if (ipdevice->ipv6_gateway != NULL)
		return ipdevice->ipv6_gateway;

	if (ipdevice->config_ipv6 != NULL &&
			ipdevice->config_ipv6->address != NULL)
		return ipdevice->config_ipv6->address->gateway;

	return NULL;
}

void __connman_ipconfig_set_index(struct connman_ipconfig *ipconfig, int index)
{
	ipconfig->index = index;
}

static struct connman_ipconfig *create_ipv6config(int index)
{
	struct connman_ipconfig *ipv6config;

	DBG("index %d", index);

	ipv6config = g_try_new0(struct connman_ipconfig, 1);
	if (ipv6config == NULL)
		return NULL;

	ipv6config->index = index;
	ipv6config->type = CONNMAN_IPCONFIG_TYPE_IPV6;
	ipv6config->method = CONNMAN_IPCONFIG_METHOD_OFF;

	ipv6config->address = connman_ipaddress_alloc(AF_INET6);
	if (ipv6config->address == NULL) {
		g_free(ipv6config);
		return NULL;
	}

	ipv6config->system = connman_ipaddress_alloc(AF_INET6);

	DBG("ipconfig %p", ipv6config);

	return ipv6config;
}

/**
 * connman_ipconfig_create:
 *
 * Allocate a new ipconfig structure.
 *
 * Returns: a newly-allocated #connman_ipconfig structure
 */
struct connman_ipconfig *connman_ipconfig_create(int index,
					enum connman_ipconfig_type type)
{
	struct connman_ipconfig *ipconfig;

	if (type == CONNMAN_IPCONFIG_TYPE_IPV6)
		return create_ipv6config(index);

	DBG("index %d", index);

	ipconfig = g_try_new0(struct connman_ipconfig, 1);
	if (ipconfig == NULL)
		return NULL;

	ipconfig->refcount = 1;

	ipconfig->index = index;
	ipconfig->type = CONNMAN_IPCONFIG_TYPE_IPV4;

	ipconfig->address = connman_ipaddress_alloc(AF_INET);
	if (ipconfig->address == NULL) {
		g_free(ipconfig);
		return NULL;
	}

	ipconfig->system = connman_ipaddress_alloc(AF_INET);

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
	if (ipconfig &&
		g_atomic_int_dec_and_test(&ipconfig->refcount) == TRUE) {
		__connman_ipconfig_disable(ipconfig);

		connman_ipconfig_set_ops(ipconfig, NULL);

		if (ipconfig->origin != NULL) {
			connman_ipconfig_unref(ipconfig->origin);
			ipconfig->origin = NULL;
		}

		connman_ipaddress_free(ipconfig->system);
		connman_ipaddress_free(ipconfig->address);
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
	if (ipconfig == NULL)
		return -1;

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

	if (ipconfig == NULL)
		return NULL;

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

struct connman_ipconfig *connman_ipconfig_get_ipv6config(
				struct connman_ipconfig *ipconfig)
{
	if (ipconfig == NULL || ipconfig->type != CONNMAN_IPCONFIG_TYPE_IPV6)
		return NULL;

	return ipconfig;
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

enum connman_ipconfig_method __connman_ipconfig_get_method(struct connman_ipconfig *ipconfig)
{
	if (ipconfig == NULL)
		return CONNMAN_IPCONFIG_METHOD_UNKNOWN;

	return ipconfig->method;
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

void __connman_ipconfig_set_element_ipv6_gateway(
			struct connman_ipconfig *ipconfig,
				struct connman_element *element)
{
	if (ipconfig->type == CONNMAN_IPCONFIG_TYPE_IPV6)
		element->ipv6.gateway = ipconfig->address->gateway;
}

/*
 * FIXME: The element soulution should be removed in the future
 * Set IPv4 and IPv6 gateway
 */
int __connman_ipconfig_set_gateway(struct connman_ipconfig *ipconfig,
						struct connman_element *parent)
{
	struct connman_element *connection;

	connection = connman_element_create(NULL);

	DBG("ipconfig %p", ipconfig);

	connection->type  = CONNMAN_ELEMENT_TYPE_CONNECTION;
	connection->index = ipconfig->index;

	if (ipconfig->type == CONNMAN_IPCONFIG_TYPE_IPV4)
		connection->ipv4.gateway = ipconfig->address->gateway;
	else if (ipconfig->type == CONNMAN_IPCONFIG_TYPE_IPV6)
		connection->ipv6.gateway = ipconfig->address->gateway;

	if (connman_element_register(connection, parent) < 0)
		connman_element_unref(connection);

	return 0;
}

int __connman_ipconfig_set_address(struct connman_ipconfig *ipconfig)
{
	DBG("");

	switch (ipconfig->method) {
	case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
	case CONNMAN_IPCONFIG_METHOD_OFF:
	case CONNMAN_IPCONFIG_METHOD_FIXED:
	case CONNMAN_IPCONFIG_METHOD_DHCP:
		break;
	case CONNMAN_IPCONFIG_METHOD_MANUAL:
		if (ipconfig->type == CONNMAN_IPCONFIG_TYPE_IPV4)
			return connman_inet_set_address(ipconfig->index,
							ipconfig->address);
		else if (ipconfig->type == CONNMAN_IPCONFIG_TYPE_IPV6)
			return connman_inet_set_ipv6_address(
					ipconfig->index, ipconfig->address);
	}

	return 0;
}

int __connman_ipconfig_clear_address(struct connman_ipconfig *ipconfig)
{
	DBG("");

	if (ipconfig == NULL)
		return 0;

	DBG("method %d", ipconfig->method);

	switch (ipconfig->method) {
	case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
	case CONNMAN_IPCONFIG_METHOD_OFF:
	case CONNMAN_IPCONFIG_METHOD_FIXED:
	case CONNMAN_IPCONFIG_METHOD_DHCP:
		break;
	case CONNMAN_IPCONFIG_METHOD_MANUAL:
		if (ipconfig->type == CONNMAN_IPCONFIG_TYPE_IPV4)
			return connman_inet_clear_address(ipconfig->index,
							ipconfig->address);
		else if (ipconfig->type == CONNMAN_IPCONFIG_TYPE_IPV6)
			return connman_inet_clear_ipv6_address(
						ipconfig->index,
						ipconfig->address->local,
						ipconfig->address->prefixlen);
	}

	return 0;
}

int __connman_ipconfig_set_proxy_autoconfig(struct connman_ipconfig *ipconfig,
                                                        const char *url)
{
	struct connman_ipdevice *ipdevice;

	DBG("ipconfig %p", ipconfig);

	if (ipconfig == NULL || ipconfig->index < 0)
		return -ENODEV;

	ipdevice = g_hash_table_lookup(ipdevice_hash,
					GINT_TO_POINTER(ipconfig->index));
	if (ipdevice == NULL)
		return -ENXIO;

	g_free(ipdevice->pac);
	ipdevice->pac = g_strdup(url);

	return 0;
}

const char *__connman_ipconfig_get_proxy_autoconfig(struct connman_ipconfig *ipconfig)
{
	struct connman_ipdevice *ipdevice;

	DBG("ipconfig %p", ipconfig);

	if (ipconfig == NULL || ipconfig->index < 0)
		return NULL;

	ipdevice = g_hash_table_lookup(ipdevice_hash,
					GINT_TO_POINTER(ipconfig->index));
	if (ipdevice == NULL)
		return NULL;

	return ipdevice->pac;
}

int __connman_ipconfig_enable(struct connman_ipconfig *ipconfig)
{
	struct connman_ipdevice *ipdevice;
	gboolean up = FALSE, down = FALSE;
	gboolean lower_up = FALSE, lower_down = FALSE;
	enum connman_ipconfig_type type;

	DBG("ipconfig %p", ipconfig);

	if (ipconfig == NULL || ipconfig->index < 0)
		return -ENODEV;

	ipdevice = g_hash_table_lookup(ipdevice_hash,
					GINT_TO_POINTER(ipconfig->index));
	if (ipdevice == NULL)
		return -ENXIO;

	if (ipconfig->type == CONNMAN_IPCONFIG_TYPE_IPV4) {
		if (ipdevice->config_ipv4 == ipconfig)
			return -EALREADY;
		type = CONNMAN_IPCONFIG_TYPE_IPV4;
	} else if (ipconfig->type == CONNMAN_IPCONFIG_TYPE_IPV6) {
		if (ipdevice->config_ipv6 == ipconfig)
			return -EALREADY;
		type = CONNMAN_IPCONFIG_TYPE_IPV6;
	} else
		return -EINVAL;

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4 &&
					ipdevice->config_ipv4 != NULL) {
		ipconfig_list = g_list_remove(ipconfig_list, ipconfig);

		connman_ipaddress_clear(ipdevice->config_ipv4->system);

		connman_ipconfig_unref(ipdevice->config_ipv4);
	}

	if (type == CONNMAN_IPCONFIG_TYPE_IPV6 &&
					ipdevice->config_ipv6 != NULL) {
		ipconfig_list = g_list_remove(ipconfig_list, ipconfig);

		connman_ipaddress_clear(ipdevice->config_ipv6->system);

		connman_ipconfig_unref(ipdevice->config_ipv6);
	}

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		ipdevice->config_ipv4 = connman_ipconfig_ref(ipconfig);
	else if (type == CONNMAN_IPCONFIG_TYPE_IPV6)
		ipdevice->config_ipv6 = connman_ipconfig_ref(ipconfig);

	ipconfig_list = g_list_append(ipconfig_list, ipconfig);

	if (ipdevice->flags & IFF_UP)
		up = TRUE;
	else
		down = TRUE;

	if ((ipdevice->flags & (IFF_RUNNING | IFF_LOWER_UP)) ==
			(IFF_RUNNING | IFF_LOWER_UP))
		lower_up = TRUE;
	else if ((ipdevice->flags & (IFF_RUNNING | IFF_LOWER_UP)) == 0)
		lower_down = TRUE;

	if (up == TRUE && ipconfig->ops->up)
		ipconfig->ops->up(ipconfig);
	if (lower_up == TRUE && ipconfig->ops->lower_up)
		ipconfig->ops->lower_up(ipconfig);

	if (lower_down == TRUE && ipconfig->ops->lower_down)
		ipconfig->ops->lower_down(ipconfig);
	if (down == TRUE && ipconfig->ops->down)
		ipconfig->ops->down(ipconfig);

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

	if (ipdevice->config_ipv4 == NULL && ipdevice->config_ipv6 == NULL)
		return -EINVAL;

	if (ipdevice->config_ipv4 == ipconfig) {
		ipconfig_list = g_list_remove(ipconfig_list, ipconfig);

		connman_ipaddress_clear(ipdevice->config_ipv4->system);
		connman_ipconfig_unref(ipdevice->config_ipv4);
		ipdevice->config_ipv4 = NULL;
		return 0;
	}

	if (ipdevice->config_ipv6 == ipconfig) {
		ipconfig_list = g_list_remove(ipconfig_list, ipconfig);

		connman_ipaddress_clear(ipdevice->config_ipv6->system);
		connman_ipconfig_unref(ipdevice->config_ipv6);
		ipdevice->config_ipv6 = NULL;
		return 0;
	}

	return -EINVAL;
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

	DBG("");

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

	if (ipconfig->system->gateway != NULL)
		connman_dbus_dict_append_basic(iter, "Gateway",
				DBUS_TYPE_STRING, &ipconfig->system->gateway);
}

void __connman_ipconfig_append_ipv6(struct connman_ipconfig *ipconfig,
							DBusMessageIter *iter)
{
	const char *str;

	DBG("");

	str = __connman_ipconfig_method2string(ipconfig->method);
	if (str == NULL)
		return;

	connman_dbus_dict_append_basic(iter, "Method", DBUS_TYPE_STRING, &str);

	if (ipconfig->system == NULL)
		return;

	if (ipconfig->system->local != NULL) {
		connman_dbus_dict_append_basic(iter, "Address",
				DBUS_TYPE_STRING, &ipconfig->system->local);
		connman_dbus_dict_append_basic(iter, "PrefixLength",
						DBUS_TYPE_BYTE,
						&ipconfig->system->prefixlen);
	}

	if (ipconfig->system->gateway != NULL)
		connman_dbus_dict_append_basic(iter, "Gateway",
				DBUS_TYPE_STRING, &ipconfig->system->gateway);
}

void __connman_ipconfig_append_ipv6config(struct connman_ipconfig *ipconfig,
							DBusMessageIter *iter)
{
	const char *str;

	DBG("");

	str = __connman_ipconfig_method2string(ipconfig->method);
	if (str == NULL)
		return;

	connman_dbus_dict_append_basic(iter, "Method", DBUS_TYPE_STRING, &str);

	switch (ipconfig->method) {
	case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
	case CONNMAN_IPCONFIG_METHOD_OFF:
	case CONNMAN_IPCONFIG_METHOD_DHCP:
		return;
	case CONNMAN_IPCONFIG_METHOD_FIXED:
	case CONNMAN_IPCONFIG_METHOD_MANUAL:
		break;
	}

	if (ipconfig->address == NULL)
		return;

	if (ipconfig->address->local != NULL) {
		connman_dbus_dict_append_basic(iter, "Address",
				DBUS_TYPE_STRING, &ipconfig->address->local);
		connman_dbus_dict_append_basic(iter, "PrefixLength",
						DBUS_TYPE_BYTE,
						&ipconfig->address->prefixlen);
	}

	if (ipconfig->address->gateway != NULL)
		connman_dbus_dict_append_basic(iter, "Gateway",
				DBUS_TYPE_STRING, &ipconfig->address->gateway);
}

void __connman_ipconfig_append_ipv4config(struct connman_ipconfig *ipconfig,
							DBusMessageIter *iter)
{
	const char *str;

	DBG("");

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

	if (ipconfig->address->gateway != NULL)
		connman_dbus_dict_append_basic(iter, "Gateway",
				DBUS_TYPE_STRING, &ipconfig->address->gateway);
}

int __connman_ipconfig_set_config(struct connman_ipconfig *ipconfig,
		enum connman_ipconfig_type type, DBusMessageIter *array)
{
	enum connman_ipconfig_method method = CONNMAN_IPCONFIG_METHOD_UNKNOWN;
	const char *address = NULL, *netmask = NULL, *gateway = NULL,
			*prefix_length_string = NULL;
	int prefix_length = 0;
	DBusMessageIter dict;

	DBG("ipconfig %p type %d", ipconfig, type);

	if (type != CONNMAN_IPCONFIG_TYPE_IPV4 &&
			type != CONNMAN_IPCONFIG_TYPE_IPV6)
		return -EINVAL;

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
		} else if (g_str_equal(key, "PrefixLength") == TRUE) {
			if (type != DBUS_TYPE_STRING)
				return -EINVAL;

			dbus_message_iter_get_basic(&entry,
							&prefix_length_string);

			prefix_length = atoi(prefix_length_string);
			if (prefix_length < 0 || prefix_length > 128)
				return -EINVAL;

		} else if (g_str_equal(key, "Netmask") == TRUE) {
			if (type != DBUS_TYPE_STRING)
				return -EINVAL;

			dbus_message_iter_get_basic(&entry, &netmask);
		} else if (g_str_equal(key, "Gateway") == TRUE) {
			if (type != DBUS_TYPE_STRING)
				return -EINVAL;

			dbus_message_iter_get_basic(&entry, &gateway);
		}
		dbus_message_iter_next(&dict);
	}

	DBG("method %d address %s netmask %s gateway %s prefix_length %d",
			method, address, netmask, gateway, prefix_length);

	switch (method) {
	case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
	case CONNMAN_IPCONFIG_METHOD_OFF:
	case CONNMAN_IPCONFIG_METHOD_FIXED:
		return -EINVAL;

	case CONNMAN_IPCONFIG_METHOD_MANUAL:
		if (address == NULL)
			return -EINVAL;

		ipconfig->method = method;

		if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
			connman_ipaddress_set_ipv4(ipconfig->address,
						address, netmask, gateway);
		else
			return connman_ipaddress_set_ipv6(
					ipconfig->address, address,
						gateway, prefix_length);
		break;

	case CONNMAN_IPCONFIG_METHOD_DHCP:
		if (ipconfig->method == method)
			return 0;

		ipconfig->method = method;
		break;
	}

	return 0;
}

void __connman_ipconfig_append_ethernet(struct connman_ipconfig *ipconfig,
							DBusMessageIter *iter)
{
	struct connman_ipdevice *ipdevice;
	const char *method = "auto";

	connman_dbus_dict_append_basic(iter, "Method",
						DBUS_TYPE_STRING, &method);

	ipdevice = g_hash_table_lookup(ipdevice_hash,
					GINT_TO_POINTER(ipconfig->index));
	if (ipdevice == NULL)
		return;

	if (ipdevice->ifname != NULL)
		connman_dbus_dict_append_basic(iter, "Interface",
					DBUS_TYPE_STRING, &ipdevice->ifname);

	if (ipdevice->address != NULL)
		connman_dbus_dict_append_basic(iter, "Address",
					DBUS_TYPE_STRING, &ipdevice->address);

	if (ipdevice->mtu > 0)
		connman_dbus_dict_append_basic(iter, "MTU",
					DBUS_TYPE_UINT16, &ipdevice->mtu);
}

int __connman_ipconfig_load(struct connman_ipconfig *ipconfig,
		GKeyFile *keyfile, const char *identifier, const char *prefix)
{
	const char *method;
	char *key;

	DBG("ipconfig %p identifier %s", ipconfig, identifier);

	key = g_strdup_printf("%smethod", prefix);
	method = g_key_file_get_string(keyfile, identifier, key, NULL);
	if (method == NULL) {
		if (ipconfig->type == CONNMAN_IPCONFIG_TYPE_IPV4)
			ipconfig->method = CONNMAN_IPCONFIG_METHOD_DHCP;
		else
			ipconfig->method = CONNMAN_IPCONFIG_METHOD_OFF;
	} else
		ipconfig->method = __connman_ipconfig_string2method(method);
	g_free(key);

	key = g_strdup_printf("%snetmask_prefixlen", prefix);
	ipconfig->address->prefixlen = g_key_file_get_integer(
				keyfile, identifier, key, NULL);
	g_free(key);

	key = g_strdup_printf("%slocal_address", prefix);
	ipconfig->address->local = g_key_file_get_string(
			keyfile, identifier, key, NULL);
	g_free(key);

	key = g_strdup_printf("%speer_address", prefix);
	ipconfig->address->peer = g_key_file_get_string(
				keyfile, identifier, key, NULL);
	g_free(key);

	key = g_strdup_printf("%sbroadcast_address", prefix);
	ipconfig->address->broadcast = g_key_file_get_string(
				keyfile, identifier, key, NULL);
	g_free(key);

	key = g_strdup_printf("%sgateway", prefix);
	ipconfig->address->gateway = g_key_file_get_string(
				keyfile, identifier, key, NULL);
	g_free(key);

	return 0;
}

int __connman_ipconfig_save(struct connman_ipconfig *ipconfig,
		GKeyFile *keyfile, const char *identifier, const char *prefix)
{
	const char *method;
	char *key;

	DBG("ipconfig %p identifier %s", ipconfig, identifier);

	method = __connman_ipconfig_method2string(ipconfig->method);

	key = g_strdup_printf("%smethod", prefix);
	g_key_file_set_string(keyfile, identifier, key, method);
	g_free(key);

	key = g_strdup_printf("%snetmask_prefixlen", prefix);
	g_key_file_set_integer(keyfile, identifier,
			key, ipconfig->address->prefixlen);
	g_free(key);

	key = g_strdup_printf("%slocal_address", prefix);
	if (ipconfig->address->local != NULL)
		g_key_file_set_string(keyfile, identifier,
				key, ipconfig->address->local);
	g_free(key);

	key = g_strdup_printf("%speer_address", prefix);
	if (ipconfig->address->peer != NULL)
		g_key_file_set_string(keyfile, identifier,
				key, ipconfig->address->peer);
	g_free(key);

	key = g_strdup_printf("%sbroadcast_address", prefix);
	if (ipconfig->address->broadcast != NULL)
		g_key_file_set_string(keyfile, identifier,
			key, ipconfig->address->broadcast);
	g_free(key);

	key = g_strdup_printf("%sgateway", prefix);
	if (ipconfig->address->gateway != NULL)
		g_key_file_set_string(keyfile, identifier,
			key, ipconfig->address->gateway);
	g_free(key);

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
