/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2012  Intel Corporation. All rights reserved.
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
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include <connman/ipconfig.h>

#include <gdhcp/gdhcp.h>

#include <glib.h>

#include "connman.h"

struct connman_dhcp {
	struct connman_network *network;
	dhcp_cb callback;

	char **nameservers;
	char **timeservers;
	char *pac;

	GDHCPClient *dhcp_client;
};

static GHashTable *network_table;

static void dhcp_free(struct connman_dhcp *dhcp)
{
	g_strfreev(dhcp->nameservers);
	g_strfreev(dhcp->timeservers);
	g_free(dhcp->pac);

	dhcp->nameservers = NULL;
	dhcp->timeservers = NULL;
	dhcp->pac = NULL;
}

/**
 * dhcp_invalidate: Invalidate an existing DHCP lease
 * @dhcp: pointer to the DHCP lease to invalidate.
 * @callback: flag indicating whether or not to invoke the client callback
 *            if present.
 *
 * Invalidates an existing DHCP lease, optionally invoking the client
 * callback. The caller may wish to avoid the client callback invocation
 * when the invocation of that callback might otherwise unnecessarily upset
 * service state due to the IP configuration change implied by this
 * invalidation.
 */
static void dhcp_invalidate(struct connman_dhcp *dhcp, connman_bool_t callback)
{
	struct connman_service *service;
	struct connman_ipconfig *ipconfig;
	int i;

	DBG("dhcp %p callback %u", dhcp, callback);

	if (dhcp == NULL)
		return;

	service = __connman_service_lookup_from_network(dhcp->network);
	if (service == NULL)
		goto out;

	ipconfig = __connman_service_get_ip4config(service);
	if (ipconfig == NULL)
		goto out;

	__connman_6to4_remove(ipconfig);

	__connman_service_set_domainname(service, NULL);
	__connman_service_set_pac(service, NULL);

	if (dhcp->timeservers != NULL) {
		for (i = 0; dhcp->timeservers[i] != NULL; i++) {
			__connman_service_timeserver_remove(service,
							dhcp->timeservers[i]);
		}
	}

	if (dhcp->nameservers != NULL) {
		for (i = 0; dhcp->nameservers[i] != NULL; i++) {
			__connman_service_nameserver_remove(service,
						dhcp->nameservers[i], FALSE);
		}
	}

	__connman_ipconfig_set_dhcp_address(ipconfig,
				__connman_ipconfig_get_local(ipconfig));
	DBG("last address %s", __connman_ipconfig_get_dhcp_address(ipconfig));

	__connman_ipconfig_address_remove(ipconfig);

	__connman_ipconfig_set_local(ipconfig, NULL);
	__connman_ipconfig_set_broadcast(ipconfig, NULL);
	__connman_ipconfig_set_gateway(ipconfig, NULL);
	__connman_ipconfig_set_prefixlen(ipconfig, 0);

	if (dhcp->callback != NULL && callback)
		dhcp->callback(dhcp->network, FALSE);

out:
	dhcp_free(dhcp);
}

static void dhcp_valid(struct connman_dhcp *dhcp)
{
	if (dhcp->callback != NULL)
		dhcp->callback(dhcp->network, TRUE);
}

static void no_lease_cb(GDHCPClient *dhcp_client, gpointer user_data)
{
	struct connman_dhcp *dhcp = user_data;

	DBG("No lease available");

	dhcp_invalidate(dhcp, TRUE);
}

static void lease_lost_cb(GDHCPClient *dhcp_client, gpointer user_data)
{
	struct connman_dhcp *dhcp = user_data;

	DBG("Lease lost");

	dhcp_invalidate(dhcp, TRUE);
}

static void ipv4ll_lost_cb(GDHCPClient *dhcp_client, gpointer user_data)
{
	struct connman_dhcp *dhcp = user_data;

	DBG("Lease lost");

	dhcp_invalidate(dhcp, TRUE);
}


static gboolean compare_string_arrays(char **array_a, char **array_b)
{
	int i;

	if (array_a == NULL || array_b == NULL)
		return FALSE;

	if (g_strv_length(array_a) != g_strv_length(array_b))
		return FALSE;

	for (i = 0; array_a[i] != NULL &&
			     array_b[i] != NULL; i++) {
		if (g_strcmp0(array_a[i], array_b[i]) != 0)
			return FALSE;
	}

	return TRUE;
}

static void lease_available_cb(GDHCPClient *dhcp_client, gpointer user_data)
{
	struct connman_dhcp *dhcp = user_data;
	GList *list, *option = NULL;
	char *address, *netmask = NULL, *gateway = NULL;
	const char *c_address, *c_gateway;
	char *domainname = NULL, *hostname = NULL;
	char **nameservers, **timeservers, *pac = NULL;
	int ns_entries;
	struct connman_ipconfig *ipconfig;
	struct connman_service *service;
	unsigned char prefixlen, c_prefixlen;
	gboolean ip_change;
	int i;

	DBG("Lease available");

	service = __connman_service_lookup_from_network(dhcp->network);
	if (service == NULL) {
		connman_error("Can not lookup service");
		return;
	}

	ipconfig = __connman_service_get_ip4config(service);
	if (ipconfig == NULL) {
		connman_error("Could not lookup ipconfig");
		return;
	}

	c_address = __connman_ipconfig_get_local(ipconfig);
	c_gateway = __connman_ipconfig_get_gateway(ipconfig);
	c_prefixlen = __connman_ipconfig_get_prefixlen(ipconfig);

	address = g_dhcp_client_get_address(dhcp_client);

	__connman_ipconfig_set_dhcp_address(ipconfig, address);
	DBG("last address %s", address);

	option = g_dhcp_client_get_option(dhcp_client, G_DHCP_SUBNET);
	if (option != NULL)
		netmask = g_strdup(option->data);

	option = g_dhcp_client_get_option(dhcp_client, G_DHCP_ROUTER);
	if (option != NULL)
		gateway = g_strdup(option->data);

	prefixlen = __connman_ipconfig_netmask_prefix_len(netmask);

	DBG("c_address %s", c_address);

	if (address != NULL && c_address != NULL &&
					g_strcmp0(address, c_address) != 0)
		ip_change = TRUE;
	else if (gateway != NULL && c_gateway != NULL &&
					g_strcmp0(gateway, c_gateway) != 0)
		ip_change = TRUE;
	else if (prefixlen != c_prefixlen)
		ip_change = TRUE;
	else if (c_address == NULL || c_gateway == NULL)
		ip_change = TRUE;
	else
		ip_change = FALSE;

	option = g_dhcp_client_get_option(dhcp_client, G_DHCP_DNS_SERVER);
	ns_entries = g_list_length(option);
	nameservers = g_try_new0(char *, ns_entries + 1);
	if (nameservers != NULL) {
		for (i = 0, list = option; list; list = list->next, i++)
			nameservers[i] = g_strdup(list->data);
		nameservers[ns_entries] = NULL;
	}

	option = g_dhcp_client_get_option(dhcp_client, G_DHCP_DOMAIN_NAME);
	if (option != NULL)
		domainname = g_strdup(option->data);

	option = g_dhcp_client_get_option(dhcp_client, G_DHCP_HOST_NAME);
	if (option != NULL)
		hostname = g_strdup(option->data);

	option = g_dhcp_client_get_option(dhcp_client, G_DHCP_NTP_SERVER);
	ns_entries = g_list_length(option);
	timeservers = g_try_new0(char *, ns_entries + 1);
	if (timeservers != NULL) {
		for (i = 0, list = option; list; list = list->next, i++)
			timeservers[i] = g_strdup(list->data);
		timeservers[ns_entries] = NULL;
	}

	option = g_dhcp_client_get_option(dhcp_client, 252);
	if (option != NULL)
		pac = g_strdup(option->data);

	__connman_ipconfig_set_method(ipconfig, CONNMAN_IPCONFIG_METHOD_DHCP);

	if (ip_change == TRUE) {
		__connman_ipconfig_set_local(ipconfig, address);
		__connman_ipconfig_set_prefixlen(ipconfig, prefixlen);
		__connman_ipconfig_set_gateway(ipconfig, gateway);
	}

	if (compare_string_arrays(nameservers, dhcp->nameservers) == FALSE) {
		if (dhcp->nameservers != NULL) {
			for (i = 0; dhcp->nameservers[i] != NULL; i++) {
				__connman_service_nameserver_remove(service,
						dhcp->nameservers[i], FALSE);
			}
			g_strfreev(dhcp->nameservers);
		}

		dhcp->nameservers = nameservers;

		for (i = 0; dhcp->nameservers != NULL &&
					dhcp->nameservers[i] != NULL; i++) {
			__connman_service_nameserver_append(service,
						dhcp->nameservers[i], FALSE);
		}
	} else {
		g_strfreev(nameservers);
	}

	if (compare_string_arrays(timeservers, dhcp->timeservers) == FALSE) {
		if (dhcp->timeservers != NULL) {
			for (i = 0; dhcp->timeservers[i] != NULL; i++) {
				__connman_service_timeserver_remove(service,
							dhcp->timeservers[i]);
			}
			g_strfreev(dhcp->timeservers);
		}

		dhcp->timeservers = timeservers;

		for (i = 0; dhcp->timeservers != NULL &&
					 dhcp->timeservers[i] != NULL; i++) {
			__connman_service_timeserver_append(service,
							dhcp->timeservers[i]);
		}
	} else {
		g_strfreev(timeservers);
	}

	if (g_strcmp0(pac, dhcp->pac) != 0) {
		g_free(dhcp->pac);
		dhcp->pac = pac;

		__connman_service_set_pac(service, dhcp->pac);
	}

	__connman_service_set_domainname(service, domainname);

	if (domainname != NULL)
		__connman_utsname_set_domainname(domainname);

	if (hostname != NULL)
		__connman_utsname_set_hostname(hostname);

	if (ip_change == TRUE)
		dhcp_valid(dhcp);

	__connman_6to4_probe(service);

	g_free(address);
	g_free(netmask);
	g_free(gateway);
	g_free(domainname);
	g_free(hostname);
}

static void ipv4ll_available_cb(GDHCPClient *dhcp_client, gpointer user_data)
{
	struct connman_dhcp *dhcp = user_data;
	char *address, *netmask;
	struct connman_service *service;
	struct connman_ipconfig *ipconfig;
	unsigned char prefixlen;

	DBG("IPV4LL available");

	service = __connman_service_lookup_from_network(dhcp->network);
	if (service == NULL)
		return;

	ipconfig = __connman_service_get_ip4config(service);
	if (ipconfig == NULL)
		return;

	address = g_dhcp_client_get_address(dhcp_client);
	netmask = g_dhcp_client_get_netmask(dhcp_client);

	prefixlen = __connman_ipconfig_netmask_prefix_len(netmask);

	__connman_ipconfig_set_method(ipconfig, CONNMAN_IPCONFIG_METHOD_DHCP);
	__connman_ipconfig_set_local(ipconfig, address);
	__connman_ipconfig_set_prefixlen(ipconfig, prefixlen);
	__connman_ipconfig_set_gateway(ipconfig, NULL);

	dhcp_valid(dhcp);

	g_free(address);
	g_free(netmask);
}

static void dhcp_debug(const char *str, void *data)
{
	connman_info("%s: %s\n", (const char *) data, str);
}

static int dhcp_request(struct connman_dhcp *dhcp)
{
	struct connman_service *service;
	struct connman_ipconfig *ipconfig;
	GDHCPClient *dhcp_client;
	GDHCPClientError error;
	const char *hostname;
	int index;

	DBG("dhcp %p", dhcp);

	index = connman_network_get_index(dhcp->network);

	dhcp_client = g_dhcp_client_new(G_DHCP_IPV4, index, &error);
	if (error != G_DHCP_CLIENT_ERROR_NONE)
		return -EINVAL;

	if (getenv("CONNMAN_DHCP_DEBUG"))
		g_dhcp_client_set_debug(dhcp_client, dhcp_debug, "DHCP");

	g_dhcp_client_set_id(dhcp_client);

	hostname = connman_utsname_get_hostname();
	if (hostname != NULL)
		g_dhcp_client_set_send(dhcp_client, G_DHCP_HOST_NAME, hostname);

	g_dhcp_client_set_request(dhcp_client, G_DHCP_HOST_NAME);
	g_dhcp_client_set_request(dhcp_client, G_DHCP_SUBNET);
	g_dhcp_client_set_request(dhcp_client, G_DHCP_DNS_SERVER);
	g_dhcp_client_set_request(dhcp_client, G_DHCP_DOMAIN_NAME);
	g_dhcp_client_set_request(dhcp_client, G_DHCP_NTP_SERVER);
	g_dhcp_client_set_request(dhcp_client, G_DHCP_ROUTER);
	g_dhcp_client_set_request(dhcp_client, 252);

	g_dhcp_client_register_event(dhcp_client,
			G_DHCP_CLIENT_EVENT_LEASE_AVAILABLE,
						lease_available_cb, dhcp);

	g_dhcp_client_register_event(dhcp_client,
			G_DHCP_CLIENT_EVENT_IPV4LL_AVAILABLE,
						ipv4ll_available_cb, dhcp);

	g_dhcp_client_register_event(dhcp_client,
			G_DHCP_CLIENT_EVENT_LEASE_LOST, lease_lost_cb, dhcp);

	g_dhcp_client_register_event(dhcp_client,
			G_DHCP_CLIENT_EVENT_IPV4LL_LOST, ipv4ll_lost_cb, dhcp);

	g_dhcp_client_register_event(dhcp_client,
			G_DHCP_CLIENT_EVENT_NO_LEASE, no_lease_cb, dhcp);

	dhcp->dhcp_client = dhcp_client;

	service = __connman_service_lookup_from_network(dhcp->network);
	ipconfig = __connman_service_get_ip4config(service);

	return g_dhcp_client_start(dhcp_client,
				__connman_ipconfig_get_dhcp_address(ipconfig));
}

static int dhcp_release(struct connman_dhcp *dhcp)
{
	DBG("dhcp %p", dhcp);

	if (dhcp->dhcp_client == NULL)
		return 0;

	g_dhcp_client_stop(dhcp->dhcp_client);
	g_dhcp_client_unref(dhcp->dhcp_client);

	dhcp->dhcp_client = NULL;

	return 0;
}

static void remove_network(gpointer user_data)
{
	struct connman_dhcp *dhcp = user_data;

	DBG("dhcp %p", dhcp);

	dhcp_invalidate(dhcp, FALSE);
	dhcp_release(dhcp);

	g_free(dhcp);
}

int __connman_dhcp_start(struct connman_network *network, dhcp_cb callback)
{
	struct connman_dhcp *dhcp;

	DBG("");

	dhcp = g_try_new0(struct connman_dhcp, 1);
	if (dhcp == NULL)
		return -ENOMEM;

	dhcp->network = network;
	dhcp->callback = callback;

	connman_network_ref(network);

	g_hash_table_replace(network_table, network, dhcp);

	return dhcp_request(dhcp);
}

void __connman_dhcp_stop(struct connman_network *network)
{
	DBG("");

	if (network_table == NULL)
		return;

	if (g_hash_table_remove(network_table, network) == TRUE)
		connman_network_unref(network);
}

int __connman_dhcp_init(void)
{
	DBG("");

	network_table = g_hash_table_new_full(g_direct_hash, g_direct_equal,
							NULL, remove_network);

	return 0;
}

void __connman_dhcp_cleanup(void)
{
	DBG("");

	g_hash_table_destroy(network_table);
	network_table = NULL;
}
