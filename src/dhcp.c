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
	char *timeserver;
	char *pac;

	GDHCPClient *dhcp_client;
};

static GHashTable *network_table;

static void dhcp_free(struct connman_dhcp *dhcp)
{
	g_strfreev(dhcp->nameservers);
	g_free(dhcp->timeserver);
	g_free(dhcp->pac);

	dhcp->nameservers = NULL;
	dhcp->timeserver = NULL;
	dhcp->pac = NULL;
}

static void dhcp_invalid(struct connman_dhcp *dhcp)
{
	struct connman_service *service;
	struct connman_ipconfig *ipconfig;
	int i;

	service = __connman_service_lookup_from_network(dhcp->network);
	if (service == NULL)
		return;

	ipconfig = __connman_service_get_ip4config(service);
	if (ipconfig == NULL)
		return;

	__connman_service_set_domainname(service, NULL);
	__connman_service_set_pac(service, NULL);
	__connman_service_timeserver_remove(service, dhcp->timeserver);

	for (i = 0; dhcp->nameservers[i] != NULL; i++) {
		__connman_service_nameserver_remove(service,
						dhcp->nameservers[i]);
	}

	__connman_ipconfig_set_local(ipconfig, NULL);
	__connman_ipconfig_set_broadcast(ipconfig, NULL);
	__connman_ipconfig_set_gateway(ipconfig, NULL);
	__connman_ipconfig_set_prefixlen(ipconfig, 0);

	if (dhcp->callback != NULL)
		dhcp->callback(dhcp->network, FALSE);

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

	dhcp_invalid(dhcp);
}

static void lease_lost_cb(GDHCPClient *dhcp_client, gpointer user_data)
{
	struct connman_dhcp *dhcp = user_data;

	DBG("Lease lost");

	dhcp_invalid(dhcp);
}

static void ipv4ll_lost_cb(GDHCPClient *dhcp_client, gpointer user_data)
{
	struct connman_dhcp *dhcp = user_data;

	DBG("Lease lost");

	dhcp_invalid(dhcp);
}

static void lease_available_cb(GDHCPClient *dhcp_client, gpointer user_data)
{
	struct connman_dhcp *dhcp = user_data;
	GList *list, *option = NULL;
	char *address, *netmask = NULL, *gateway = NULL, *net = NULL;
	char *domainname = NULL, *hostname = NULL;
	int ns_entries;
	struct connman_ipconfig *ipconfig;
	struct connman_service *service;
	unsigned char prefixlen;
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

	address = g_dhcp_client_get_address(dhcp_client);

	option = g_dhcp_client_get_option(dhcp_client, G_DHCP_SUBNET);
	if (option != NULL)
		netmask = g_strdup(option->data);

	option = g_dhcp_client_get_option(dhcp_client, G_DHCP_ROUTER);
	if (option != NULL)
		gateway = g_strdup(option->data);

	option = g_dhcp_client_get_option(dhcp_client, G_DHCP_DNS_SERVER);
	for (ns_entries = 0, list = option; list; list = list->next)
		ns_entries += 1;
	dhcp->nameservers = g_try_new0(char *, ns_entries + 1);
	if (dhcp->nameservers) {
		for (i = 0, list = option; list; list = list->next)
			dhcp->nameservers[i] = g_strdup(list->data);
		dhcp->nameservers[ns_entries] = NULL;
	}

	option = g_dhcp_client_get_option(dhcp_client, G_DHCP_DOMAIN_NAME);
	if (option != NULL)
		domainname = g_strdup(option->data);

	option = g_dhcp_client_get_option(dhcp_client, G_DHCP_HOST_NAME);
	if (option != NULL)
		hostname = g_strdup(option->data);

	option = g_dhcp_client_get_option(dhcp_client, G_DHCP_NTP_SERVER);
	if (option != NULL)
		dhcp->timeserver = g_strdup(option->data);

	option = g_dhcp_client_get_option(dhcp_client, 252);
	if (option != NULL)
		dhcp->pac = g_strdup(option->data);

	prefixlen = __connman_ipconfig_netmask_prefix_len(netmask);

	connman_ipconfig_set_method(ipconfig, CONNMAN_IPCONFIG_METHOD_DHCP);
	__connman_ipconfig_set_local(ipconfig, address);
	__connman_ipconfig_set_prefixlen(ipconfig, prefixlen);
	__connman_ipconfig_set_gateway(ipconfig, gateway);

	for (i = 0; dhcp->nameservers[i] != NULL; i++) {
		__connman_service_nameserver_append(service,
					dhcp->nameservers[i]);
	}
	__connman_service_timeserver_append(service, dhcp->timeserver);
	__connman_service_set_pac(service, dhcp->pac);
	__connman_service_set_domainname(service, domainname);

	if (domainname != NULL)
		__connman_utsname_set_domainname(domainname);

	if (hostname != NULL)
		__connman_utsname_set_hostname(hostname);

	dhcp_valid(dhcp);

	g_free(address);
	g_free(netmask);
	g_free(gateway);
	g_free(net);
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

	connman_ipconfig_set_method(ipconfig, CONNMAN_IPCONFIG_METHOD_DHCP);
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

	return g_dhcp_client_start(dhcp_client);
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

	dhcp_release(dhcp);

	dhcp_free(dhcp);
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

	g_hash_table_replace(network_table, network, dhcp);

	return dhcp_request(dhcp);
}

void __connman_dhcp_stop(struct connman_network *network)
{
	struct connman_dhcp *dhcp;

	DBG("");

	dhcp = g_hash_table_lookup(network_table, network);
	if (dhcp == NULL)
		return;

	dhcp_release(dhcp);

	g_hash_table_remove(network_table, network);
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
}
