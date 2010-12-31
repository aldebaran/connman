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

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/dhcp.h>
#include <connman/utsname.h>
#include <connman/log.h>

#include <gdhcp/gdhcp.h>

static void dhcp_debug(const char *str, void *data)
{
	connman_info("%s: %s\n", (const char *) data, str);
}

static void no_lease_cb(GDHCPClient *dhcp_client, gpointer user_data)
{
	struct connman_dhcp *dhcp = user_data;

	DBG("No lease available");

	connman_dhcp_fail(dhcp);
}

static void lease_lost_cb(GDHCPClient *dhcp_client, gpointer user_data)
{
	DBG("Lease lost");
}

static void ipv4ll_lost_cb(GDHCPClient *dhcp_client, gpointer user_data)
{
	struct connman_dhcp *dhcp = user_data;

	DBG("Lease lost");

	connman_dhcp_release(dhcp);
}

static void lease_available_cb(GDHCPClient *dhcp_client, gpointer user_data)
{
	struct connman_dhcp *dhcp = user_data;
	GList *list, *option = NULL;
	char *address, *nameservers;
	size_t ns_strlen = 0;

	DBG("Lease available");

	address = g_dhcp_client_get_address(dhcp_client);
	if (address != NULL)
		connman_dhcp_set_value(dhcp, "Address", address);
	g_free(address);

	option = g_dhcp_client_get_option(dhcp_client, G_DHCP_SUBNET);
	if (option != NULL)
		connman_dhcp_set_value(dhcp, "Netmask", option->data);

	option = g_dhcp_client_get_option(dhcp_client, G_DHCP_DNS_SERVER);
	for (list = option; list; list = list->next)
		ns_strlen += strlen((char *) list->data) + 2;
	nameservers = g_try_malloc0(ns_strlen);
	if (nameservers) {
		char *ns_index = nameservers;

		for (list = option; list; list = list->next) {
			sprintf(ns_index, "%s ", (char *) list->data);
			ns_index += strlen((char *) list->data) + 1;
		}

		connman_dhcp_set_value(dhcp, "Nameserver", nameservers);
	}
	g_free(nameservers);

	option = g_dhcp_client_get_option(dhcp_client, G_DHCP_DOMAIN_NAME);
	if (option != NULL)
		connman_dhcp_set_value(dhcp, "Domainname", option->data);

	option = g_dhcp_client_get_option(dhcp_client, G_DHCP_ROUTER);
	if (option != NULL)
		connman_dhcp_set_value(dhcp, "Gateway", option->data);

	option = g_dhcp_client_get_option(dhcp_client, G_DHCP_HOST_NAME);
	if (option != NULL)
		connman_dhcp_set_value(dhcp, "Hostname", option->data);

	option = g_dhcp_client_get_option(dhcp_client, G_DHCP_NTP_SERVER);
	if (option != NULL)
		connman_dhcp_set_value(dhcp, "Timeserver", option->data);

	option = g_dhcp_client_get_option(dhcp_client, 252);
	if (option != NULL)
		connman_dhcp_set_value(dhcp, "PAC", option->data);

	connman_dhcp_bound(dhcp);
}

static void ipv4ll_available_cb(GDHCPClient *dhcp_client, gpointer user_data)
{
	struct connman_dhcp *dhcp = user_data;
	char *address, *netmask;

	DBG("IPV4LL available");

	address = g_dhcp_client_get_address(dhcp_client);
	if (address != NULL)
		connman_dhcp_set_value(dhcp, "Address", address);

	netmask = g_dhcp_client_get_netmask(dhcp_client);
	if (netmask != NULL)
		connman_dhcp_set_value(dhcp, "Netmask", netmask);

	g_free(address);
	g_free(netmask);

	connman_dhcp_bound(dhcp);
}

static int dhcp_request(struct connman_dhcp *dhcp)
{
	GDHCPClient *dhcp_client;
	GDHCPClientError error;
	const char *hostname;
	int index;

	DBG("dhcp %p", dhcp);

	index = connman_dhcp_get_index(dhcp);

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

	connman_dhcp_set_data(dhcp, dhcp_client);

	g_dhcp_client_ref(dhcp_client);

	return g_dhcp_client_start(dhcp_client);
}

static int dhcp_release(struct connman_dhcp *dhcp)
{
	GDHCPClient *dhcp_client = connman_dhcp_get_data(dhcp);

	DBG("dhcp %p", dhcp);

	g_dhcp_client_stop(dhcp_client);
	g_dhcp_client_unref(dhcp_client);

	return 0;
}

static struct connman_dhcp_driver dhcp_driver = {
	.name		= "dhcp",
	.priority	= CONNMAN_DHCP_PRIORITY_DEFAULT,
	.request	= dhcp_request,
	.release	= dhcp_release,
};

static int dhcp_init(void)
{
	return connman_dhcp_driver_register(&dhcp_driver);
}

static void dhcp_exit(void)
{
	connman_dhcp_driver_unregister(&dhcp_driver);
}

CONNMAN_PLUGIN_DEFINE(dhcp, "Generic DHCP plugin", VERSION,
			CONNMAN_PLUGIN_PRIORITY_DEFAULT, dhcp_init, dhcp_exit)
