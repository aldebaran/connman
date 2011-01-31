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

#include <gdhcp/gdhcp.h>

#include <glib.h>

#include "connman.h"

enum connman_dhcp_state {
	CONNMAN_DHCP_STATE_UNKNOWN  = 0,
	CONNMAN_DHCP_STATE_IDLE     = 1,
	CONNMAN_DHCP_STATE_BOUND    = 2,
	CONNMAN_DHCP_STATE_RENEW    = 3,
	CONNMAN_DHCP_STATE_FAIL     = 4,
};

struct connman_dhcp {
	GDHCPClient *dhcp_client;

	int index;
	enum connman_dhcp_state state;

	struct connman_element *element;
};

static void dhcp_set_value(struct connman_dhcp *dhcp,
				const char *key, const char *value)
{
	char **nameservers;

	if (g_strcmp0(key, "Address") == 0) {
		g_free(dhcp->element->ipv4.address);
		dhcp->element->ipv4.address = g_strdup(value);
	} else if (g_strcmp0(key, "Netmask") == 0) {
		g_free(dhcp->element->ipv4.netmask);
		dhcp->element->ipv4.netmask = g_strdup(value);
	} else if (g_strcmp0(key, "Gateway") == 0) {
		g_free(dhcp->element->ipv4.gateway);
		dhcp->element->ipv4.gateway = g_strdup(value);
	} else if (g_strcmp0(key, "Network") == 0) {
		g_free(dhcp->element->ipv4.network);
		dhcp->element->ipv4.network = g_strdup(value);
	} else if (g_strcmp0(key, "Broadcast") == 0) {
		g_free(dhcp->element->ipv4.broadcast);
		dhcp->element->ipv4.broadcast = g_strdup(value);
	} else if (g_strcmp0(key, "Nameserver") == 0) {
		g_free(dhcp->element->ipv4.nameserver);
		nameservers = g_strsplit_set(value, " ", 0);
		/* FIXME: The ipv4 structure can only hold one nameserver, so
		 * we are only able to pass along the first nameserver sent by
		 * the DHCP server.  If this situation changes, we should
		 * retain all of them.
		 */
		dhcp->element->ipv4.nameserver = g_strdup(nameservers[0]);
		g_strfreev(nameservers);
	} else if (g_strcmp0(key, "Domainname") == 0) {
		g_free(dhcp->element->domainname);
		dhcp->element->domainname = g_strdup(value);

		__connman_utsname_set_domainname(value);
	} else if (g_strcmp0(key, "Hostname") == 0) {
		g_free(dhcp->element->hostname);
		dhcp->element->hostname = g_strdup(value);

		__connman_utsname_set_hostname(value);
	} else if (g_strcmp0(key, "Timeserver") == 0) {
		connman_info("Timeserver %s", value);

		g_free(dhcp->element->ipv4.timeserver);
		dhcp->element->ipv4.timeserver = g_strdup(value);
	} else if (g_strcmp0(key, "MTU") == 0) {
	} else if (g_strcmp0(key, "PAC") == 0) {
		connman_info("PAC configuration %s", value);

		g_free(dhcp->element->ipv4.pac);
		dhcp->element->ipv4.pac = g_strdup(value);
	}
}

static void dhcp_bound(struct connman_dhcp *dhcp)
{
	struct connman_element *element;

	DBG("dhcp %p", dhcp);

	element = connman_element_create(NULL);
	if (element == NULL)
		return;

	element->type = CONNMAN_ELEMENT_TYPE_IPV4;
	element->index = dhcp->index;

	connman_element_update(dhcp->element);

	if (connman_element_register(element, dhcp->element) < 0)
		connman_element_unref(element);
}

static void no_lease_cb(GDHCPClient *dhcp_client, gpointer user_data)
{
	struct connman_dhcp *dhcp = user_data;

	DBG("No lease available");

	connman_element_set_error(dhcp->element,
					CONNMAN_ELEMENT_ERROR_FAILED);
}

static void lease_lost_cb(GDHCPClient *dhcp_client, gpointer user_data)
{
	DBG("Lease lost");
}

static void ipv4ll_lost_cb(GDHCPClient *dhcp_client, gpointer user_data)
{
	struct connman_dhcp *dhcp = user_data;

	DBG("Lease lost");

	connman_element_unregister_children(dhcp->element);
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
		dhcp_set_value(dhcp, "Address", address);
	g_free(address);

	option = g_dhcp_client_get_option(dhcp_client, G_DHCP_SUBNET);
	if (option != NULL)
		dhcp_set_value(dhcp, "Netmask", option->data);

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

		dhcp_set_value(dhcp, "Nameserver", nameservers);
	}
	g_free(nameservers);

	option = g_dhcp_client_get_option(dhcp_client, G_DHCP_DOMAIN_NAME);
	if (option != NULL)
		dhcp_set_value(dhcp, "Domainname", option->data);

	option = g_dhcp_client_get_option(dhcp_client, G_DHCP_ROUTER);
	if (option != NULL)
		dhcp_set_value(dhcp, "Gateway", option->data);

	option = g_dhcp_client_get_option(dhcp_client, G_DHCP_HOST_NAME);
	if (option != NULL)
		dhcp_set_value(dhcp, "Hostname", option->data);

	option = g_dhcp_client_get_option(dhcp_client, G_DHCP_NTP_SERVER);
	if (option != NULL)
		dhcp_set_value(dhcp, "Timeserver", option->data);

	option = g_dhcp_client_get_option(dhcp_client, 252);
	if (option != NULL)
		dhcp_set_value(dhcp, "PAC", option->data);

	dhcp_bound(dhcp);
}

static void ipv4ll_available_cb(GDHCPClient *dhcp_client, gpointer user_data)
{
	struct connman_dhcp *dhcp = user_data;
	char *address, *netmask;

	DBG("IPV4LL available");

	address = g_dhcp_client_get_address(dhcp_client);
	if (address != NULL)
		dhcp_set_value(dhcp, "Address", address);

	netmask = g_dhcp_client_get_netmask(dhcp_client);
	if (netmask != NULL)
		dhcp_set_value(dhcp, "Netmask", netmask);

	g_free(address);
	g_free(netmask);

	dhcp_bound(dhcp);
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

	index = dhcp->index;

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

	g_dhcp_client_stop(dhcp->dhcp_client);
	g_dhcp_client_unref(dhcp->dhcp_client);

	return 0;
}

static int dhcp_probe(struct connman_element *element)
{
	struct connman_dhcp *dhcp;

	DBG("element %p name %s", element, element->name);

	dhcp = g_try_new0(struct connman_dhcp, 1);
	if (dhcp == NULL)
		return -ENOMEM;

	dhcp->index = element->index;
	dhcp->state = CONNMAN_DHCP_STATE_IDLE;

	dhcp->element = element;

	connman_element_set_data(element, dhcp);

	dhcp_request(dhcp);

	return 0;
}

static void dhcp_remove(struct connman_element *element)
{
	struct connman_dhcp *dhcp = connman_element_get_data(element);

	DBG("element %p name %s", element, element->name);

	connman_element_set_data(element, NULL);

	dhcp_release(dhcp);
	g_free(dhcp);

	connman_element_unref(element);
}

static void dhcp_change(struct connman_element *element)
{
	DBG("element %p name %s", element, element->name);

	if (element->state == CONNMAN_ELEMENT_STATE_ERROR)
		connman_element_set_error(element->parent,
					CONNMAN_ELEMENT_ERROR_DHCP_FAILED);
}

static struct connman_driver dhcp_driver = {
	.name		= "dhcp",
	.type		= CONNMAN_ELEMENT_TYPE_DHCP,
	.priority	= CONNMAN_DRIVER_PRIORITY_LOW,
	.probe		= dhcp_probe,
	.remove		= dhcp_remove,
	.change		= dhcp_change,
};

int __connman_dhcp_init(void)
{
	return connman_driver_register(&dhcp_driver);
}

void __connman_dhcp_cleanup(void)
{
	connman_driver_unregister(&dhcp_driver);
}
