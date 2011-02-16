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

#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "connman.h"

static int ipv4_probe(struct connman_element *element)
{
	struct connman_service *service;
	const char *address = NULL, *netmask = NULL, *broadcast = NULL;
	const char *peer = NULL, *nameserver = NULL, *pac = NULL;
	const char *domainname = NULL, *ipv4_gw = NULL, *ipv6_gw = NULL;
	char *timeserver = NULL;
	unsigned char prefixlen;
	int err;

	DBG("element %p name %s", element, element->name);
	connman_element_get_value(element,
				CONNMAN_PROPERTY_ID_IPV4_ADDRESS, &address);
	connman_element_get_value(element,
				CONNMAN_PROPERTY_ID_IPV4_NETMASK, &netmask);
	connman_element_get_value(element,
				CONNMAN_PROPERTY_ID_IPV4_BROADCAST, &broadcast);
	connman_element_get_value(element,
				CONNMAN_PROPERTY_ID_IPV4_PEER, &peer);

	connman_element_get_value(element,
			CONNMAN_PROPERTY_ID_IPV4_NAMESERVER, &nameserver);
	connman_element_get_value(element,
			CONNMAN_PROPERTY_ID_IPV4_TIMESERVER, &timeserver);
	connman_element_get_value(element,
			CONNMAN_PROPERTY_ID_IPV4_PAC, &pac);

	connman_element_get_value(element,
			CONNMAN_PROPERTY_ID_DOMAINNAME, &domainname);

	connman_element_get_value(element,
			CONNMAN_PROPERTY_ID_IPV4_GATEWAY, &ipv4_gw);
	connman_element_get_value(element,
			CONNMAN_PROPERTY_ID_IPV6_GATEWAY, &ipv6_gw);

	DBG("address %s", address);
	DBG("peer %s", peer);
	DBG("netmask %s", netmask);
	DBG("broadcast %s", broadcast);

	if (address == NULL)
		return -EINVAL;

	prefixlen = __connman_ipconfig_netmask_prefix_len(netmask);

	if ((__connman_inet_modify_address(RTM_NEWADDR,
			NLM_F_REPLACE | NLM_F_ACK, element->index,
			AF_INET, address, peer, prefixlen, broadcast)) < 0)
		DBG("address setting failed");

	service = __connman_element_get_service(element);

	if (pac != NULL)
		__connman_service_set_proxy_autoconfig(service, pac);

	if (nameserver != NULL)
		__connman_service_nameserver_append(service, nameserver);

	if (domainname != NULL)
		__connman_service_set_domainname(service, domainname);

	connman_timeserver_append(timeserver);

	err = __connman_connection_gateway_add(service, ipv4_gw, ipv6_gw, peer);
	if (err < 0)
		return err;

	return 0;
}

static void ipv4_remove(struct connman_element *element)
{
	struct connman_service *service;
	const char *address = NULL, *netmask = NULL, *broadcast = NULL;
	const char *peer = NULL, *nameserver = NULL;
	char *timeserver = NULL;
	unsigned char prefixlen;

	DBG("element %p name %s", element, element->name);

	connman_element_get_value(element,
				CONNMAN_PROPERTY_ID_IPV4_ADDRESS, &address);
	connman_element_get_value(element,
				CONNMAN_PROPERTY_ID_IPV4_NETMASK, &netmask);
	connman_element_get_value(element,
				CONNMAN_PROPERTY_ID_IPV4_BROADCAST, &broadcast);
	connman_element_get_value(element,
				CONNMAN_PROPERTY_ID_IPV4_PEER, &peer);

	connman_element_get_value(element,
			CONNMAN_PROPERTY_ID_IPV4_NAMESERVER, &nameserver);
	connman_element_get_value(element,
			CONNMAN_PROPERTY_ID_IPV4_TIMESERVER, &timeserver);

	connman_timeserver_remove(timeserver);

	DBG("address %s", address);
	DBG("peer %s", peer);
	DBG("netmask %s", netmask);
	DBG("broadcast %s", broadcast);

	service = __connman_element_get_service(element);

	__connman_service_set_domainname(service, NULL);

	__connman_connection_gateway_remove(service);

	if (nameserver != NULL)
		__connman_service_nameserver_remove(service, nameserver);

	prefixlen = __connman_ipconfig_netmask_prefix_len(netmask);

	if ((__connman_inet_modify_address(RTM_DELADDR, 0, element->index,
			AF_INET, address, peer, prefixlen, broadcast) < 0))
		DBG("address removal failed");

	connman_element_unref(element);
}

static struct connman_driver ipv4_driver = {
	.name		= "ipv4",
	.type		= CONNMAN_ELEMENT_TYPE_IPV4,
	.priority	= CONNMAN_DRIVER_PRIORITY_LOW,
	.probe		= ipv4_probe,
	.remove		= ipv4_remove,
};

int __connman_ipv4_init(void)
{
	DBG("");

	return connman_driver_register(&ipv4_driver);
}

void __connman_ipv4_cleanup(void)
{
	connman_driver_unregister(&ipv4_driver);
}
