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

#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/route.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <connman/plugin.h>
#include <connman/driver.h>
#include <connman/resolver.h>
#include <connman/rtnl.h>
#include <connman/log.h>

#include "inet.h"

enum connman_ipv4_method {
	CONNMAN_IPV4_METHOD_UNKNOWN = 0,
	CONNMAN_IPV4_METHOD_OFF     = 1,
	CONNMAN_IPV4_METHOD_STATIC  = 2,
	CONNMAN_IPV4_METHOD_DHCP    = 3,
};

struct connman_ipv4 {
	enum connman_ipv4_method method;
	struct in_addr address;
	struct in_addr netmask;
	struct in_addr broadcast;
};

struct gateway_data {
	int index;
	char *gateway;
};

static GSList *gateway_list = NULL;

static struct gateway_data *find_gateway(int index, const char *gateway)
{
	GSList *list;

	if (gateway == NULL)
		return NULL;

	for (list = gateway_list; list; list = list->next) {
		struct gateway_data *data = list->data;

		if (data->gateway == NULL)
			continue;

		if (data->index == index &&
				g_str_equal(data->gateway, gateway) == TRUE)
			return data;
	}

	return NULL;
}

static int set_ipv4(struct connman_element *element,
			struct connman_ipv4 *ipv4, const char *nameserver)
{
	struct ifreq ifr;
	struct sockaddr_in *addr;
	int sk, err;

	DBG("element %p ipv4 %p", element, ipv4);

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = element->index;

	if (ioctl(sk, SIOCGIFNAME, &ifr) < 0) {
		close(sk);
		return -1;
	}

	DBG("ifname %s", ifr.ifr_name);

	addr = (struct sockaddr_in *) &ifr.ifr_addr;
	addr->sin_family = AF_INET;
	addr->sin_addr = ipv4->address;

	err = ioctl(sk, SIOCSIFADDR, &ifr);

	if (err < 0)
		DBG("address setting failed (%s)", strerror(errno));

	addr = (struct sockaddr_in *) &ifr.ifr_netmask;
	addr->sin_family = AF_INET;
	addr->sin_addr = ipv4->netmask;

	err = ioctl(sk, SIOCSIFNETMASK, &ifr);

	if (err < 0)
		DBG("netmask setting failed (%s)", strerror(errno));

	addr = (struct sockaddr_in *) &ifr.ifr_broadaddr;
	addr->sin_family = AF_INET;
	addr->sin_addr = ipv4->broadcast;

	err = ioctl(sk, SIOCSIFBRDADDR, &ifr);

	if (err < 0)
		DBG("broadcast setting failed (%s)", strerror(errno));

	close(sk);

	connman_resolver_append(ifr.ifr_name, NULL, nameserver);

	return 0;
}

static int clear_ipv4(struct connman_element *element)
{
	struct ifreq ifr;
	struct sockaddr_in *addr;
	int sk, err;

	DBG("element %p", element);

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = element->index;

	if (ioctl(sk, SIOCGIFNAME, &ifr) < 0) {
		close(sk);
		return -1;
	}

	DBG("ifname %s", ifr.ifr_name);

	connman_resolver_remove_all(ifr.ifr_name);

	addr = (struct sockaddr_in *) &ifr.ifr_addr;
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = INADDR_ANY;

	//err = ioctl(sk, SIOCDIFADDR, &ifr);
	err = ioctl(sk, SIOCSIFADDR, &ifr);

	close(sk);

	if (err < 0 && errno != EADDRNOTAVAIL) {
		DBG("address removal failed (%s)", strerror(errno));
		return -1;
	}

	return 0;
}

static int set_route(struct connman_element *element, const char *gateway)
{
	struct ifreq ifr;
	struct rtentry rt;
	struct sockaddr_in *addr;
	int sk, err;

	DBG("element %p", element);

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = element->index;

	if (ioctl(sk, SIOCGIFNAME, &ifr) < 0) {
		close(sk);
		return -1;
	}

	DBG("ifname %s", ifr.ifr_name);

	memset(&rt, 0, sizeof(rt));
	rt.rt_flags = RTF_UP | RTF_GATEWAY;

	addr = (struct sockaddr_in *) &rt.rt_dst;
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = INADDR_ANY;

	addr = (struct sockaddr_in *) &rt.rt_gateway;
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = inet_addr(gateway);

	addr = (struct sockaddr_in *) &rt.rt_genmask;
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = INADDR_ANY;

	err = ioctl(sk, SIOCADDRT, &rt);
	if (err < 0)
		DBG("default route setting failed (%s)", strerror(errno));

	close(sk);

	return err;
}

static int del_route(struct connman_element *element, const char *gateway)
{
	struct ifreq ifr;
	struct rtentry rt;
	struct sockaddr_in *addr;
	int sk, err;

	DBG("element %p", element);

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = element->index;

	if (ioctl(sk, SIOCGIFNAME, &ifr) < 0) {
		close(sk);
		return -1;
	}

	DBG("ifname %s", ifr.ifr_name);

	memset(&rt, 0, sizeof(rt));
	rt.rt_flags = RTF_UP | RTF_GATEWAY;

	addr = (struct sockaddr_in *) &rt.rt_dst;
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = INADDR_ANY;

	addr = (struct sockaddr_in *) &rt.rt_gateway;
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = inet_addr(gateway);

	addr = (struct sockaddr_in *) &rt.rt_genmask;
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = INADDR_ANY;

	err = ioctl(sk, SIOCDELRT, &rt);
	if (err < 0)
		DBG("default route removal failed (%s)", strerror(errno));

	close(sk);

	return err;
}

static int conn_probe(struct connman_element *element)
{
	const char *gateway = NULL;

	DBG("element %p name %s", element, element->name);

	if (element->parent == NULL)
		return -ENODEV;

	if (element->parent->type != CONNMAN_ELEMENT_TYPE_IPV4)
		return -ENODEV;

	connman_element_get_value(element,
				CONNMAN_PROPERTY_ID_IPV4_GATEWAY, &gateway);

	DBG("gateway %s", gateway);

	if (gateway == NULL)
		return 0;

	if (g_slist_length(gateway_list) > 0) {
		DBG("default already present");
		return 0;
	}

	set_route(element, gateway);

	connman_element_set_enabled(element, TRUE);

	return 0;
}

static void conn_remove(struct connman_element *element)
{
	DBG("element %p name %s", element, element->name);
}

static int conn_enable(struct connman_element *element)
{
	const char *gateway = NULL;

	DBG("element %p name %s", element, element->name);

	connman_element_get_value(element,
				CONNMAN_PROPERTY_ID_IPV4_GATEWAY, &gateway);

	DBG("gateway %s", gateway);

	if (gateway == NULL)
		return -EINVAL;

	set_route(element, gateway);

	return 0;
}

static int conn_disable(struct connman_element *element)
{
	const char *gateway = NULL;

	DBG("element %p name %s", element, element->name);

	connman_element_get_value(element,
				CONNMAN_PROPERTY_ID_IPV4_GATEWAY, &gateway);

	DBG("gateway %s", gateway);

	if (gateway == NULL)
		return -EINVAL;

	del_route(element, gateway);

	return 0;
}

static struct connman_driver conn_driver = {
	.name		= "ipv4-connection",
	.type		= CONNMAN_ELEMENT_TYPE_CONNECTION,
	.probe		= conn_probe,
	.remove		= conn_remove,
	.enable		= conn_enable,
	.disable	= conn_disable,
};

static int ipv4_probe(struct connman_element *element)
{
	struct connman_element *connection;
	struct connman_ipv4 ipv4;
	const char *address = NULL, *netmask = NULL, *broadcast = NULL;
	const char *nameserver = NULL;

	DBG("element %p name %s", element, element->name);

	connman_element_get_value(element,
				CONNMAN_PROPERTY_ID_IPV4_ADDRESS, &address);
	connman_element_get_value(element,
				CONNMAN_PROPERTY_ID_IPV4_NETMASK, &netmask);
	connman_element_get_value(element,
				CONNMAN_PROPERTY_ID_IPV4_BROADCAST, &broadcast);

	connman_element_get_value(element,
			CONNMAN_PROPERTY_ID_IPV4_NAMESERVER, &nameserver);

	DBG("address %s", address);
	DBG("netmask %s", netmask);
	DBG("broadcast %s", broadcast);

	if (address == NULL || netmask == NULL)
		return -EINVAL;

	memset(&ipv4, 0, sizeof(ipv4));
	ipv4.address.s_addr = inet_addr(address);
	ipv4.netmask.s_addr = inet_addr(netmask);
	ipv4.broadcast.s_addr = inet_addr(broadcast);

	set_ipv4(element, &ipv4, nameserver);

	connection = connman_element_create(NULL);

	connection->type = CONNMAN_ELEMENT_TYPE_CONNECTION;
	connection->index = element->index;

	if (connman_element_register(connection, element) < 0)
		connman_element_unref(connection);

	return 0;
}

static void ipv4_remove(struct connman_element *element)
{
	DBG("element %p name %s", element, element->name);

	clear_ipv4(element);
}

static struct connman_driver ipv4_driver = {
	.name		= "ipv4-address",
	.type		= CONNMAN_ELEMENT_TYPE_IPV4,
	.probe		= ipv4_probe,
	.remove		= ipv4_remove,
};

static void ipv4_newgateway(int index, const char *gateway)
{
	struct gateway_data *data;

	DBG("index %d gateway %s", index, gateway);

	data = find_gateway(index, gateway);
	if (data != NULL)
		return;

	data = g_try_new0(struct gateway_data, 1);
	if (data == NULL)
		return;

	data->index = index;
	data->gateway = g_strdup(gateway);

	gateway_list = g_slist_append(gateway_list, data);
}

static void ipv4_delgateway(int index, const char *gateway)
{
	struct gateway_data *data;

	DBG("index %d gateway %s", index, gateway);

	data = find_gateway(index, gateway);
	if (data == NULL)
		return;

	gateway_list = g_slist_remove(gateway_list, data);

	g_free(data->gateway);
	g_free(data);
}

static struct connman_rtnl ipv4_rtnl = {
	.name		= "ipv4-rtnl",
	.newgateway	= ipv4_newgateway,
	.delgateway	= ipv4_delgateway,
};

static int ipv4_init(void)
{
	int err;

	err = connman_rtnl_register(&ipv4_rtnl);
	if (err < 0)
		return err;

	connman_rtnl_send_getroute();

	err = connman_driver_register(&conn_driver);
	if (err < 0) {
		connman_rtnl_unregister(&ipv4_rtnl);
		return err;
	}

	err = connman_driver_register(&ipv4_driver);
	if (err < 0) {
		connman_driver_unregister(&conn_driver);
		connman_rtnl_unregister(&ipv4_rtnl);
	}

	return err;
}

static void ipv4_exit(void)
{
	GSList *list;

	connman_driver_unregister(&conn_driver);
	connman_driver_unregister(&ipv4_driver);

	connman_rtnl_unregister(&ipv4_rtnl);

	for (list = gateway_list; list; list = list->next) {
		struct gateway_data *data = list->data;

		DBG("index %d gateway %s", data->index, data->gateway);

		g_free(data->gateway);
		g_free(data);
		list->data = NULL;
	}

	g_slist_free(gateway_list);
	gateway_list = NULL;
}

CONNMAN_PLUGIN_DEFINE(ipv4, "IPv4 configuration plugin", VERSION,
							ipv4_init, ipv4_exit)
