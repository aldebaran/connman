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
#include <connman/log.h>

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
	struct in_addr gateway;
	struct in_addr network;
	struct in_addr broadcast;
	struct in_addr nameserver;
};

static int set_ipv4(struct connman_element *element,
						struct connman_ipv4 *ipv4)
{
	struct ifreq ifr;
	struct rtentry rt;
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

	memset(&rt, 0, sizeof(rt));
	rt.rt_flags = RTF_UP | RTF_GATEWAY;

	addr = (struct sockaddr_in *) &rt.rt_dst;
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = INADDR_ANY;

	addr = (struct sockaddr_in *) &rt.rt_gateway;
	addr->sin_family = AF_INET;
	addr->sin_addr = ipv4->gateway;

	addr = (struct sockaddr_in *) &rt.rt_genmask;
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = INADDR_ANY;

	err = ioctl(sk, SIOCADDRT, &rt);

	close(sk);

	if (err < 0) {
		DBG("default route failed (%s)", strerror(errno));
		return -1;
	}

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

static int ipv4_probe(struct connman_element *element)
{
	struct connman_element *resolver;
	struct connman_ipv4 ipv4;
	const char *address = NULL, *netmask = NULL, *gateway = NULL;

	DBG("element %p name %s", element, element->name);

	connman_element_get_value(element,
				CONNMAN_PROPERTY_ID_IPV4_ADDRESS, &address);
	connman_element_get_value(element,
				CONNMAN_PROPERTY_ID_IPV4_NETMASK, &netmask);
	connman_element_get_value(element,
				CONNMAN_PROPERTY_ID_IPV4_GATEWAY, &gateway);

	DBG("address %s", address);
	DBG("netmask %s", netmask);
	DBG("gateway %s", gateway);

	if (address == NULL || netmask == NULL || gateway == NULL)
		return -EINVAL;

	memset(&ipv4, 0, sizeof(ipv4));
	ipv4.address.s_addr = inet_addr(address);
	ipv4.netmask.s_addr = inet_addr(netmask);
	ipv4.gateway.s_addr = inet_addr(gateway);

	set_ipv4(element, &ipv4);

	resolver = connman_element_create(NULL);

	resolver->type = CONNMAN_ELEMENT_TYPE_RESOLVER;
	resolver->index = element->index;

	connman_element_register(resolver, element);

	return 0;
}

static void ipv4_remove(struct connman_element *element)
{
	DBG("element %p name %s", element, element->name);

	clear_ipv4(element);
}

static struct connman_driver ipv4_driver = {
	.name		= "ipv4",
	.type		= CONNMAN_ELEMENT_TYPE_IPV4,
	.probe		= ipv4_probe,
	.remove		= ipv4_remove,
};

static int ipv4_init(void)
{
	return connman_driver_register(&ipv4_driver);
}

static void ipv4_exit(void)
{
	connman_driver_unregister(&ipv4_driver);
}

CONNMAN_PLUGIN_DEFINE("ipv4", "IPv4 configuration plugin", VERSION,
							ipv4_init, ipv4_exit)
