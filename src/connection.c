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

#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/route.h>

#include <gdbus.h>

#include "connman.h"

struct gateway_data {
	int index;
	char *gateway;
	struct connman_element *element;
	unsigned int order;
	gboolean active;
	/* VPN extra data */
	gboolean vpn;
	char *vpn_ip;
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

static int add_vpn_host(struct connman_element *element,
			const char *gateway,
			const char *host)
{
	struct ifreq ifr;
	struct rtentry rt;
	struct sockaddr_in addr;
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
	rt.rt_flags = RTF_UP | RTF_HOST | RTF_GATEWAY;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(host);
	memcpy(&rt.rt_dst, &addr, sizeof(rt.rt_dst));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(gateway);
	memcpy(&rt.rt_gateway, &addr, sizeof(rt.rt_gateway));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_NONE;
	memcpy(&rt.rt_genmask, &addr, sizeof(rt.rt_genmask));

	rt.rt_dev = ifr.ifr_name;

	err = ioctl(sk, SIOCADDRT, &rt);
	if (err < 0)
		connman_error("Setting VPN host failed (%s)",
			      strerror(errno));

	close(sk);

	return err;
}

static int del_vpn_host(const char *host)
{
	struct rtentry rt;
	struct sockaddr_in addr;
	int sk, err;

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0)
		return -1;

	memset(&rt, 0, sizeof(rt));
	rt.rt_flags = RTF_UP | RTF_HOST;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(host);
	memcpy(&rt.rt_dst, &addr, sizeof(rt.rt_dst));

	err = ioctl(sk, SIOCDELRT, &rt);
	if (err < 0)
		connman_error("Del vpn route failed (%s)",
			      strerror(errno));

	close(sk);

	return err;
}

static int set_vpn_route(struct connman_element *element, const char *gateway)
{
	struct ifreq ifr;
	struct rtentry rt;
	struct sockaddr_in addr;
	int sk, err;

	DBG("set_rout1: element %p", element);

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

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = element->index;

	memset(&rt, 0, sizeof(rt));
	rt.rt_flags = RTF_UP | RTF_GATEWAY;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	memcpy(&rt.rt_dst, &addr, sizeof(rt.rt_dst));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(gateway);
	memcpy(&rt.rt_gateway, &addr, sizeof(rt.rt_gateway));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	memcpy(&rt.rt_genmask, &addr, sizeof(rt.rt_genmask));

	err = ioctl(sk, SIOCADDRT, &rt);
	if (err < 0)
		connman_error("Setting VPN route failed (%s)",
			       strerror(errno));

	close(sk);

	return err;
}

static int del_route(struct connman_element *element, const char *gateway)
{
	struct ifreq ifr;
	struct rtentry rt;
	struct sockaddr_in addr;
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

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	memcpy(&rt.rt_dst, &addr, sizeof(rt.rt_dst));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(gateway);
	memcpy(&rt.rt_gateway, &addr, sizeof(rt.rt_gateway));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	memcpy(&rt.rt_genmask, &addr, sizeof(rt.rt_genmask));

	err = ioctl(sk, SIOCDELRT, &rt);
	if (err < 0)
		connman_error("Removing default route failed (%s)",
							strerror(errno));

	close(sk);

	return err;
}

static int del_route_all(struct gateway_data *data)
{
	int err = 0;

	if (data->vpn) {
		del_vpn_host(data->gateway);

		err = del_route(data->element, data->vpn_ip);
	} else
		err = del_route(data->element, data->gateway);

	return err;
}

static void find_element(struct connman_element *element, gpointer user_data)
{
	struct gateway_data *data = user_data;

	DBG("element %p name %s", element, element->name);

	if (data->element != NULL)
		return;

	if (element->index != data->index)
		return;

	data->element = element;
}

static struct gateway_data *add_gateway(int index, const char *gateway)
{
	struct gateway_data *data;
	struct connman_service *service;

	data = g_try_new0(struct gateway_data, 1);
	if (data == NULL)
		return NULL;

	data->index = index;
	data->gateway = g_strdup(gateway);
	data->active = FALSE;
	data->element = NULL;
	data->vpn_ip = NULL;
	data->vpn = FALSE;

	__connman_element_foreach(NULL, CONNMAN_ELEMENT_TYPE_CONNECTION,
							find_element, data);

	service = __connman_element_get_service(data->element);
	data->order = __connman_service_get_order(service);

	gateway_list = g_slist_append(gateway_list, data);

	return data;
}

static void connection_newgateway(int index, const char *gateway)
{
	struct gateway_data *data;

	DBG("index %d gateway %s", index, gateway);

	data = find_gateway(index, gateway);
	if (data == NULL)
		return;

	data->active = TRUE;
}

static void set_default_gateway(struct gateway_data *data)
{
	struct connman_element *element = data->element;
	struct connman_service *service = NULL;
	short int ifflags;

	DBG("gateway %s", data->gateway);

	if (data->vpn == TRUE) {

		set_vpn_route(element, data->vpn_ip);
		/* vpn gateway going away no changes in services */
		return;
	}

	ifflags = connman_inet_ifflags(element->index);
	if (ifflags < 0) {
		connman_error("Fail to get network interface flags");
		return;
	}

	if (ifflags & IFF_POINTOPOINT) {
		if (connman_inet_set_gateway_interface(element->index) < 0)
			return;
		goto done;
	}

	if (connman_inet_set_gateway_address(element->index, data->gateway) < 0)
		return;

done:
	service = __connman_element_get_service(element);
	__connman_service_indicate_default(service);
}

static struct gateway_data *find_default_gateway(void)
{
	struct gateway_data *found = NULL;
	unsigned int order = 0;
	GSList *list;

	for (list = gateway_list; list; list = list->next) {
		struct gateway_data *data = list->data;

		if (found == NULL || data->order > order) {
			found = data;
			order = data->order;
		}
	}

	return found;
}

static void remove_gateway(struct gateway_data *data)
{
	DBG("gateway %s", data->gateway);

	gateway_list = g_slist_remove(gateway_list, data);

	if (data->active == TRUE)
		del_route_all(data);

	g_free(data->gateway);
	g_free(data->vpn_ip);
	g_free(data);
}

static void connection_delgateway(int index, const char *gateway)
{
	struct gateway_data *data;

	DBG("index %d gateway %s", index, gateway);

	data = find_gateway(index, gateway);
	if (data != NULL)
		data->active = FALSE;

	data = find_default_gateway();
	if (data != NULL)
		set_default_gateway(data);
}

static struct connman_rtnl connection_rtnl = {
	.name		= "connection",
	.newgateway	= connection_newgateway,
	.delgateway	= connection_delgateway,
};

static struct gateway_data *find_active_gateway(void)
{
	GSList *list;

	DBG("");

	for (list = gateway_list; list; list = list->next) {
		struct gateway_data *data = list->data;
		if (data->active == TRUE)
			return data;
	}

	return NULL;
}

static int connection_probe(struct connman_element *element)
{
	struct connman_service *service = NULL;
	const char *gateway = NULL;
	const char *vpn_ip = NULL;
	struct gateway_data *active_gateway = NULL;
	struct gateway_data *new_gateway = NULL;

	DBG("element %p name %s", element, element->name);

	if (element->parent == NULL)
		return -ENODEV;

	if (element->parent->type != CONNMAN_ELEMENT_TYPE_IPV4)
		return -ENODEV;

	connman_element_get_value(element,
				CONNMAN_PROPERTY_ID_IPV4_GATEWAY, &gateway);

	connman_element_get_value(element,
				  CONNMAN_PROPERTY_ID_IPV4_ADDRESS, &vpn_ip);

	DBG("gateway %s", gateway);

	service = __connman_element_get_service(element);
	__connman_service_indicate_state(service,
					CONNMAN_SERVICE_STATE_READY);

	connman_element_set_enabled(element, TRUE);

	if (gateway == NULL)
		return 0;

	active_gateway = find_active_gateway();
	new_gateway = add_gateway(element->index, gateway);

	if (service == NULL) {
		new_gateway->vpn = TRUE;
		new_gateway->vpn_ip = g_strdup(vpn_ip);
		/* make sure vpn gateway are at higher priority */
		new_gateway->order = 10;
	} else
		new_gateway->vpn = FALSE;

	if (active_gateway == NULL) {
		set_default_gateway(new_gateway);
		return 0;
	}

	if (new_gateway->vpn == TRUE) {
		add_vpn_host(active_gateway->element,
			     active_gateway->gateway,
			     new_gateway->gateway);

	}

	if (new_gateway->order >= active_gateway->order) {
		del_route_all(active_gateway);
		return 0;
	}

	return 0;
}

static void connection_remove(struct connman_element *element)
{
	struct connman_service *service;
	const char *gateway = NULL;
	struct gateway_data *data = NULL;
	gboolean set_default = FALSE;

	DBG("element %p name %s", element, element->name);

	service = __connman_element_get_service(element);
	__connman_service_indicate_state(service,
					CONNMAN_SERVICE_STATE_DISCONNECT);

	connman_element_set_enabled(element, FALSE);

	connman_element_get_value(element,
				CONNMAN_PROPERTY_ID_IPV4_GATEWAY, &gateway);

	DBG("gateway %s", gateway);

	if (gateway == NULL)
		return;

	data = find_gateway(element->index, gateway);
	if (data == NULL)
		return;

	set_default = data->vpn;

	if (data->vpn == TRUE)
		del_vpn_host(data->gateway);

	remove_gateway(data);

	/* with vpn this will be called after the network was deleted,
	 * we need to call set_default here because we will not recieve any
	 * gateway delete notification.
	 */
	if (set_default) {
		data = find_default_gateway();
		if (data != NULL)
			set_default_gateway(data);
	}
}

static struct connman_driver connection_driver = {
	.name		= "connection",
	.type		= CONNMAN_ELEMENT_TYPE_CONNECTION,
	.priority	= CONNMAN_DRIVER_PRIORITY_LOW,
	.probe		= connection_probe,
	.remove		= connection_remove,
};

int __connman_connection_init(void)
{
	DBG("");

	if (connman_rtnl_register(&connection_rtnl) < 0)
		connman_error("Failed to setup RTNL gateway driver");

	return connman_driver_register(&connection_driver);
}

void __connman_connection_cleanup(void)
{
	GSList *list;

	DBG("");

	connman_driver_unregister(&connection_driver);

	connman_rtnl_unregister(&connection_rtnl);

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

static void update_order(void)
{
	GSList *list = NULL;

	for (list = gateway_list; list; list = list->next) {
		struct gateway_data *data = list->data;
		struct connman_service *service;

		/* vpn gataway is not attached to a service. */
		if (data->vpn)
			continue;

		service = __connman_element_get_service(data->element);
		data->order = __connman_service_get_order(service);
	}
}

gboolean __connman_connection_update_gateway(void)
{
	struct gateway_data *active_gateway, *default_gateway;
	gboolean updated = FALSE;

	update_order();

	active_gateway = find_active_gateway();
	default_gateway = find_default_gateway();

	if (active_gateway && active_gateway != default_gateway) {
		del_route_all(active_gateway);
		updated = TRUE;
	}

	return updated;
}
