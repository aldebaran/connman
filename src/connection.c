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
	int vpn_phy_index;
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

static int del_routes(struct gateway_data *data)
{
	if (data->vpn) {
		if (data->vpn_phy_index >= 0)
			connman_inet_del_host_route(data->vpn_phy_index,
							data->gateway);
		return connman_inet_clear_gateway_address(data->index,
							data->vpn_ip);
	} else if (g_strcmp0(data->gateway, "0.0.0.0") == 0) {
		return connman_inet_clear_gateway_interface(data->index);
	} else {
		connman_inet_del_host_route(data->index, data->gateway);
		return connman_inet_clear_gateway_address(data->index,
							data->gateway);
	}
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
	data->vpn_phy_index = -1;

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

	DBG("gateway %s", data->gateway);

	if (data->vpn == TRUE) {
		connman_inet_set_gateway_address(data->index, data->vpn_ip);
		data->active = TRUE;
		/* vpn gateway going away no changes in services */
		return;
	}

	if (g_strcmp0(data->gateway, "0.0.0.0") == 0) {
		if (connman_inet_set_gateway_interface(element->index) < 0)
			return;
		goto done;
	}

	connman_inet_add_host_route(element->index, data->gateway, NULL);

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

static int remove_gateway(struct gateway_data *data)
{
	int err;

	DBG("gateway %s", data->gateway);

	gateway_list = g_slist_remove(gateway_list, data);

	if (data->active == TRUE)
		err = del_routes(data);
	else
		err = 0;

	g_free(data->gateway);
	g_free(data->vpn_ip);
	g_free(data);

	return err;
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

	/* FIXME: Remove temporarily for the static gateway support */
	/* if (element->parent->type != CONNMAN_ELEMENT_TYPE_IPV4)
		return -ENODEV; */

	connman_element_get_value(element,
				CONNMAN_PROPERTY_ID_IPV4_GATEWAY, &gateway);

	connman_element_get_value(element,
				  CONNMAN_PROPERTY_ID_IPV4_ADDRESS, &vpn_ip);

	DBG("gateway %s", gateway);

	/*
	 * If gateway is NULL, it's a point to point link and the default
	 * gateway is 0.0.0.0, meaning the interface.
	 */
	if (gateway == NULL) {
		gateway = "0.0.0.0";
		element->ipv4.gateway = g_strdup(gateway);
	}

	service = __connman_element_get_service(element);
	__connman_service_indicate_state(service,
					CONNMAN_SERVICE_STATE_READY);

	connman_element_set_enabled(element, TRUE);

	active_gateway = find_active_gateway();
	new_gateway = add_gateway(element->index, gateway);

	if (service == NULL) {
		new_gateway->vpn = TRUE;
		new_gateway->vpn_ip = g_strdup(vpn_ip);
		/* make sure vpn gateway are at higher priority */
		new_gateway->order = 10;
		if (active_gateway)
			new_gateway->vpn_phy_index = active_gateway->index;
	} else
		new_gateway->vpn = FALSE;

	if (active_gateway == NULL) {
		set_default_gateway(new_gateway);
		return 0;
	}

	if (new_gateway->vpn == TRUE) {
		connman_inet_add_host_route(active_gateway->index,
						new_gateway->gateway,
						active_gateway->gateway);
	}

	if (new_gateway->order >= active_gateway->order) {
		del_routes(active_gateway);
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
	int err;

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

	if (data->vpn == TRUE && data->vpn_phy_index >= 0)
		connman_inet_del_host_route(data->vpn_phy_index, data->gateway);

	err = remove_gateway(data);

	/* with vpn this will be called after the network was deleted,
	 * we need to call set_default here because we will not recieve any
	 * gateway delete notification.
	 * We hit the same issue if remove_gateway() fails.
	 */
	if (set_default || err < 0) {
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
		del_routes(active_gateway);
		updated = TRUE;
	}

	return updated;
}
