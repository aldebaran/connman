/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2010  Intel Corporation. All rights reserved.
 *  Copyright (C) 2011  BMW Car IT GmbH. All rights reserved.
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

#include <string.h>
#include <net/if.h>

#include <gdbus.h>

#include "connman.h"

struct gateway_data {
	int index;
	struct connman_service *service;
	char *ipv4_gateway;
	char *ipv6_gateway;
	unsigned int order;
	gboolean active;
	/* VPN extra data */
	gboolean vpn;
	char *vpn_ip;
	int vpn_phy_index;
};

static GHashTable *gateway_hash = NULL;

static struct gateway_data *find_gateway(int index, const char *gateway)
{
	GHashTableIter iter;
	gpointer value, key;

	if (gateway == NULL)
		return NULL;

	g_hash_table_iter_init(&iter, gateway_hash);

	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		struct gateway_data *data = value;

		if (data->ipv4_gateway == NULL)
			continue;

		if (data->index == index &&
				g_str_equal(data->ipv4_gateway, gateway)
								== TRUE)
			return data;
	}

	return NULL;
}

static int del_routes(struct gateway_data *data)
{
	if (data->vpn) {
		if (data->vpn_phy_index >= 0)
			connman_inet_del_host_route(data->vpn_phy_index,
							data->ipv4_gateway);
		return connman_inet_clear_gateway_address(data->index,
							data->vpn_ip);
	} else if (g_strcmp0(data->ipv4_gateway, "0.0.0.0") == 0) {
		return connman_inet_clear_gateway_interface(data->index);
	} else {
		connman_inet_del_ipv6_host_route(data->index,
						data->ipv6_gateway);
		connman_inet_clear_ipv6_gateway_address(data->index,
							data->ipv6_gateway);
		connman_inet_del_host_route(data->index, data->ipv4_gateway);
		return connman_inet_clear_gateway_address(data->index,
							data->ipv4_gateway);
	}
}

static struct gateway_data *add_gateway(struct connman_service *service,
					int index, const char *ipv4_gateway,
					const char *ipv6_gateway)
{
	struct gateway_data *data;

	if (strlen(ipv4_gateway) == 0)
		return NULL;

	data = g_try_new0(struct gateway_data, 1);
	if (data == NULL)
		return NULL;

	data->index = index;
	data->ipv4_gateway = g_strdup(ipv4_gateway);
	data->ipv6_gateway = g_strdup(ipv6_gateway);
	data->active = FALSE;
	data->vpn_ip = NULL;
	data->vpn = FALSE;
	data->vpn_phy_index = -1;
	data->service = service;

	data->order = __connman_service_get_order(service);

	g_hash_table_replace(gateway_hash, service, data);

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
	int index;

	DBG("gateway %s", data->ipv4_gateway);

	if (data->vpn == TRUE) {
		connman_inet_set_gateway_address(data->index,
							data->vpn_ip);
		data->active = TRUE;

		__connman_service_indicate_default(data->service);

		return;
	}

	index = __connman_service_get_index(data->service);

	if (g_strcmp0(data->ipv4_gateway, "0.0.0.0") == 0) {
		if (connman_inet_set_gateway_interface(index) < 0)
			return;
		goto done;
	}

	connman_inet_set_ipv6_gateway_address(index, data->ipv6_gateway);
	if (connman_inet_set_gateway_address(index, data->ipv4_gateway) < 0)
		return;

done:
	__connman_service_indicate_default(data->service);
}

static struct gateway_data *find_default_gateway(void)
{
	struct gateway_data *found = NULL;
	unsigned int order = 0;
	GHashTableIter iter;
	gpointer value, key;

	g_hash_table_iter_init(&iter, gateway_hash);

	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		struct gateway_data *data = value;

		if (found == NULL || data->order > order) {
			found = data;
			order = data->order;
		}
	}

	return found;
}

static int disable_gateway(struct gateway_data *data)
{
	if (data->active == TRUE)
		return del_routes(data);

	return 0;
}

static void remove_gateway(gpointer user_data)
{
	struct gateway_data *data = user_data;

	DBG("gateway %s", data->ipv4_gateway);

	g_free(data->ipv4_gateway);
	g_free(data->ipv6_gateway);
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
	GHashTableIter iter;
	gpointer value, key;

	DBG("");

	g_hash_table_iter_init(&iter, gateway_hash);

	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		struct gateway_data *data = value;

		if (data->active == TRUE)
			return data;
	}

	return NULL;
}

static void update_order(void)
{
	GHashTableIter iter;
	gpointer value, key;

	DBG("");

	g_hash_table_iter_init(&iter, gateway_hash);

	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		struct gateway_data *data = value;

		data->order = __connman_service_get_order(data->service);
	}
}

int __connman_connection_gateway_add(struct connman_service *service,
					const char *ipv4_gateway,
					const char *ipv6_gateway,
					const char *peer)
{
	struct gateway_data *active_gateway = NULL;
	struct gateway_data *new_gateway = NULL;
	int index;

	index = __connman_service_get_index(service);

	DBG("service %p index %d ipv4 gateway %s ipv6 gateway %s vpn ip %s",
		service, index, ipv4_gateway, ipv6_gateway, peer);

	/*
	 * If gateway is NULL, it's a point to point link and the default
	 * gateway is 0.0.0.0, meaning the interface.
	 */
	if (ipv4_gateway == NULL)
		ipv4_gateway = "0.0.0.0";

	active_gateway = find_active_gateway();
	new_gateway = add_gateway(service, index, ipv4_gateway, ipv6_gateway);
	if (new_gateway == NULL)
		return 0;

	if (new_gateway->ipv6_gateway) {
		connman_inet_add_ipv6_host_route(index,
						new_gateway->ipv6_gateway,
						NULL);
	}

	if (g_strcmp0(new_gateway->ipv4_gateway, "0.0.0.0") != 0) {
		connman_inet_add_host_route(index,
						new_gateway->ipv4_gateway,
						NULL);
	}

	__connman_service_nameserver_add_routes(service,
						new_gateway->ipv4_gateway);

	__connman_service_indicate_state(service, CONNMAN_SERVICE_STATE_READY,
						CONNMAN_IPCONFIG_TYPE_IPV4);

	if (connman_service_get_type(service) == CONNMAN_SERVICE_TYPE_VPN) {
		new_gateway->vpn = TRUE;
		if (peer != NULL)
			new_gateway->vpn_ip = g_strdup(peer);
		else if (ipv4_gateway != NULL)
			new_gateway->vpn_ip = g_strdup(ipv4_gateway);
		else
			new_gateway->vpn_ip = g_strdup(ipv6_gateway);

		if (active_gateway)
			new_gateway->vpn_phy_index = active_gateway->index;
	} else {
		new_gateway->vpn = FALSE;
	}

	if (active_gateway == NULL) {
		set_default_gateway(new_gateway);
		return 0;
	}

	if (new_gateway->vpn == TRUE) {
		connman_inet_add_host_route(active_gateway->index,
						new_gateway->ipv4_gateway,
						active_gateway->ipv4_gateway);
		connman_inet_clear_gateway_address(active_gateway->index,
						active_gateway->ipv4_gateway);
	}

	return 0;
}

void __connman_connection_gateway_remove(struct connman_service *service)
{
	struct gateway_data *data = NULL;
	gboolean set_default = FALSE;
	int err;

	DBG("service %p", service);

	__connman_service_nameserver_del_routes(service);

	__connman_service_indicate_state(service,
					CONNMAN_SERVICE_STATE_DISCONNECT,
					CONNMAN_IPCONFIG_TYPE_IPV4);

	data = g_hash_table_lookup(gateway_hash, service);
	if (data == NULL)
		return;

	set_default = data->vpn;

	if (data->vpn == TRUE && data->index >= 0) {
		connman_inet_del_host_route(data->index,
						data->ipv4_gateway);
	}

	__connman_service_nameserver_del_routes(service);

	err = disable_gateway(data);
	g_hash_table_remove(gateway_hash, service);

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

gboolean __connman_connection_update_gateway(void)
{
	struct gateway_data *active_gateway, *default_gateway;
	gboolean updated = FALSE;

	update_order();

	active_gateway = find_active_gateway();
	default_gateway = find_default_gateway();

	if (active_gateway && active_gateway != default_gateway)
		updated = TRUE;

	return updated;
}

int __connman_connection_init(void)
{
	int err;

	DBG("");

	gateway_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal,
							NULL, remove_gateway);

	err = connman_rtnl_register(&connection_rtnl);
	if (err < 0)
		connman_error("Failed to setup RTNL gateway driver");

	return err;
}

void __connman_connection_cleanup(void)
{
	GHashTableIter iter;
	gpointer value, key;

	DBG("");

	connman_rtnl_unregister(&connection_rtnl);

	g_hash_table_iter_init(&iter, gateway_hash);

	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		struct gateway_data *data = value;

		disable_gateway(data);
	}

	g_hash_table_destroy(gateway_hash);
	gateway_hash = NULL;
}
