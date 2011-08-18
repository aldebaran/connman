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

#include <errno.h>
#include <string.h>
#include <net/if.h>

#include <gdbus.h>

#include "connman.h"

struct gateway_config {
	gboolean active;
	char *gateway;

	/* VPN extra data */
	gboolean vpn;
	char *vpn_ip;
	int vpn_phy_index;
	char *vpn_phy_ip;
};

struct gateway_data {
	int index;
	struct connman_service *service;
	unsigned int order;
	struct gateway_config *ipv4_gateway;
	struct gateway_config *ipv6_gateway;
};

static GHashTable *gateway_hash = NULL;

static struct gateway_config *find_gateway(int index, const char *gateway)
{
	GHashTableIter iter;
	gpointer value, key;

	if (gateway == NULL)
		return NULL;

	g_hash_table_iter_init(&iter, gateway_hash);

	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		struct gateway_data *data = value;

		if (data->ipv4_gateway != NULL && data->index == index &&
				g_str_equal(data->ipv4_gateway->gateway,
					gateway) == TRUE)
			return data->ipv4_gateway;

		if (data->ipv6_gateway != NULL && data->index == index &&
				g_str_equal(data->ipv6_gateway->gateway,
					gateway) == TRUE)
			return data->ipv6_gateway;
	}

	return NULL;
}

static int del_routes(struct gateway_data *data,
			enum connman_ipconfig_type type)
{
	int status4 = 0, status6 = 0;
	int do_ipv4 = FALSE, do_ipv6 = FALSE;

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		do_ipv4 = TRUE;
	else if (type == CONNMAN_IPCONFIG_TYPE_IPV6)
		do_ipv6 = TRUE;
	else
		do_ipv4 = do_ipv6 = TRUE;

	if (do_ipv4 == TRUE && data->ipv4_gateway != NULL) {
		if (data->ipv4_gateway->vpn == TRUE) {
			if (data->ipv4_gateway->vpn_phy_index >= 0)
				connman_inet_del_host_route(
					data->ipv4_gateway->vpn_phy_index,
					data->ipv4_gateway->gateway);

			status4 = connman_inet_clear_gateway_address(
						data->index,
						data->ipv4_gateway->vpn_ip);

		} else if (g_strcmp0(data->ipv4_gateway->gateway,
							"0.0.0.0") == 0) {
			status4 = connman_inet_clear_gateway_interface(
								data->index);
		} else {
			connman_inet_del_host_route(data->index,
						data->ipv4_gateway->gateway);
			status4 = connman_inet_clear_gateway_address(
						data->index,
						data->ipv4_gateway->gateway);
		}
	}

	if (do_ipv6 == TRUE && data->ipv6_gateway != NULL) {
		if (data->ipv6_gateway->vpn == TRUE) {
			if (data->ipv6_gateway->vpn_phy_index >= 0)
				connman_inet_del_host_route(
					data->ipv6_gateway->vpn_phy_index,
					data->ipv6_gateway->gateway);

			status6 = connman_inet_clear_ipv6_gateway_address(
						data->index,
						data->ipv6_gateway->vpn_ip);

		} else if (g_strcmp0(data->ipv6_gateway->gateway, "::") == 0) {
			status6 = connman_inet_clear_ipv6_gateway_interface(
								data->index);
		} else {
			connman_inet_del_ipv6_host_route(data->index,
						data->ipv6_gateway->gateway);
			status6 = connman_inet_clear_ipv6_gateway_address(
						data->index,
						data->ipv6_gateway->gateway);
		}
	}

	return (status4 < 0 ? status4 : status6);
}

static int disable_gateway(struct gateway_data *data,
			enum connman_ipconfig_type type)
{
	gboolean active = FALSE;

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4) {
		if (data->ipv4_gateway != NULL)
			active = data->ipv4_gateway->active;
	} else if (type == CONNMAN_IPCONFIG_TYPE_IPV6) {
		if (data->ipv6_gateway != NULL)
			active = data->ipv6_gateway->active;
	} else
		active = TRUE;

	DBG("type %d active %d", type, active);

	if (active == TRUE)
		return del_routes(data, type);

	return 0;
}

static struct gateway_data *add_gateway(struct connman_service *service,
					int index, const char *gateway,
					enum connman_ipconfig_type type)
{
	struct gateway_data *data, *old;
	struct gateway_config *config;

	if (gateway == NULL || strlen(gateway) == 0)
		return NULL;

	data = g_try_new0(struct gateway_data, 1);
	if (data == NULL)
		return NULL;

	data->index = index;

	config = g_try_new0(struct gateway_config, 1);
	if (config == NULL) {
		g_free(data);
		return NULL;
	}

	config->gateway = g_strdup(gateway);
	config->vpn_ip = NULL;
	config->vpn_phy_ip = NULL;
	config->vpn = FALSE;
	config->vpn_phy_index = -1;
	config->active = FALSE;

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		data->ipv4_gateway = config;
	else if (type == CONNMAN_IPCONFIG_TYPE_IPV6)
		data->ipv6_gateway = config;
	else {
		g_free(config->gateway);
		g_free(config);
		g_free(data);
		return NULL;
	}

	data->service = service;

	data->order = __connman_service_get_order(service);

	/*
	 * If the service is already in the hash, then we
	 * must not replace it blindly but disable the gateway
	 * of the type we are replacing and take the other type
	 * from old gateway settings.
	 */
	old = g_hash_table_lookup(gateway_hash, service);
	if (old != NULL) {
		DBG("Replacing gw %p ipv4 %p ipv6 %p", old,
			old->ipv4_gateway, old->ipv6_gateway);
		disable_gateway(old, type);
		if (type == CONNMAN_IPCONFIG_TYPE_IPV4) {
			data->ipv6_gateway = old->ipv6_gateway;
			old->ipv6_gateway = NULL;
		} else if (type == CONNMAN_IPCONFIG_TYPE_IPV6) {
			data->ipv4_gateway = old->ipv4_gateway;
			old->ipv4_gateway = NULL;
		}
	}

	g_hash_table_replace(gateway_hash, service, data);

	return data;
}

static void connection_newgateway(int index, const char *gateway)
{
	struct gateway_config *config;

	DBG("index %d gateway %s", index, gateway);

	config = find_gateway(index, gateway);
	if (config == NULL)
		return;

	config->active = TRUE;
}

static void set_default_gateway(struct gateway_data *data,
				enum connman_ipconfig_type type)
{
	int index;
	int status4 = 0, status6 = 0;
	int do_ipv4 = FALSE, do_ipv6 = FALSE;

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		do_ipv4 = TRUE;
	else if (type == CONNMAN_IPCONFIG_TYPE_IPV6)
		do_ipv6 = TRUE;
	else
		do_ipv4 = do_ipv6 = TRUE;

	DBG("type %d gateway ipv4 %p ipv6 %p", type, data->ipv4_gateway,
						data->ipv6_gateway);

	if (do_ipv4 == TRUE && data->ipv4_gateway != NULL &&
					data->ipv4_gateway->vpn == TRUE) {
		connman_inet_set_gateway_address(data->index,
						data->ipv4_gateway->vpn_ip);
		connman_inet_add_host_route(data->ipv4_gateway->vpn_phy_index,
					data->ipv4_gateway->vpn_ip,
					data->ipv4_gateway->vpn_phy_ip);
		data->ipv4_gateway->active = TRUE;

		__connman_service_indicate_default(data->service);

		return;
	}

	if (do_ipv6 == TRUE && data->ipv6_gateway != NULL &&
					data->ipv6_gateway->vpn == TRUE) {
		connman_inet_set_ipv6_gateway_address(data->index,
						data->ipv6_gateway->vpn_ip);
		connman_inet_add_host_route(data->ipv6_gateway->vpn_phy_index,
					data->ipv6_gateway->vpn_ip,
					data->ipv6_gateway->vpn_phy_ip);
		data->ipv6_gateway->active = TRUE;

		__connman_service_indicate_default(data->service);

		return;
	}

	index = __connman_service_get_index(data->service);

	if (do_ipv4 == TRUE && data->ipv4_gateway != NULL &&
			g_strcmp0(data->ipv4_gateway->gateway,
							"0.0.0.0") == 0) {
		if (connman_inet_set_gateway_interface(index) < 0)
			return;
		goto done;
	}

	if (do_ipv6 == TRUE && data->ipv6_gateway != NULL &&
			g_strcmp0(data->ipv6_gateway->gateway,
							"::") == 0) {
		if (connman_inet_set_ipv6_gateway_interface(index) < 0)
			return;
		goto done;
	}

	if (do_ipv6 == TRUE && data->ipv6_gateway != NULL)
		status6 = connman_inet_set_ipv6_gateway_address(index,
						data->ipv6_gateway->gateway);

	if (do_ipv4 == TRUE && data->ipv4_gateway != NULL)
		status4 = connman_inet_set_gateway_address(index,
						data->ipv4_gateway->gateway);

	if (status4 < 0 || status6 < 0)
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

static void remove_gateway(gpointer user_data)
{
	struct gateway_data *data = user_data;

	DBG("gateway ipv4 %p ipv6 %p", data->ipv4_gateway, data->ipv6_gateway);

	if (data->ipv4_gateway != NULL) {
		g_free(data->ipv4_gateway->gateway);
		g_free(data->ipv4_gateway->vpn_ip);
		g_free(data->ipv4_gateway->vpn_phy_ip);
		g_free(data->ipv4_gateway);
	}

	if (data->ipv6_gateway != NULL) {
		g_free(data->ipv6_gateway->gateway);
		g_free(data->ipv6_gateway->vpn_ip);
		g_free(data->ipv6_gateway->vpn_phy_ip);
		g_free(data->ipv6_gateway);
	}

	g_free(data);
}

static void connection_delgateway(int index, const char *gateway)
{
	struct gateway_config *config;
	struct gateway_data *data;

	DBG("index %d gateway %s", index, gateway);

	config = find_gateway(index, gateway);
	if (config != NULL)
		config->active = FALSE;

	data = find_default_gateway();
	if (data != NULL)
		set_default_gateway(data, CONNMAN_IPCONFIG_TYPE_ALL);
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

		if (data->ipv4_gateway != NULL &&
				data->ipv4_gateway->active == TRUE)
			return data;

		if (data->ipv6_gateway != NULL &&
				data->ipv6_gateway->active == TRUE)
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

void __connman_connection_gateway_activate(struct connman_service *service,
					enum connman_ipconfig_type type)
{
	struct gateway_data *data = NULL;

	data = g_hash_table_lookup(gateway_hash, service);
	if (data == NULL)
		return;

	DBG("gateway %p/%p type %d", data->ipv4_gateway,
					data->ipv6_gateway, type);

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		data->ipv4_gateway->active = TRUE;
	else if (type == CONNMAN_IPCONFIG_TYPE_IPV6)
		data->ipv6_gateway->active = TRUE;
}

int __connman_connection_gateway_add(struct connman_service *service,
					const char *gateway,
					enum connman_ipconfig_type type,
					const char *peer)
{
	struct gateway_data *active_gateway = NULL;
	struct gateway_data *new_gateway = NULL;
	int index;

	index = __connman_service_get_index(service);

	DBG("service %p index %d gateway %s vpn ip %s type %d",
		service, index, gateway, peer, type);

	/*
	 * If gateway is NULL, it's a point to point link and the default
	 * gateway for ipv4 is 0.0.0.0 and for ipv6 is ::, meaning the
	 * interface
	 */
	if (gateway == NULL && type == CONNMAN_IPCONFIG_TYPE_IPV4)
		gateway = "0.0.0.0";

	if (gateway == NULL && type == CONNMAN_IPCONFIG_TYPE_IPV6)
		gateway = "::";

	active_gateway = find_active_gateway();
	new_gateway = add_gateway(service, index, gateway, type);
	if (new_gateway == NULL)
		return -EINVAL;

	if (type == CONNMAN_IPCONFIG_TYPE_IPV6 &&
			new_gateway->ipv6_gateway != NULL &&
			g_strcmp0(new_gateway->ipv6_gateway->gateway,
								"::") != 0)
		connman_inet_add_ipv6_host_route(index,
					new_gateway->ipv6_gateway->gateway,
					NULL);

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4 &&
			new_gateway->ipv4_gateway != NULL &&
			g_strcmp0(new_gateway->ipv4_gateway->gateway,
							"0.0.0.0") != 0)
		connman_inet_add_host_route(index,
					new_gateway->ipv4_gateway->gateway,
					NULL);

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4 &&
				new_gateway->ipv4_gateway != NULL) {
		__connman_service_nameserver_add_routes(service,
					new_gateway->ipv4_gateway->gateway);
		__connman_service_ipconfig_indicate_state(service,
						CONNMAN_SERVICE_STATE_READY,
						CONNMAN_IPCONFIG_TYPE_IPV4);
	}

	if (type == CONNMAN_IPCONFIG_TYPE_IPV6 &&
				new_gateway->ipv6_gateway != NULL) {
		__connman_service_nameserver_add_routes(service,
					new_gateway->ipv6_gateway->gateway);
		__connman_service_ipconfig_indicate_state(service,
						CONNMAN_SERVICE_STATE_READY,
						CONNMAN_IPCONFIG_TYPE_IPV6);
	}

	if (connman_service_get_type(service) == CONNMAN_SERVICE_TYPE_VPN) {
		if (type == CONNMAN_IPCONFIG_TYPE_IPV4 &&
					new_gateway->ipv4_gateway != NULL) {
			new_gateway->ipv4_gateway->vpn = TRUE;
			if (peer != NULL)
				new_gateway->ipv4_gateway->vpn_ip =
							g_strdup(peer);
			else if (gateway != NULL)
				new_gateway->ipv4_gateway->vpn_ip =
							g_strdup(gateway);
			if (active_gateway) {
				const char *new_ipv4_gateway;

				new_ipv4_gateway =
					active_gateway->ipv4_gateway->gateway;
				if (new_ipv4_gateway != NULL &&
					 g_strcmp0(new_ipv4_gateway,
							"0.0.0.0") != 0)
					new_gateway->ipv4_gateway->vpn_phy_ip =
						g_strdup(new_ipv4_gateway);

				new_gateway->ipv4_gateway->vpn_phy_index =
							active_gateway->index;
			}

		} else if (type == CONNMAN_IPCONFIG_TYPE_IPV6 &&
					new_gateway->ipv6_gateway != NULL) {
			new_gateway->ipv6_gateway->vpn = TRUE;
			if (peer != NULL)
				new_gateway->ipv6_gateway->vpn_ip =
							g_strdup(peer);
			else if (gateway != NULL)
				new_gateway->ipv6_gateway->vpn_ip =
							g_strdup(gateway);
			if (active_gateway) {
				const char *new_ipv6_gateway;

				new_ipv6_gateway =
					active_gateway->ipv6_gateway->gateway;
				if (new_ipv6_gateway != NULL &&
					g_strcmp0(new_ipv6_gateway, "::") != 0)
					new_gateway->ipv6_gateway->vpn_phy_ip =
						g_strdup(new_ipv6_gateway);

				new_gateway->ipv6_gateway->vpn_phy_index =
							active_gateway->index;
			}
		}
	} else {
		if (type == CONNMAN_IPCONFIG_TYPE_IPV4 &&
					new_gateway->ipv4_gateway != NULL)
			new_gateway->ipv4_gateway->vpn = FALSE;

		if (type == CONNMAN_IPCONFIG_TYPE_IPV6 &&
					new_gateway->ipv6_gateway != NULL)
			new_gateway->ipv6_gateway->vpn = FALSE;
	}

	if (active_gateway == NULL) {
		set_default_gateway(new_gateway, type);
		return 0;
	}

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4 &&
				new_gateway->ipv4_gateway != NULL &&
				new_gateway->ipv4_gateway->vpn == TRUE) {
		connman_inet_add_host_route(active_gateway->index,
					new_gateway->ipv4_gateway->gateway,
					active_gateway->ipv4_gateway->gateway);
		connman_inet_clear_gateway_address(active_gateway->index,
					active_gateway->ipv4_gateway->gateway);
	}

	if (type == CONNMAN_IPCONFIG_TYPE_IPV6 &&
				new_gateway->ipv6_gateway != NULL &&
				new_gateway->ipv6_gateway->vpn == TRUE) {
		connman_inet_add_ipv6_host_route(active_gateway->index,
					new_gateway->ipv6_gateway->gateway,
					active_gateway->ipv6_gateway->gateway);
		connman_inet_clear_ipv6_gateway_address(active_gateway->index,
					active_gateway->ipv6_gateway->gateway);
	}

	return 0;
}

void __connman_connection_gateway_remove(struct connman_service *service,
					enum connman_ipconfig_type type)
{
	struct gateway_data *data = NULL;
	gboolean set_default4 = FALSE, set_default6 = FALSE;
	int do_ipv4 = FALSE, do_ipv6 = FALSE;
	int err;

	DBG("service %p type %d", service, type);

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		do_ipv4 = TRUE;
	else if (type == CONNMAN_IPCONFIG_TYPE_IPV6)
		do_ipv6 = TRUE;
	else
		do_ipv4 = do_ipv6 = TRUE;

	__connman_service_nameserver_del_routes(service);

	data = g_hash_table_lookup(gateway_hash, service);
	if (data == NULL)
		return;

	if (do_ipv4 == TRUE && data->ipv4_gateway != NULL)
		set_default4 = data->ipv4_gateway->vpn;

	if (do_ipv6 == TRUE && data->ipv6_gateway != NULL)
		set_default6 = data->ipv6_gateway->vpn;

	DBG("ipv4 gateway %s ipv6 gateway %s vpn %d/%d",
		data->ipv4_gateway ? data->ipv4_gateway->gateway : "<null>",
		data->ipv6_gateway ? data->ipv6_gateway->gateway : "<null>",
		set_default4, set_default6);

	if (do_ipv4 == TRUE && data->ipv4_gateway != NULL &&
			data->ipv4_gateway->vpn == TRUE && data->index >= 0)
		connman_inet_del_host_route(data->index,
						data->ipv4_gateway->gateway);

	if (do_ipv6 == TRUE && data->ipv6_gateway != NULL &&
			data->ipv6_gateway->vpn == TRUE && data->index >= 0)
		connman_inet_del_ipv6_host_route(data->index,
						data->ipv6_gateway->gateway);

	__connman_service_nameserver_del_routes(service);

	err = disable_gateway(data, type);

	/*
	 * We remove the service from the hash only if all the gateway
	 * settings are to be removed.
	 */
	if (do_ipv4 == do_ipv6 ||
		(data->ipv4_gateway != NULL && data->ipv6_gateway == NULL
			&& do_ipv4 == TRUE) ||
		(data->ipv6_gateway != NULL && data->ipv4_gateway == NULL
			&& do_ipv6 == TRUE)
		)
		g_hash_table_remove(gateway_hash, service);
	else
		DBG("Not yet removing gw ipv4 %p/%d ipv6 %p/%d",
			data->ipv4_gateway, do_ipv4,
			data->ipv6_gateway, do_ipv6);

	/* with vpn this will be called after the network was deleted,
	 * we need to call set_default here because we will not recieve any
	 * gateway delete notification.
	 * We hit the same issue if remove_gateway() fails.
	 */
	if (set_default4 || set_default6 || err < 0) {
		data = find_default_gateway();
		if (data != NULL)
			set_default_gateway(data, type);
	}
}

gboolean __connman_connection_update_gateway(void)
{
	struct gateway_data *active_gateway, *default_gateway;
	gboolean updated = FALSE;

	if (gateway_hash == NULL)
		return updated;

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

		disable_gateway(data, CONNMAN_IPCONFIG_TYPE_ALL);
	}

	g_hash_table_destroy(gateway_hash);
	gateway_hash = NULL;
}
