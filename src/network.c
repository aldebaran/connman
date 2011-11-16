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
#include <string.h>

#include "connman.h"

static GSList *network_list = NULL;
static GSList *driver_list = NULL;

struct connman_network {
	int refcount;
	enum connman_network_type type;
	connman_bool_t available;
	connman_bool_t connected;
	connman_bool_t roaming;
	connman_uint8_t strength;
	connman_uint16_t frequency;
	char *identifier;
	char *name;
	char *node;
	char *group;
	char *path;
	int index;

	struct connman_network_driver *driver;
	void *driver_data;

	connman_bool_t connecting;
	connman_bool_t associating;

	struct connman_device *device;

	struct {
		void *ssid;
		int ssid_len;
		char *mode;
		unsigned short channel;
		char *security;
		char *passphrase;
		char *agent_passphrase;
		char *eap;
		char *identity;
		char *agent_identity;
		char *ca_cert_path;
		char *client_cert_path;
		char *private_key_path;
		char *private_key_passphrase;
		char *phase2_auth;
		connman_bool_t wps;
		connman_bool_t use_wps;
		char *pin_wps;
	} wifi;

	struct {
		char *nsp_name;
		int nsp_name_len;
	} wimax;
};

static const char *type2string(enum connman_network_type type)
{
	switch (type) {
	case CONNMAN_NETWORK_TYPE_UNKNOWN:
	case CONNMAN_NETWORK_TYPE_VENDOR:
		break;
	case CONNMAN_NETWORK_TYPE_ETHERNET:
		return "ethernet";
	case CONNMAN_NETWORK_TYPE_WIFI:
		return "wifi";
	case CONNMAN_NETWORK_TYPE_WIMAX:
		return "wimax";
	case CONNMAN_NETWORK_TYPE_BLUETOOTH_PAN:
	case CONNMAN_NETWORK_TYPE_BLUETOOTH_DUN:
		return "bluetooth";
	case CONNMAN_NETWORK_TYPE_CELLULAR:
		return "cellular";
	}

	return NULL;
}

connman_bool_t __connman_network_has_driver(struct connman_network *network)
{
	if (network == NULL || network->driver == NULL)
		return FALSE;

	return TRUE;
}

static gboolean match_driver(struct connman_network *network,
					struct connman_network_driver *driver)
{
	if (network->type == driver->type ||
			driver->type == CONNMAN_NETWORK_TYPE_UNKNOWN)
		return TRUE;

	return FALSE;
}

static int network_probe(struct connman_network *network)
{
	GSList *list;
	struct connman_network_driver *driver = NULL;

	DBG("network %p name %s", network, network->name);

	if (network->driver != NULL)
		return -EALREADY;

	for (list = driver_list; list; list = list->next) {
		driver = list->data;

		if (match_driver(network, driver) == FALSE)
			continue;

		DBG("driver %p name %s", driver, driver->name);

		if (driver->probe(network) == 0)
			break;

		driver = NULL;
	}

	if (driver == NULL)
		return -ENODEV;

	if (network->group == NULL)
		return -EINVAL;

	switch (network->type) {
	case CONNMAN_NETWORK_TYPE_UNKNOWN:
	case CONNMAN_NETWORK_TYPE_VENDOR:
		return 0;
	case CONNMAN_NETWORK_TYPE_ETHERNET:
	case CONNMAN_NETWORK_TYPE_BLUETOOTH_PAN:
	case CONNMAN_NETWORK_TYPE_BLUETOOTH_DUN:
	case CONNMAN_NETWORK_TYPE_CELLULAR:
	case CONNMAN_NETWORK_TYPE_WIFI:
	case CONNMAN_NETWORK_TYPE_WIMAX:
		network->driver = driver;
		if (__connman_service_create_from_network(network) == NULL) {
			network->driver = NULL;
			return -EINVAL;
		}
	}

	return 0;
}

static void network_remove(struct connman_network *network)
{
	DBG("network %p name %s", network, network->name);

	if (network->driver == NULL)
		return;

	connman_network_set_connected(network, FALSE);

	switch (network->type) {
	case CONNMAN_NETWORK_TYPE_UNKNOWN:
	case CONNMAN_NETWORK_TYPE_VENDOR:
		break;
	case CONNMAN_NETWORK_TYPE_ETHERNET:
	case CONNMAN_NETWORK_TYPE_BLUETOOTH_PAN:
	case CONNMAN_NETWORK_TYPE_BLUETOOTH_DUN:
	case CONNMAN_NETWORK_TYPE_CELLULAR:
	case CONNMAN_NETWORK_TYPE_WIFI:
	case CONNMAN_NETWORK_TYPE_WIMAX:
		if (network->group != NULL) {
			__connman_service_remove_from_network(network);

			g_free(network->group);
			network->group = NULL;
		}
		break;
	}

	if (network->driver->remove)
		network->driver->remove(network);

	network->driver = NULL;
}

static void network_change(struct connman_network *network)
{
	DBG("network %p name %s", network, network->name);

	if (network->connected == FALSE)
		return;

	connman_device_set_disconnected(network->device, TRUE);

	if (network->driver && network->driver->disconnect) {
		network->driver->disconnect(network);
		return;
	}

	network->connected = FALSE;
}

static void probe_driver(struct connman_network_driver *driver)
{
	GSList *list;

	DBG("driver %p name %s", driver, driver->name);

	for (list = network_list; list != NULL; list = list->next) {
		struct connman_network *network = list->data;

		if (network->driver != NULL)
			continue;

		if (driver->type != network->type)
			continue;

		if (driver->probe(network) < 0)
			continue;

		network->driver = driver;
	}
}

static void remove_driver(struct connman_network_driver *driver)
{
	GSList *list;

	DBG("driver %p name %s", driver, driver->name);

	for (list = network_list; list != NULL; list = list->next) {
		struct connman_network *network = list->data;

		if (network->driver == driver)
			network_remove(network);
	}
}

static gint compare_priority(gconstpointer a, gconstpointer b)
{
	const struct connman_network_driver *driver1 = a;
	const struct connman_network_driver *driver2 = b;

	return driver2->priority - driver1->priority;
}

/**
 * connman_network_driver_register:
 * @driver: network driver definition
 *
 * Register a new network driver
 *
 * Returns: %0 on success
 */
int connman_network_driver_register(struct connman_network_driver *driver)
{
	GSList *list;

	DBG("driver %p name %s", driver, driver->name);

	for (list = driver_list; list; list = list->next) {
		struct connman_network_driver *tmp = list->data;

		if (tmp->type == driver->type)
			return -EALREADY;

	}

	driver_list = g_slist_insert_sorted(driver_list, driver,
							compare_priority);

	probe_driver(driver);

	return 0;
}

/**
 * connman_network_driver_unregister:
 * @driver: network driver definition
 *
 * Remove a previously registered network driver
 */
void connman_network_driver_unregister(struct connman_network_driver *driver)
{
	DBG("driver %p name %s", driver, driver->name);

	driver_list = g_slist_remove(driver_list, driver);

	remove_driver(driver);
}

static void network_destruct(struct connman_network *network)
{
	DBG("network %p name %s", network, network->name);

	g_free(network->wifi.ssid);
	g_free(network->wifi.mode);
	g_free(network->wifi.security);
	g_free(network->wifi.passphrase);
	g_free(network->wifi.agent_passphrase);
	g_free(network->wifi.eap);
	g_free(network->wifi.identity);
	g_free(network->wifi.agent_identity);
	g_free(network->wifi.ca_cert_path);
	g_free(network->wifi.client_cert_path);
	g_free(network->wifi.private_key_path);
	g_free(network->wifi.private_key_passphrase);
	g_free(network->wifi.phase2_auth);
	g_free(network->wifi.pin_wps);

	g_free(network->path);
	g_free(network->group);
	g_free(network->node);
	g_free(network->name);
	g_free(network->identifier);

	network->device = NULL;

	g_free(network);
}

/**
 * connman_network_create:
 * @identifier: network identifier (for example an unqiue name)
 *
 * Allocate a new network and assign the #identifier to it.
 *
 * Returns: a newly-allocated #connman_network structure
 */
struct connman_network *connman_network_create(const char *identifier,
						enum connman_network_type type)
{
	struct connman_network *network;
	char *ident;

	DBG("identifier %s type %d", identifier, type);

	network = g_try_new0(struct connman_network, 1);
	if (network == NULL)
		return NULL;

	DBG("network %p", network);

	network->refcount = 1;

	ident = g_strdup(identifier);

	if (ident == NULL) {
		g_free(network);
		return NULL;
	}

	network->type       = type;
	network->identifier = ident;

	network_list = g_slist_append(network_list, network);

	return network;
}

/**
 * connman_network_ref:
 * @network: network structure
 *
 * Increase reference counter of  network
 */
struct connman_network *connman_network_ref(struct connman_network *network)
{
	DBG("network %p name %s refcount %d", network, network->name,
		network->refcount + 1);

	__sync_fetch_and_add(&network->refcount, 1);

	return network;
}

/**
 * connman_network_unref:
 * @network: network structure
 *
 * Decrease reference counter of network
 */
void connman_network_unref(struct connman_network *network)
{
	DBG("network %p name %s refcount %d", network, network->name,
		network->refcount - 1);

	if (__sync_fetch_and_sub(&network->refcount, 1) != 1)
		return;

	network_list = g_slist_remove(network_list, network);

	network_destruct(network);
}

const char *__connman_network_get_type(struct connman_network *network)
{
	return type2string(network->type);
}

/**
 * connman_network_get_type:
 * @network: network structure
 *
 * Get type of network
 */
enum connman_network_type connman_network_get_type(struct connman_network *network)
{
	return network->type;
}

/**
 * connman_network_get_identifier:
 * @network: network structure
 *
 * Get identifier of network
 */
const char *connman_network_get_identifier(struct connman_network *network)
{
	return network->identifier;
}

/**
 * connman_network_set_index:
 * @network: network structure
 * @index: index number
 *
 * Set index number of network
 */
void connman_network_set_index(struct connman_network *network, int index)
{
	struct connman_service *service;
	struct connman_ipconfig *ipconfig;

	service = __connman_service_lookup_from_network(network);
	if (service == NULL)
		goto done;

	ipconfig = __connman_service_get_ip4config(service);

	DBG("index %d service %p ip4config %p", network->index,
		service, ipconfig);

	if (network->index < 0 && ipconfig == NULL) {

		ipconfig = __connman_service_get_ip4config(service);
		if (ipconfig == NULL)
			/*
			 * This is needed for plugins that havent set their
			 * ipconfig layer yet, due to not being able to get
			 * a network index prior to creating a service.
			 */
			__connman_service_create_ip4config(service, index);
		else
			__connman_ipconfig_set_index(ipconfig, index);

	} else {
		/* If index changed, the index of ipconfig must be reset. */
		if (ipconfig == NULL)
			goto done;

		__connman_ipconfig_set_index(ipconfig, index);
	}

done:
	network->index = index;
}

/**
 * connman_network_get_index:
 * @network: network structure
 *
 * Get index number of network
 */
int connman_network_get_index(struct connman_network *network)
{
	return network->index;
}

/**
 * connman_network_set_group:
 * @network: network structure
 * @group: group name
 *
 * Set group name for automatic clustering
 */
void connman_network_set_group(struct connman_network *network,
							const char *group)
{
	switch (network->type) {
	case CONNMAN_NETWORK_TYPE_UNKNOWN:
	case CONNMAN_NETWORK_TYPE_VENDOR:
		return;
	case CONNMAN_NETWORK_TYPE_ETHERNET:
	case CONNMAN_NETWORK_TYPE_BLUETOOTH_PAN:
	case CONNMAN_NETWORK_TYPE_BLUETOOTH_DUN:
	case CONNMAN_NETWORK_TYPE_CELLULAR:
	case CONNMAN_NETWORK_TYPE_WIFI:
	case CONNMAN_NETWORK_TYPE_WIMAX:
		break;
	}

	if (g_strcmp0(network->group, group) == 0) {
		if (group != NULL)
			__connman_service_update_from_network(network);
		return;
	}

	if (network->group != NULL) {
		__connman_service_remove_from_network(network);

		g_free(network->group);
	}

	network->group = g_strdup(group);

	if (network->group != NULL)
		network_probe(network);
}

/**
 * connman_network_get_group:
 * @network: network structure
 *
 * Get group name for automatic clustering
 */
const char *connman_network_get_group(struct connman_network *network)
{
	return network->group;
}

const char *__connman_network_get_ident(struct connman_network *network)
{
	if (network->device == NULL)
		return NULL;

	return connman_device_get_ident(network->device);
}

connman_bool_t __connman_network_get_weakness(struct connman_network *network)
{
	switch (network->type) {
	case CONNMAN_NETWORK_TYPE_UNKNOWN:
	case CONNMAN_NETWORK_TYPE_VENDOR:
	case CONNMAN_NETWORK_TYPE_ETHERNET:
	case CONNMAN_NETWORK_TYPE_BLUETOOTH_PAN:
	case CONNMAN_NETWORK_TYPE_BLUETOOTH_DUN:
	case CONNMAN_NETWORK_TYPE_CELLULAR:
	case CONNMAN_NETWORK_TYPE_WIMAX:
		break;
	case CONNMAN_NETWORK_TYPE_WIFI:
		if (g_strcmp0(network->wifi.mode, "adhoc") == 0)
			return TRUE;
		if (network->strength > 0 && network->strength < 20)
			return TRUE;
		break;
	}

	return FALSE;
}

connman_bool_t connman_network_get_connecting(struct connman_network *network)
{
	return network->connecting;
}

/**
 * connman_network_set_available:
 * @network: network structure
 * @available: availability state
 *
 * Change availability state of network (in range)
 */
int connman_network_set_available(struct connman_network *network,
						connman_bool_t available)
{
	DBG("network %p available %d", network, available);

	if (network->available == available)
		return -EALREADY;

	network->available = available;

	return 0;
}

/**
 * connman_network_get_available:
 * @network: network structure
 *
 * Get network available setting
 */
connman_bool_t connman_network_get_available(struct connman_network *network)
{
	return network->available;
}

/**
 * connman_network_set_associating:
 * @network: network structure
 * @associating: associating state
 *
 * Change associating state of network
 */
int connman_network_set_associating(struct connman_network *network,
						connman_bool_t associating)
{
	DBG("network %p associating %d", network, associating);

	if (network->associating == associating)
		return -EALREADY;

	network->associating = associating;

	if (associating == TRUE) {
		struct connman_service *service;

		service = __connman_service_lookup_from_network(network);
		__connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_ASSOCIATION,
					CONNMAN_IPCONFIG_TYPE_IPV4);
		__connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_ASSOCIATION,
					CONNMAN_IPCONFIG_TYPE_IPV6);
	}

	return 0;
}

static void set_associate_error(struct connman_network *network)
{
	struct connman_service *service;

	service = __connman_service_lookup_from_network(network);

	__connman_service_indicate_error(service,
					CONNMAN_SERVICE_ERROR_CONNECT_FAILED);
}

static void set_configure_error(struct connman_network *network)
{
	struct connman_service *service;

	service = __connman_service_lookup_from_network(network);

	__connman_service_indicate_error(service,
					CONNMAN_SERVICE_ERROR_CONNECT_FAILED);
}

static void set_invalid_key_error(struct connman_network *network)
{
	struct connman_service *service;

	service = __connman_service_lookup_from_network(network);

	__connman_service_indicate_error(service,
					CONNMAN_SERVICE_ERROR_INVALID_KEY);
}

static void set_connect_error(struct connman_network *network)
{
	struct connman_service *service;

	service = __connman_service_lookup_from_network(network);

	__connman_service_indicate_error(service,
					CONNMAN_SERVICE_ERROR_CONNECT_FAILED);
}

void connman_network_set_ipv4_method(struct connman_network *network,
					enum connman_ipconfig_method method)
{
	struct connman_service *service;
	struct connman_ipconfig *ipconfig;

	service = __connman_service_lookup_from_network(network);
	if (service == NULL)
		return;

	ipconfig = __connman_service_get_ip4config(service);
	if (ipconfig == NULL)
		return;

	connman_ipconfig_set_method(ipconfig, method);
}

void connman_network_set_ipv6_method(struct connman_network *network,
					enum connman_ipconfig_method method)
{
	struct connman_service *service;
	struct connman_ipconfig *ipconfig;

	service = __connman_service_lookup_from_network(network);
	if (service == NULL)
		return;

	ipconfig = __connman_service_get_ip6config(service);
	if (ipconfig == NULL)
		return;

	connman_ipconfig_set_method(ipconfig, method);
}

void connman_network_set_error(struct connman_network *network,
					enum connman_network_error error)
{
	DBG("nework %p, error %d", network, error);

	network->connecting = FALSE;
	network->associating = FALSE;

	switch (error) {
	case CONNMAN_NETWORK_ERROR_UNKNOWN:
		return;
	case CONNMAN_NETWORK_ERROR_ASSOCIATE_FAIL:
		set_associate_error(network);
		break;
	case CONNMAN_NETWORK_ERROR_CONFIGURE_FAIL:
		set_configure_error(network);
		break;
	case CONNMAN_NETWORK_ERROR_INVALID_KEY:
		set_invalid_key_error(network);
		break;
	case CONNMAN_NETWORK_ERROR_CONNECT_FAIL:
		set_connect_error(network);
		break;
	}

	network_change(network);
}

void connman_network_clear_error(struct connman_network *network)
{
	struct connman_service *service;

	DBG("network %p", network);

	if (network == NULL)
		return;

	if (network->connecting == TRUE || network->associating == TRUE)
		return;

	service = __connman_service_lookup_from_network(network);
	__connman_service_clear_error(service);
}

static void set_configuration(struct connman_network *network)
{
	struct connman_service *service;

	DBG("network %p", network);

	if (network->device == NULL)
		return;

	__connman_device_set_network(network->device, network);

	connman_device_set_disconnected(network->device, FALSE);

	service = __connman_service_lookup_from_network(network);
	__connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_CONFIGURATION,
					CONNMAN_IPCONFIG_TYPE_IPV4);
}

static void dhcp_success(struct connman_network *network)
{
	struct connman_service *service;
	struct connman_ipconfig *ipconfig_ipv4;
	int err;

	service = __connman_service_lookup_from_network(network);
	if (service == NULL)
		goto err;

	connman_network_set_associating(network, FALSE);

	network->connecting = FALSE;

	ipconfig_ipv4 = __connman_service_get_ip4config(service);
	err = __connman_ipconfig_address_add(ipconfig_ipv4);
	if (err < 0)
		goto err;

	err = __connman_ipconfig_gateway_add(ipconfig_ipv4);
	if (err < 0)
		goto err;

	return;

err:
	connman_network_set_error(network,
				CONNMAN_NETWORK_ERROR_CONFIGURE_FAIL);
}

static void dhcp_failure(struct connman_network *network)
{
	struct connman_service *service;

	service = __connman_service_lookup_from_network(network);
	if (service == NULL)
		return;

	__connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_IDLE,
					CONNMAN_IPCONFIG_TYPE_IPV4);
}

static void dhcp_callback(struct connman_network *network,
			connman_bool_t success)
{
	DBG("success %d", success);

	if (success == TRUE)
		dhcp_success(network);
	else
		dhcp_failure(network);
}

static int set_connected_fixed(struct connman_network *network)
{
	struct connman_service *service;
	struct connman_ipconfig *ipconfig_ipv4;
	int err;

	DBG("");

	service = __connman_service_lookup_from_network(network);

	ipconfig_ipv4 = __connman_service_get_ip4config(service);

	set_configuration(network);

	network->connecting = FALSE;

	connman_network_set_associating(network, FALSE);

	err = __connman_ipconfig_address_add(ipconfig_ipv4);
	if (err < 0)
		goto err;

	err = __connman_ipconfig_gateway_add(ipconfig_ipv4);
	if (err < 0)
		goto err;

	return 0;

err:
	connman_network_set_error(network,
			CONNMAN_NETWORK_ERROR_CONFIGURE_FAIL);

	return err;
}

static void set_connected_manual(struct connman_network *network)
{
	struct connman_service *service;
	struct connman_ipconfig *ipconfig;
	int err;

	DBG("network %p", network);

	service = __connman_service_lookup_from_network(network);

	ipconfig = __connman_service_get_ip4config(service);

	if (__connman_ipconfig_get_local(ipconfig) == NULL)
		__connman_service_read_ip4config(service);

	set_configuration(network);

	err = __connman_ipconfig_address_add(ipconfig);
	if (err < 0)
		goto err;

	err = __connman_ipconfig_gateway_add(ipconfig);
	if (err < 0)
		goto err;

	network->connecting = FALSE;

	connman_network_set_associating(network, FALSE);

	return;

err:
	connman_network_set_error(network,
					CONNMAN_NETWORK_ERROR_CONFIGURE_FAIL);
	return;
}

static int set_connected_dhcp(struct connman_network *network)
{
	int err;

	DBG("network %p", network);

	set_configuration(network);

	err = __connman_dhcp_start(network, dhcp_callback);
	if (err < 0) {
		connman_error("Can not request DHCP lease");
		return err;
	}

	return 0;
}

static int manual_ipv6_set(struct connman_network *network,
				struct connman_ipconfig *ipconfig_ipv6)
{
	struct connman_service *service;
	int err;

	DBG("network %p ipv6 %p", network, ipconfig_ipv6);

	service = __connman_service_lookup_from_network(network);
	if (service == NULL)
		return -EINVAL;

	if (__connman_ipconfig_get_local(ipconfig_ipv6) == NULL)
		__connman_service_read_ip6config(service);

	err = __connman_ipconfig_address_add(ipconfig_ipv6);
	if (err < 0) {
		connman_network_set_error(network,
			CONNMAN_NETWORK_ERROR_CONFIGURE_FAIL);
		return err;
	}

	err = __connman_ipconfig_gateway_add(ipconfig_ipv6);
	if (err < 0)
		return err;

	__connman_connection_gateway_activate(service,
						CONNMAN_IPCONFIG_TYPE_IPV6);

	__connman_device_set_network(network->device, network);

	connman_device_set_disconnected(network->device, FALSE);

	network->connecting = FALSE;

	return 0;
}

static void autoconf_ipv6_set(struct connman_network *network)
{
	DBG("network %p", network);

	__connman_device_set_network(network->device, network);

	connman_device_set_disconnected(network->device, FALSE);

	/* XXX: Append IPv6 nameservers here */

	network->connecting = FALSE;
}

static gboolean set_connected(gpointer user_data)
{
	struct connman_network *network = user_data;
	struct connman_service *service;
	struct connman_ipconfig *ipconfig_ipv4, *ipconfig_ipv6;
	enum connman_ipconfig_method ipv4_method, ipv6_method;

	service = __connman_service_lookup_from_network(network);

	ipconfig_ipv4 = __connman_service_get_ip4config(service);
	ipconfig_ipv6 = __connman_service_get_ip6config(service);

	DBG("service %p ipv4 %p ipv6 %p", service, ipconfig_ipv4,
		ipconfig_ipv6);

	ipv4_method = __connman_ipconfig_get_method(ipconfig_ipv4);
	ipv6_method = __connman_ipconfig_get_method(ipconfig_ipv6);

	DBG("method ipv4 %d ipv6 %d", ipv4_method, ipv6_method);
	DBG("network connected %d", network->connected);

	if (network->connected == TRUE) {
		int ret;

		switch (ipv6_method) {
		case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
		case CONNMAN_IPCONFIG_METHOD_OFF:
			break;
		case CONNMAN_IPCONFIG_METHOD_AUTO:
			autoconf_ipv6_set(network);
			break;
		case CONNMAN_IPCONFIG_METHOD_FIXED:
		case CONNMAN_IPCONFIG_METHOD_MANUAL:
			ret = manual_ipv6_set(network, ipconfig_ipv6);
			if (ret != 0) {
				connman_network_set_error(network,
					CONNMAN_NETWORK_ERROR_ASSOCIATE_FAIL);
				return FALSE;
			}
			break;
		case CONNMAN_IPCONFIG_METHOD_DHCP:
			break;
		}

		switch (ipv4_method) {
		case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
		case CONNMAN_IPCONFIG_METHOD_OFF:
		case CONNMAN_IPCONFIG_METHOD_AUTO:
			return FALSE;
		case CONNMAN_IPCONFIG_METHOD_FIXED:
			if (set_connected_fixed(network) < 0) {
				connman_network_set_error(network,
					CONNMAN_NETWORK_ERROR_ASSOCIATE_FAIL);
				return FALSE;
			}
			return TRUE;
		case CONNMAN_IPCONFIG_METHOD_MANUAL:
			set_connected_manual(network);
			return TRUE;
		case CONNMAN_IPCONFIG_METHOD_DHCP:
			if (set_connected_dhcp(network) < 0) {
				connman_network_set_error(network,
					CONNMAN_NETWORK_ERROR_ASSOCIATE_FAIL);
				return FALSE;
			}
		}

	} else {
		enum connman_service_state state;

		__connman_device_set_network(network->device, NULL);

		switch (ipv4_method) {
		case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
		case CONNMAN_IPCONFIG_METHOD_OFF:
		case CONNMAN_IPCONFIG_METHOD_AUTO:
		case CONNMAN_IPCONFIG_METHOD_FIXED:
		case CONNMAN_IPCONFIG_METHOD_MANUAL:
			break;
		case CONNMAN_IPCONFIG_METHOD_DHCP:
			__connman_dhcp_stop(network);
			break;
		}

		/*
		 * We only set the disconnect state if we were not in idle
		 * or in failure. It does not make sense to go to disconnect
		 * state if we were not connected.
		 */
		state = __connman_service_ipconfig_get_state(service,
						CONNMAN_IPCONFIG_TYPE_IPV4);
		if (state != CONNMAN_SERVICE_STATE_IDLE &&
					state != CONNMAN_SERVICE_STATE_FAILURE)
			__connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_DISCONNECT,
					CONNMAN_IPCONFIG_TYPE_IPV4);

		state = __connman_service_ipconfig_get_state(service,
						CONNMAN_IPCONFIG_TYPE_IPV6);
		if (state != CONNMAN_SERVICE_STATE_IDLE &&
					state != CONNMAN_SERVICE_STATE_FAILURE)
			__connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_DISCONNECT,
					CONNMAN_IPCONFIG_TYPE_IPV6);

		__connman_connection_gateway_remove(service,
						CONNMAN_IPCONFIG_TYPE_ALL);

		__connman_ipconfig_address_unset(ipconfig_ipv4);
		__connman_ipconfig_address_unset(ipconfig_ipv6);

		/*
		 * Special handling for IPv6 autoconfigured address.
		 * The simplest way to remove autoconfigured routes is to
		 * disable IPv6 temporarily so that kernel will do the cleanup
		 * automagically.
		 */
		if (ipv6_method == CONNMAN_IPCONFIG_METHOD_AUTO) {
			__connman_ipconfig_disable_ipv6(ipconfig_ipv6);
			__connman_ipconfig_enable_ipv6(ipconfig_ipv6);
		}

		__connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_IDLE,
					CONNMAN_IPCONFIG_TYPE_IPV4);

		__connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_IDLE,
					CONNMAN_IPCONFIG_TYPE_IPV6);
	}

	network->connecting = FALSE;

	connman_network_set_associating(network, FALSE);

	return FALSE;
}

/**
 * connman_network_set_connected:
 * @network: network structure
 * @connected: connected state
 *
 * Change connected state of network
 */
int connman_network_set_connected(struct connman_network *network,
						connman_bool_t connected)
{
	DBG("network %p connected %d", network, connected);

	if ((network->connecting == TRUE || network->associating == TRUE) &&
							connected == FALSE) {
		connman_network_set_error(network,
					CONNMAN_NETWORK_ERROR_CONNECT_FAIL);
		__connman_network_disconnect(network);
	}

	if (network->connected == connected)
		return -EALREADY;

	network->connected = connected;

	set_connected(network);

	return 0;
}

/**
 * connman_network_get_connected:
 * @network: network structure
 *
 * Get network connection status
 */
connman_bool_t connman_network_get_connected(struct connman_network *network)
{
	return network->connected;
}

/**
 * connman_network_get_associating:
 * @network: network structure
 *
 * Get network associating status
 */
connman_bool_t connman_network_get_associating(struct connman_network *network)
{
	return network->associating;
}

/**
 * __connman_network_connect:
 * @network: network structure
 *
 * Connect network
 */
int __connman_network_connect(struct connman_network *network)
{
	int err;

	DBG("network %p", network);

	if (network->connected == TRUE)
		return -EISCONN;

	if (network->connecting == TRUE || network->associating == TRUE)
		return -EALREADY;

	if (network->driver == NULL)
		return -EUNATCH;

	if (network->driver->connect == NULL)
		return -ENOSYS;

	if (network->device == NULL)
		return -ENODEV;

	network->connecting = TRUE;

	__connman_device_disconnect(network->device);

	err = network->driver->connect(network);
	if (err < 0) {
		if (err == -EINPROGRESS)
			connman_network_set_associating(network, TRUE);
		else {
			network->connecting = FALSE;
		}

		return err;
	}

	network->connected = TRUE;
	set_connected(network);

	return err;
}

/**
 * __connman_network_disconnect:
 * @network: network structure
 *
 * Disconnect network
 */
int __connman_network_disconnect(struct connman_network *network)
{
	int err;

	DBG("network %p", network);

	if (network->connected == FALSE && network->connecting == FALSE &&
						network->associating == FALSE)
		return -ENOTCONN;

	if (network->driver == NULL)
		return -EUNATCH;

	if (network->driver->disconnect == NULL)
		return -ENOSYS;

	network->connecting = FALSE;

	err = network->driver->disconnect(network);
	if (err == 0) {
		connman_network_set_connected(network, FALSE);
		set_connected(network);
	}

	return err;
}

static int manual_ipv4_set(struct connman_network *network,
				struct connman_ipconfig *ipconfig)
{
	struct connman_service *service;
	int err;

	service = __connman_service_lookup_from_network(network);
	if (service == NULL)
		return -EINVAL;

	err = __connman_ipconfig_address_add(ipconfig);
	if (err < 0) {
		connman_network_set_error(network,
			CONNMAN_NETWORK_ERROR_CONFIGURE_FAIL);
		return err;
	}

	return __connman_ipconfig_gateway_add(ipconfig);
}

int __connman_network_clear_ipconfig(struct connman_network *network,
					struct connman_ipconfig *ipconfig)
{
	struct connman_service *service;
	enum connman_ipconfig_method method;
	enum connman_ipconfig_type type;

	service = __connman_service_lookup_from_network(network);
	if (service == NULL)
		return -EINVAL;

	method = __connman_ipconfig_get_method(ipconfig);
	type = __connman_ipconfig_get_config_type(ipconfig);

	switch (method) {
	case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
	case CONNMAN_IPCONFIG_METHOD_OFF:
	case CONNMAN_IPCONFIG_METHOD_FIXED:
	case CONNMAN_IPCONFIG_METHOD_AUTO:
		return -EINVAL;
	case CONNMAN_IPCONFIG_METHOD_MANUAL:
		__connman_ipconfig_address_remove(ipconfig);
		break;
	case CONNMAN_IPCONFIG_METHOD_DHCP:
		__connman_dhcp_stop(network);
		break;
	}

	if (type == CONNMAN_IPCONFIG_TYPE_IPV6)
		__connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_CONFIGURATION,
					CONNMAN_IPCONFIG_TYPE_IPV6);
	else if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		__connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_CONFIGURATION,
					CONNMAN_IPCONFIG_TYPE_IPV4);

	return 0;
}

int __connman_network_set_ipconfig(struct connman_network *network,
					struct connman_ipconfig *ipconfig_ipv4,
					struct connman_ipconfig *ipconfig_ipv6)
{
	enum connman_ipconfig_method method;
	int ret;

	if (network == NULL)
		return -EINVAL;

	if (ipconfig_ipv6) {
		method = __connman_ipconfig_get_method(ipconfig_ipv6);

		switch (method) {
		case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
		case CONNMAN_IPCONFIG_METHOD_OFF:
			break;
		case CONNMAN_IPCONFIG_METHOD_AUTO:
			autoconf_ipv6_set(network);
			break;
		case CONNMAN_IPCONFIG_METHOD_FIXED:
		case CONNMAN_IPCONFIG_METHOD_MANUAL:
			ret = manual_ipv6_set(network, ipconfig_ipv6);
			if (ret != 0) {
				connman_network_set_error(network,
					CONNMAN_NETWORK_ERROR_ASSOCIATE_FAIL);
				return ret;
			}
			break;
		case CONNMAN_IPCONFIG_METHOD_DHCP:
			break;
		}
	}

	if (ipconfig_ipv4) {
		method = __connman_ipconfig_get_method(ipconfig_ipv4);

		switch (method) {
		case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
		case CONNMAN_IPCONFIG_METHOD_OFF:
		case CONNMAN_IPCONFIG_METHOD_FIXED:
		case CONNMAN_IPCONFIG_METHOD_AUTO:
			return -EINVAL;
		case CONNMAN_IPCONFIG_METHOD_MANUAL:
			return manual_ipv4_set(network, ipconfig_ipv4);
		case CONNMAN_IPCONFIG_METHOD_DHCP:
			return __connman_dhcp_start(network, dhcp_callback);
		}
	}

	return 0;
}

int connman_network_set_ipaddress(struct connman_network *network,
					struct connman_ipaddress *ipaddress)
{
	struct connman_service *service;
	struct connman_ipconfig *ipconfig = NULL;

	DBG("network %p", network);

	service = __connman_service_lookup_from_network(network);
	if (service == NULL)
		return -EINVAL;

	ipconfig = __connman_service_get_ipconfig(service, ipaddress->family);
	if (ipconfig == NULL)
		return -EINVAL;

	__connman_ipconfig_set_local(ipconfig, ipaddress->local);
	__connman_ipconfig_set_peer(ipconfig, ipaddress->peer);
	__connman_ipconfig_set_broadcast(ipconfig, ipaddress->broadcast);
	__connman_ipconfig_set_prefixlen(ipconfig, ipaddress->prefixlen);
	__connman_ipconfig_set_gateway(ipconfig, ipaddress->gateway);

	return 0;
}

int connman_network_set_nameservers(struct connman_network *network,
				const char *nameservers)
{
	struct connman_service *service;
	char **nameservers_array;
	int i;

	DBG("network %p nameservers %s", network, nameservers);

	service = __connman_service_lookup_from_network(network);
	if (service == NULL)
		return -EINVAL;

	__connman_service_nameserver_clear(service);

	if (nameservers == NULL)
		return 0;

	nameservers_array = g_strsplit(nameservers, " ", 0);

	for (i = 0; nameservers_array[i] != NULL; i++) {
		__connman_service_nameserver_append(service,
						nameservers_array[i]);
	}

	g_strfreev(nameservers_array);

	return 0;
}

int connman_network_set_domain(struct connman_network *network,
				const char *domain)
{
	struct connman_service *service;

	DBG("network %p domain %s", network, domain);

	service = __connman_service_lookup_from_network(network);
	if (service == NULL)
		return -EINVAL;

	__connman_service_set_domainname(service, domain);

	return 0;
}

/**
 * connman_network_set_name:
 * @network: network structure
 * @name: name value
 *
 * Set display name value for network
 */
int connman_network_set_name(struct connman_network *network,
							const char *name)
{
	DBG("network %p name %s", network, name);

	g_free(network->name);
	network->name = g_strdup(name);

	return 0;
}

/**
 * connman_network_set_strength:
 * @network: network structure
 * @strength: strength value
 *
 * Set signal strength value for network
 */

int connman_network_set_strength(struct connman_network *network,
						connman_uint8_t strength)
{
	DBG("network %p strengh %d", network, strength);

	network->strength = strength;

	return 0;
}

connman_uint8_t connman_network_get_strength(struct connman_network *network)
{
	return network->strength;
}

int connman_network_set_frequency(struct connman_network *network,
						connman_uint16_t frequency)
{
	DBG("network %p frequency %d", network, frequency);

	network->frequency = frequency;

	return 0;
}

connman_uint16_t connman_network_get_frequency(struct connman_network *network)
{
	return network->frequency;
}

int connman_network_set_wifi_channel(struct connman_network *network,
						connman_uint16_t channel)
{
	DBG("network %p wifi channel %d", network, channel);

	network->wifi.channel = channel;

	return 0;
}

connman_uint16_t connman_network_get_wifi_channel(struct connman_network *network)
{
	return network->wifi.channel;
}

/**
 * connman_network_set_roaming:
 * @network: network structure
 * @roaming: roaming state
 *
 * Set roaming state for network
 */
int connman_network_set_roaming(struct connman_network *network,
						connman_bool_t roaming)
{
	DBG("network %p roaming %d", network, roaming);

	network->roaming = roaming;

	return 0;
}

/**
 * connman_network_set_string:
 * @network: network structure
 * @key: unique identifier
 * @value: string value
 *
 * Set string value for specific key
 */
int connman_network_set_string(struct connman_network *network,
					const char *key, const char *value)
{
	DBG("network %p key %s value %s", network, key, value);

	if (g_strcmp0(key, "Name") == 0)
		return connman_network_set_name(network, value);

	if (g_str_equal(key, "Path") == TRUE) {
		g_free(network->path);
		network->path = g_strdup(value);
	} else if (g_str_equal(key, "Node") == TRUE) {
		g_free(network->node);
		network->node = g_strdup(value);
	} else if (g_str_equal(key, "WiFi.Mode") == TRUE) {
		g_free(network->wifi.mode);
		network->wifi.mode = g_strdup(value);
	} else if (g_str_equal(key, "WiFi.Security") == TRUE) {
		g_free(network->wifi.security);
		network->wifi.security = g_strdup(value);
	} else if (g_str_equal(key, "WiFi.Passphrase") == TRUE) {
		g_free(network->wifi.passphrase);
		network->wifi.passphrase = g_strdup(value);
	} else if (g_str_equal(key, "WiFi.AgentPassphrase") == TRUE) {
		g_free(network->wifi.agent_passphrase);
		network->wifi.agent_passphrase = g_strdup(value);
	} else if (g_str_equal(key, "WiFi.EAP") == TRUE) {
		g_free(network->wifi.eap);
		network->wifi.eap = g_strdup(value);
	} else if (g_str_equal(key, "WiFi.Identity") == TRUE) {
		g_free(network->wifi.identity);
		network->wifi.identity = g_strdup(value);
	} else if (g_str_equal(key, "WiFi.AgentIdentity") == TRUE) {
		g_free(network->wifi.agent_identity);
		network->wifi.agent_identity = g_strdup(value);
	} else if (g_str_equal(key, "WiFi.CACertFile") == TRUE) {
		g_free(network->wifi.ca_cert_path);
		network->wifi.ca_cert_path = g_strdup(value);
	} else if (g_str_equal(key, "WiFi.ClientCertFile") == TRUE) {
		g_free(network->wifi.client_cert_path);
		network->wifi.client_cert_path = g_strdup(value);
	} else if (g_str_equal(key, "WiFi.PrivateKeyFile") == TRUE) {
		g_free(network->wifi.private_key_path);
		network->wifi.private_key_path = g_strdup(value);
	} else if (g_str_equal(key, "WiFi.PrivateKeyPassphrase") == TRUE) {
		g_free(network->wifi.private_key_passphrase);
		network->wifi.private_key_passphrase = g_strdup(value);
	} else if (g_str_equal(key, "WiFi.Phase2") == TRUE) {
		g_free(network->wifi.phase2_auth);
		network->wifi.phase2_auth = g_strdup(value);
	} else if (g_str_equal(key, "WiFi.PinWPS") == TRUE) {
		g_free(network->wifi.pin_wps);
		network->wifi.pin_wps = g_strdup(value);
	} else {
		return -EINVAL;
	}

	return 0;
}

/**
 * connman_network_get_string:
 * @network: network structure
 * @key: unique identifier
 *
 * Get string value for specific key
 */
const char *connman_network_get_string(struct connman_network *network,
							const char *key)
{
	DBG("network %p key %s", network, key);

	if (g_str_equal(key, "Path") == TRUE)
		return network->path;
	else if (g_str_equal(key, "Name") == TRUE)
		return network->name;
	else if (g_str_equal(key, "Node") == TRUE)
		return network->node;
	else if (g_str_equal(key, "WiFi.Mode") == TRUE)
		return network->wifi.mode;
	else if (g_str_equal(key, "WiFi.Security") == TRUE)
		return network->wifi.security;
	else if (g_str_equal(key, "WiFi.Passphrase") == TRUE)
		return network->wifi.passphrase;
	else if (g_str_equal(key, "WiFi.AgentPassphrase") == TRUE)
		return network->wifi.agent_passphrase;
	else if (g_str_equal(key, "WiFi.EAP") == TRUE)
		return network->wifi.eap;
	else if (g_str_equal(key, "WiFi.Identity") == TRUE)
		return network->wifi.identity;
	else if (g_str_equal(key, "WiFi.AgentIdentity") == TRUE)
		return network->wifi.agent_identity;
	else if (g_str_equal(key, "WiFi.CACertFile") == TRUE)
		return network->wifi.ca_cert_path;
	else if (g_str_equal(key, "WiFi.ClientCertFile") == TRUE)
		return network->wifi.client_cert_path;
	else if (g_str_equal(key, "WiFi.PrivateKeyFile") == TRUE)
		return network->wifi.private_key_path;
	else if (g_str_equal(key, "WiFi.PrivateKeyPassphrase") == TRUE)
		return network->wifi.private_key_passphrase;
	else if (g_str_equal(key, "WiFi.Phase2") == TRUE)
		return network->wifi.phase2_auth;
	else if (g_str_equal(key, "WiFi.PinWPS") == TRUE)
		return network->wifi.pin_wps;

	return NULL;
}

/**
 * connman_network_set_bool:
 * @network: network structure
 * @key: unique identifier
 * @value: boolean value
 *
 * Set boolean value for specific key
 */
int connman_network_set_bool(struct connman_network *network,
					const char *key, connman_bool_t value)
{
	DBG("network %p key %s value %d", network, key, value);

	if (g_strcmp0(key, "Roaming") == 0)
		return connman_network_set_roaming(network, value);
	else if (g_strcmp0(key, "WiFi.WPS") == 0)
		network->wifi.wps = value;
	else if (g_strcmp0(key, "WiFi.UseWPS") == 0)
		network->wifi.use_wps = value;

	return -EINVAL;
}

/**
 * connman_network_get_bool:
 * @network: network structure
 * @key: unique identifier
 *
 * Get boolean value for specific key
 */
connman_bool_t connman_network_get_bool(struct connman_network *network,
							const char *key)
{
	DBG("network %p key %s", network, key);

	if (g_str_equal(key, "Roaming") == TRUE)
		return network->roaming;
	else if (g_str_equal(key, "WiFi.WPS") == TRUE)
		return network->wifi.wps;
	else if (g_str_equal(key, "WiFi.UseWPS") == TRUE)
		return network->wifi.use_wps;

	return FALSE;
}

/**
 * connman_network_set_blob:
 * @network: network structure
 * @key: unique identifier
 * @data: blob data
 * @size: blob size
 *
 * Set binary blob value for specific key
 */
int connman_network_set_blob(struct connman_network *network,
			const char *key, const void *data, unsigned int size)
{
	DBG("network %p key %s size %d", network, key, size);

	if (g_str_equal(key, "WiFi.SSID") == TRUE) {
		g_free(network->wifi.ssid);
		network->wifi.ssid = g_try_malloc(size);
		if (network->wifi.ssid != NULL) {
			memcpy(network->wifi.ssid, data, size);
			network->wifi.ssid_len = size;
		} else
			network->wifi.ssid_len = 0;
	} else {
		return -EINVAL;
	}

	return 0;
}

/**
 * connman_network_get_blob:
 * @network: network structure
 * @key: unique identifier
 * @size: pointer to blob size
 *
 * Get binary blob value for specific key
 */
const void *connman_network_get_blob(struct connman_network *network,
					const char *key, unsigned int *size)
{
	DBG("network %p key %s", network, key);

	if (g_str_equal(key, "WiFi.SSID") == TRUE) {
		if (size != NULL)
			*size = network->wifi.ssid_len;
		return network->wifi.ssid;
	}

	return NULL;
}

void __connman_network_set_device(struct connman_network *network,
					struct connman_device *device)
{
	if (network->device == device)
		return;

	if (network->device != NULL)
		network_remove(network);

	network->device = device;

	if (network->device != NULL)
		network_probe(network);
}

/**
 * connman_network_get_device:
 * @network: network structure
 *
 * Get parent device of network
 */
struct connman_device *connman_network_get_device(struct connman_network *network)
{
	return network->device;
}

/**
 * connman_network_get_data:
 * @network: network structure
 *
 * Get private network data pointer
 */
void *connman_network_get_data(struct connman_network *network)
{
	return network->driver_data;
}

/**
 * connman_network_set_data:
 * @network: network structure
 * @data: data pointer
 *
 * Set private network data pointer
 */
void connman_network_set_data(struct connman_network *network, void *data)
{
	network->driver_data = data;
}

void connman_network_update(struct connman_network *network)
{
	switch (network->type) {
	case CONNMAN_NETWORK_TYPE_UNKNOWN:
	case CONNMAN_NETWORK_TYPE_VENDOR:
		return;
	case CONNMAN_NETWORK_TYPE_ETHERNET:
	case CONNMAN_NETWORK_TYPE_BLUETOOTH_PAN:
	case CONNMAN_NETWORK_TYPE_BLUETOOTH_DUN:
	case CONNMAN_NETWORK_TYPE_CELLULAR:
	case CONNMAN_NETWORK_TYPE_WIFI:
	case CONNMAN_NETWORK_TYPE_WIMAX:
		break;
	}

	if (network->group != NULL)
		__connman_service_update_from_network(network);
}

int __connman_network_init(void)
{
	DBG("");

	return 0;
}

void __connman_network_cleanup(void)
{
	DBG("");
}
