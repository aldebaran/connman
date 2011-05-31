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

static unsigned int hidden_counter = 0;

struct connman_network {
	struct connman_element element;
	enum connman_network_type type;
	connman_bool_t available;
	connman_bool_t connected;
	connman_bool_t roaming;
	connman_bool_t hidden;
	connman_uint8_t strength;
	connman_uint16_t frequency;
	char *identifier;
	char *name;
	char *node;
	char *group;

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
		char *eap;
		char *identity;
		char *ca_cert_path;
		char *client_cert_path;
		char *private_key_path;
		char *private_key_passphrase;
		char *phase2_auth;
		connman_bool_t wps;
		connman_bool_t use_wps;
		char *pin_wps;
	} wifi;
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

static GSList *driver_list = NULL;

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
}

static void network_destruct(struct connman_element *element)
{
	struct connman_network *network = element->network;

	DBG("element %p name %s", element, element->name);

	g_free(network->wifi.ssid);
	g_free(network->wifi.mode);
	g_free(network->wifi.security);
	g_free(network->wifi.passphrase);
	g_free(network->wifi.eap);
	g_free(network->wifi.identity);
	g_free(network->wifi.ca_cert_path);
	g_free(network->wifi.client_cert_path);
	g_free(network->wifi.private_key_path);
	g_free(network->wifi.private_key_passphrase);
	g_free(network->wifi.phase2_auth);
	g_free(network->wifi.pin_wps);

	g_free(network->group);
	g_free(network->node);
	g_free(network->name);
	g_free(network->identifier);

	network->device = NULL;
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
	connman_uint8_t strength = 0;
	const char *str;
	char *temp;

	DBG("identifier %s type %d", identifier, type);

	network = g_try_new0(struct connman_network, 1);
	if (network == NULL)
		return NULL;

	DBG("network %p", network);

	__connman_element_initialize(&network->element);

	if (identifier == NULL) {
		temp = g_strdup_printf("hidden_%d", hidden_counter++);
		network->hidden = TRUE;
	} else
		temp = g_strdup(identifier);

	if (temp == NULL) {
		g_free(network);
		return NULL;
	}

	network->element.name = temp;
	network->element.type = CONNMAN_ELEMENT_TYPE_NETWORK;

	network->element.network = network;
	network->element.destruct = network_destruct;

	str = type2string(type);
	if (str != NULL)
		connman_element_set_string(&network->element, "Type", str);

	connman_element_set_uint8(&network->element, "Strength", strength);

	network->type       = type;
	network->identifier = g_strdup(temp);

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
	if (connman_element_ref(&network->element) == NULL)
		return NULL;

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
	connman_element_unref(&network->element);
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

	DBG("index %d service %p ip4config %p", network->element.index,
		service, ipconfig);

	if (network->element.index < 0 && ipconfig == NULL) {

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
	network->element.index = index;
}

/**
 * connman_network_get_index:
 * @network: network structure
 *
 * Get index number of network
 */
int connman_network_get_index(struct connman_network *network)
{
	return network->element.index;
}

/**
 * connman_network_get_element:
 * @network: network structure
 *
 * Get connman_element of network
 */
struct connman_element *connman_network_get_element(
				struct connman_network *network)
{
	return &network->element;
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
		__connman_service_create_from_network(network);
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
	if (network->hidden == TRUE)
		return TRUE;

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
		__connman_service_indicate_state(service,
					CONNMAN_SERVICE_STATE_ASSOCIATION,
					CONNMAN_IPCONFIG_TYPE_IPV4);
	}

	return 0;
}

static void set_associate_error(struct connman_network *network)
{
	struct connman_service *service;

	if (network->associating == FALSE)
		return ;

	network->associating = FALSE;

	service = __connman_service_lookup_from_network(network);

	__connman_service_indicate_state(service,
					CONNMAN_SERVICE_STATE_FAILURE,
					CONNMAN_IPCONFIG_TYPE_IPV4);
}

static void set_configure_error(struct connman_network *network)
{
	struct connman_service *service;

	network->connecting = FALSE;

	service = __connman_service_lookup_from_network(network);

	__connman_service_indicate_state(service,
					CONNMAN_SERVICE_STATE_FAILURE,
					CONNMAN_IPCONFIG_TYPE_IPV4);
}

static void set_invalid_key_error(struct connman_network *network)
{
	struct connman_service *service;

	service = __connman_service_lookup_from_network(network);

	__connman_service_indicate_error(service,
					CONNMAN_SERVICE_ERROR_INVALID_KEY);
}

void connman_network_set_ipv4_method(struct connman_network *network,
					enum connman_ipconfig_method method)
{
	struct connman_service *service;
	struct connman_ipconfig *ipconfig;

	network->element.ipv4.method = method;

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

	network->element.ipv6.method = method;

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
	}
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

	__connman_device_increase_connections(network->device);

	__connman_device_set_network(network->device, network);

	connman_device_set_disconnected(network->device, FALSE);

	service = __connman_service_lookup_from_network(network);
	__connman_service_indicate_state(service,
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

	__connman_service_indicate_state(service, CONNMAN_SERVICE_STATE_READY,
						CONNMAN_IPCONFIG_TYPE_IPV4);

	return;

err:
	connman_network_set_error(network,
				CONNMAN_NETWORK_ERROR_CONFIGURE_FAIL);
}

static void dhcp_failure(struct connman_network *network)
{
	struct connman_service *service;
	struct connman_ipconfig *ipconfig_ipv4;

	service = __connman_service_lookup_from_network(network);
	if (service == NULL)
		return;

	ipconfig_ipv4 = __connman_service_get_ip4config(service);
	__connman_ipconfig_address_remove(ipconfig_ipv4);

	__connman_service_indicate_state(service, CONNMAN_SERVICE_STATE_IDLE,
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

	__connman_service_indicate_state(service,
					CONNMAN_SERVICE_STATE_READY,
					CONNMAN_IPCONFIG_TYPE_IPV4);
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

	set_configuration(network);

	err = __connman_ipconfig_address_add(ipconfig);
	if (err < 0)
		goto err;

	err = __connman_ipconfig_gateway_add(ipconfig);
	if (err < 0)
		goto err;

	network->connecting = FALSE;

	connman_network_set_associating(network, FALSE);

	__connman_service_indicate_state(service, CONNMAN_SERVICE_STATE_READY,
					CONNMAN_IPCONFIG_TYPE_IPV4);

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

	service = __connman_service_lookup_from_network(network);
	if (service == NULL)
		return -EINVAL;

	err = __connman_ipconfig_address_add(ipconfig_ipv6);
	if (err < 0) {
		connman_network_set_error(network,
			CONNMAN_NETWORK_ERROR_CONFIGURE_FAIL);
		return err;
	}

	/*
	 * READY state will be indicated by IPV4 setting
	 * gateway will be set by IPV4 setting
	 */

	return 0;
}

static void autoconf_ipv6_set(struct connman_network *network)
{
	struct connman_service *service;
	const char *nameserver = NULL;

	DBG("network %p", network);

	service = __connman_service_lookup_from_network(network);

	__connman_device_increase_connections(network->device);

	__connman_device_set_network(network->device, network);

	connman_device_set_disconnected(network->device, FALSE);

	connman_element_get_value(&network->element,
			CONNMAN_PROPERTY_ID_IPV6_NAMESERVER, &nameserver);
	if (nameserver != NULL)
		__connman_service_nameserver_append(service, nameserver);

	network->connecting = FALSE;

	__connman_service_indicate_state(service,
					CONNMAN_SERVICE_STATE_READY,
					CONNMAN_IPCONFIG_TYPE_IPV6);
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
		struct connman_service *service;

		connman_element_unregister_children(&network->element);

		__connman_device_set_network(network->device, NULL);
		network->hidden = FALSE;

		service = __connman_service_lookup_from_network(network);

		__connman_service_indicate_state(service,
					CONNMAN_SERVICE_STATE_DISCONNECT,
					CONNMAN_IPCONFIG_TYPE_IPV4);

		__connman_service_indicate_state(service,
					CONNMAN_SERVICE_STATE_DISCONNECT,
					CONNMAN_IPCONFIG_TYPE_IPV6);

		__connman_connection_gateway_remove(service);

		__connman_service_indicate_state(service,
					CONNMAN_SERVICE_STATE_IDLE,
					CONNMAN_IPCONFIG_TYPE_IPV4);

		__connman_service_indicate_state(service,
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
		connman_element_set_error(&network->element,
					CONNMAN_ELEMENT_ERROR_CONNECT_FAILED);
		__connman_network_disconnect(network);
	}

	if (network->connected == connected)
		return -EALREADY;

	if (connected == FALSE)
		__connman_device_decrease_connections(network->device);

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
			network->hidden = FALSE;
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

	__connman_ipconfig_gateway_add(ipconfig);

	__connman_service_indicate_state(service, CONNMAN_SERVICE_STATE_READY,
					CONNMAN_IPCONFIG_TYPE_IPV4);

	return 0;
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
		__connman_service_indicate_state(service,
					CONNMAN_SERVICE_STATE_CONFIGURATION,
					CONNMAN_IPCONFIG_TYPE_IPV6);
	else if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		__connman_service_indicate_state(service,
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

int connman_network_set_pac(struct connman_network *network,
				const char *pac)
{
	struct connman_service *service;

	DBG("network %p pac %s", network, pac);

	service = __connman_service_lookup_from_network(network);
	if (service == NULL)
		return -EINVAL;

	__connman_service_set_pac(service, pac);

	return 0;
}

int connman_network_set_nameservers(struct connman_network *network,
				const char *nameservers)
{
	struct connman_service *service;
	char **nameservers_array = NULL;
	int i;

	DBG("network %p nameservers %s", network, nameservers);

	service = __connman_service_lookup_from_network(network);
	if (service == NULL)
		return -EINVAL;

	__connman_service_nameserver_clear(service);

	if (nameservers != NULL)
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

	return connman_element_set_string(&network->element, "Name", name);
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

	return connman_element_set_uint8(&network->element,
						"Strength", strength);
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

	return connman_element_set_bool(&network->element,
						"Roaming", roaming);
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
	int err;

	DBG("network %p key %s value %s", network, key, value);

	if (g_strcmp0(key, "Name") == 0)
		return connman_network_set_name(network, value);

	if (g_str_equal(key, "Node") == TRUE) {
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
	} else if (g_str_equal(key, "WiFi.EAP") == TRUE) {
		g_free(network->wifi.eap);
		network->wifi.eap = g_strdup(value);
	} else if (g_str_equal(key, "WiFi.Identity") == TRUE) {
		g_free(network->wifi.identity);
		network->wifi.identity = g_strdup(value);
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
	}

	err = connman_element_set_string(&network->element, key, value);
	if (err < 0)
		return err;

	if (network->driver == NULL)
		return 0;

	if (network->driver->setup)
		return network->driver->setup(network, key);

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

	if (g_str_equal(key, "Name") == TRUE)
		return network->name;
	else if (g_str_equal(key, "Node") == TRUE)
		return network->node;
	else if (g_str_equal(key, "WiFi.Mode") == TRUE)
		return network->wifi.mode;
	else if (g_str_equal(key, "WiFi.Security") == TRUE)
		return network->wifi.security;
	else if (g_str_equal(key, "WiFi.Passphrase") == TRUE)
		return network->wifi.passphrase;
	else if (g_str_equal(key, "WiFi.EAP") == TRUE)
		return network->wifi.eap;
	else if (g_str_equal(key, "WiFi.Identity") == TRUE)
		return network->wifi.identity;
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

	return connman_element_get_string(&network->element, key);
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

	return connman_element_set_bool(&network->element, key, value);
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

	return connman_element_get_bool(&network->element, key);
}

/**
 * connman_network_set_uint8:
 * @network: network structure
 * @key: unique identifier
 * @value: integer value
 *
 * Set integer value for specific key
 */
int connman_network_set_uint8(struct connman_network *network,
					const char *key, connman_uint8_t value)
{
	DBG("network %p key %s value %d", network, key, value);

	if (g_strcmp0(key, "Strength") == 0)
		return connman_network_set_strength(network, value);

	return connman_element_set_uint8(&network->element, key, value);
}

/**
 * connman_network_get_uint8:
 * @network: network structure
 * @key: unique identifier
 *
 * Get integer value for specific key
 */
connman_uint8_t connman_network_get_uint8(struct connman_network *network,
							const char *key)
{
	DBG("network %p key %s", network, key);

	if (g_str_equal(key, "Strength") == TRUE)
		return network->strength;

	return connman_element_get_uint8(&network->element, key);
}

/**
 * connman_network_set_uint16:
 * @network: network structure
 * @key: unique identifier
 * @value: integer value
 *
 * Set integer value for specific key
 */
int connman_network_set_uint16(struct connman_network *network,
				const char *key, connman_uint16_t value)
{
	DBG("network %p key %s value %d", network, key, value);

	if (g_str_equal(key, "Frequency") == TRUE)
		network->frequency = value;
	else if (g_str_equal(key, "WiFi.Channel") == TRUE)
		network->wifi.channel = value;

	return -EINVAL;
}

/**
 * connman_network_get_uint16:
 * @network: network structure
 * @key: unique identifier
 *
 * Get integer value for specific key
 */
connman_uint16_t connman_network_get_uint16(struct connman_network *network,
							const char *key)
{
	DBG("network %p key %s", network, key);

	if (g_str_equal(key, "Frequency") == TRUE)
		return network->frequency;
	else if (g_str_equal(key, "WiFi.Channel") == TRUE)
		return network->wifi.channel;

	return 0;
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
	}

	return connman_element_set_blob(&network->element, key, data, size);
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

	return connman_element_get_blob(&network->element, key, size);
}

void __connman_network_set_device(struct connman_network *network,
					struct connman_device *device)
{
	network->device = device;
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

	return;
}

static gboolean match_driver(struct connman_network *network,
					struct connman_network_driver *driver)
{
	if (network->type == driver->type ||
			driver->type == CONNMAN_NETWORK_TYPE_UNKNOWN)
		return TRUE;

	return FALSE;
}

static int network_probe(struct connman_element *element)
{
	struct connman_network *network = element->network;
	GSList *list;

	DBG("element %p name %s", element, element->name);

	if (network == NULL)
		return -ENODEV;

	for (list = driver_list; list; list = list->next) {
		struct connman_network_driver *driver = list->data;

		if (match_driver(network, driver) == FALSE)
			continue;

		DBG("driver %p name %s", driver, driver->name);

		if (driver->probe(network) == 0) {
			network->driver = driver;
			break;
		}
	}

	if (network->driver == NULL)
		return -ENODEV;

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
		if (network->group != NULL &&
			 __connman_service_create_from_network(network) == NULL)
				return -EINVAL;
	}

	return 0;
}

static void network_remove(struct connman_element *element)
{
	struct connman_network *network = element->network;

	DBG("element %p name %s", element, element->name);

	if (network == NULL)
		return;

	if (network->driver == NULL)
		return;

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
}

static void network_change(struct connman_element *element)
{
	struct connman_network *network = element->network;

	DBG("element %p name %s", element, element->name);

	if (element->state != CONNMAN_ELEMENT_STATE_ERROR)
		return;

	if (network->connected == FALSE)
		return;

	connman_element_unregister_children(element);

	connman_device_set_disconnected(network->device, TRUE);

	if (network->driver && network->driver->disconnect) {
		network->driver->disconnect(network);
		return;
	}

	network->connected = FALSE;
}

static struct connman_driver network_driver = {
	.name		= "network",
	.type		= CONNMAN_ELEMENT_TYPE_NETWORK,
	.priority	= CONNMAN_DRIVER_PRIORITY_LOW,
	.probe		= network_probe,
	.remove		= network_remove,
	.change		= network_change,
};

int __connman_network_init(void)
{
	DBG("");

	return connman_driver_register(&network_driver);
}

void __connman_network_cleanup(void)
{
	DBG("");

	connman_driver_unregister(&network_driver);
}
