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

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_arp.h>
#include <linux/wireless.h>

#include <gdbus.h>

#include <connman/plugin.h>
#include <connman/driver.h>
#include <connman/rtnl.h>
#include <connman/dbus.h>
#include <connman/log.h>

#include "inet.h"
#include "supplicant.h"

#define CLEANUP_TIMEOUT   8	/* in seconds */
#define INACTIVE_TIMEOUT  12	/* in seconds */

struct wifi_data {
	GSList *current;
	GSList *pending;
	guint cleanup_timer;
	guint inactive_timer;
	gchar *identifier;
	gboolean connected;
};

static int network_probe(struct connman_element *element)
{
	DBG("element %p name %s", element, element->name);

	return 0;
}

static void network_remove(struct connman_element *element)
{
	DBG("element %p name %s", element, element->name);
}

static int network_enable(struct connman_element *element)
{
	struct connman_element *device = element->parent;
	char *name, *security = NULL, *passphrase = NULL;
	unsigned char *ssid;
	int ssid_len;

	DBG("element %p name %s", element, element->name);

	if (connman_element_get_static_property(element,
						"Name", &name) == FALSE)
		return -EIO;

	if (connman_element_get_static_array_property(element,
				"WiFi.SSID", &ssid, &ssid_len) == FALSE)
		return -EIO;

	if (device != NULL) {
		struct wifi_data *data = connman_element_get_data(device);

		if (data != NULL) {
			if (data->connected == TRUE)
				return -EBUSY;

			g_free(data->identifier);
			data->identifier = g_strdup(name);
		}
	}

	connman_element_get_value(element,
			CONNMAN_PROPERTY_ID_WIFI_SECURITY, &security);

	connman_element_get_value(element,
			CONNMAN_PROPERTY_ID_WIFI_PASSPHRASE, &passphrase);

	DBG("name %s security %s passhprase %s",
					name, security, passphrase);

	if (__supplicant_connect(element, ssid, ssid_len,
						security, passphrase) < 0)
		connman_error("Failed to initiate connect");

	return 0;
}

static int network_disable(struct connman_element *element)
{
	DBG("element %p name %s", element, element->name);

	connman_element_unregister_children(element);

	__supplicant_disconnect(element);

	return 0;
}

static struct connman_driver network_driver = {
	.name		= "wifi-network",
	.type		= CONNMAN_ELEMENT_TYPE_NETWORK,
	.subtype	= CONNMAN_ELEMENT_SUBTYPE_WIFI,
	.probe		= network_probe,
	.remove		= network_remove,
	.enable		= network_enable,
	.disable	= network_disable,
};

static struct connman_element *find_current_element(struct wifi_data *data,
							const char *identifier)
{
	GSList *list;

	for (list = data->current; list; list = list->next) {
		struct connman_element *element = list->data;

		if (connman_element_match_static_property(element,
						"Name", &identifier) == TRUE)
			return element;
	}

	return NULL;
}

static struct connman_element *find_pending_element(struct wifi_data *data,
							const char *identifier)
{
	GSList *list;

	for (list = data->pending; list; list = list->next) {
		struct connman_element *element = list->data;

		if (connman_element_match_static_property(element,
						"Name", &identifier) == TRUE)
			return element;
	}

	return NULL;
}

static gboolean inactive_scan(gpointer user_data)
{
	struct connman_element *device = user_data;
	struct wifi_data *data = connman_element_get_data(device);

	DBG("");

	__supplicant_scan(device);

	data->inactive_timer = 0;

	return FALSE;
}

static void connect_known_networks(struct connman_element *device)
{
	struct wifi_data *data = connman_element_get_data(device);
	GSList *list;

	DBG("");

	if (data->inactive_timer > 0) {
		g_source_remove(data->inactive_timer);
		data->inactive_timer = 0;
	}

	for (list = data->current; list; list = list->next) {
		struct connman_element *element = list->data;

		if (element->policy == CONNMAN_ELEMENT_POLICY_AUTO &&
						element->remember == TRUE &&
						element->available == TRUE) {
			if (network_enable(element) == 0)
				return;
		}
	}

	data->inactive_timer = g_timeout_add_seconds(INACTIVE_TIMEOUT,
							inactive_scan, device);
}

static void state_change(struct connman_element *device,
						enum supplicant_state state)
{
	struct wifi_data *data = connman_element_get_data(device);
	struct connman_element *element;

	DBG("state %d", state);

	if (state == STATE_SCANNING)
		connman_element_set_scanning(device, TRUE);
	else
		connman_element_set_scanning(device, FALSE);

	if (data == NULL)
		return;

	if (data->identifier == NULL)
		goto reconnect;

	element = find_current_element(data, data->identifier);
	if (element == NULL)
		goto reconnect;

	if (state == STATE_COMPLETED) {
		struct connman_element *dhcp;

		data->connected = TRUE;
		connman_element_set_enabled(element, TRUE);

		dhcp = connman_element_create(NULL);

		dhcp->type = CONNMAN_ELEMENT_TYPE_DHCP;
		dhcp->index = element->index;

		if (connman_element_register(dhcp, element) < 0)
			connman_element_unref(dhcp);
	} else if (state == STATE_INACTIVE || state == STATE_DISCONNECTED) {
		data->connected = FALSE;
		connman_element_set_enabled(element, FALSE);

		connman_element_unregister_children(element);
	}

reconnect:
	if (state == STATE_INACTIVE) {
		data->connected = FALSE;
		connect_known_networks(device);
	}
}

static gboolean cleanup_pending(gpointer user_data)
{
	struct wifi_data *data = user_data;
	GSList *list;

	DBG("");

	for (list = data->pending; list; list = list->next) {
		struct connman_element *element = list->data;

		DBG("element %p name %s", element, element->name);

		connman_element_unregister(element);
		connman_element_unref(element);
	}

	g_slist_free(data->pending);
	data->pending = NULL;

	data->cleanup_timer = 0;

	return FALSE;
}

static void clear_results(struct connman_element *device)
{
	struct wifi_data *data = connman_element_get_data(device);

	DBG("pending %d", g_slist_length(data->pending));
	DBG("current %d", g_slist_length(data->current));

	if (data->cleanup_timer > 0) {
		g_source_remove(data->cleanup_timer);
		cleanup_pending(data);
	}

	data->pending = data->current;
	data->current = NULL;

	data->cleanup_timer = g_timeout_add_seconds(CLEANUP_TIMEOUT,
							cleanup_pending, data);
}

static void scan_result(struct connman_element *device,
					struct supplicant_network *network)
{
	struct wifi_data *data = connman_element_get_data(device);
	struct connman_element *element;
	gchar *temp;
	int i;

	DBG("network %p identifier %s", network, network->identifier);

	if (data == NULL)
		return;

	if (network->identifier == NULL)
		return;

	if (network->identifier[0] == '\0')
		return;

	temp = g_strdup(network->identifier);

	for (i = 0; i < strlen(temp); i++) {
		char tmp = temp[i];
		if ((tmp < '0' || tmp > '9') && (tmp < 'A' || tmp > 'Z') &&
						(tmp < 'a' || tmp > 'z'))
			temp[i] = '_';
	}

	element = find_pending_element(data, network->identifier);
	if (element == NULL) {
		element = connman_element_create(temp);

		element->type = CONNMAN_ELEMENT_TYPE_NETWORK;
		element->index = device->index;

		connman_element_add_static_property(element, "Name",
				DBUS_TYPE_STRING, &network->identifier);

		connman_element_add_static_array_property(element, "WiFi.SSID",
			DBUS_TYPE_BYTE, &network->ssid, network->ssid_len);

		if (element->wifi.security == NULL) {
			const char *security;

			if (network->has_rsn == TRUE)
				security = "wpa2";
			else if (network->has_wpa == TRUE)
				security = "wpa";
			else if (network->has_wep == TRUE)
				security = "wep";
			else
				security = "none";

			element->wifi.security = g_strdup(security);
		}

		element->strength = network->quality;

		connman_element_add_static_property(element, "Strength",
					DBUS_TYPE_BYTE, &element->strength);

		DBG("%s (%s) strength %d", network->identifier,
				element->wifi.security, element->strength);

		if (connman_element_register(element, device) < 0) {
			connman_element_unref(element);
			goto done;
		}
	} else {
		data->pending = g_slist_remove(data->pending, element);

		if (element->strength != network->quality) {
			element->strength = network->quality;

			connman_element_set_static_property(element, "Strength",
					DBUS_TYPE_BYTE, &element->strength);

			connman_element_update(element);
		}
	}

	data->current = g_slist_append(data->current, element);

	element->available = TRUE;

done:
	g_free(temp);
}

static struct supplicant_callback wifi_callback = {
	.state_change	= state_change,
	.clear_results	= clear_results,
	.scan_result	= scan_result,
};

static int wifi_probe(struct connman_element *element)
{
	struct wifi_data *data;

	DBG("element %p name %s", element, element->name);

	data = g_try_new0(struct wifi_data, 1);
	if (data == NULL)
		return -ENOMEM;

	data->connected = FALSE;

	connman_element_set_data(element, data);

	return 0;
}

static void wifi_remove(struct connman_element *element)
{
	struct wifi_data *data = connman_element_get_data(element);

	DBG("element %p name %s", element, element->name);

	connman_element_set_data(element, NULL);

	g_free(data->identifier);
	g_free(data);
}

static int wifi_update(struct connman_element *element)
{
	DBG("element %p name %s", element, element->name);

	__supplicant_scan(element);

	return 0;
}

static int wifi_enable(struct connman_element *element)
{
	int err;

	DBG("element %p name %s", element, element->name);

	err = __supplicant_start(element, &wifi_callback);
	if (err < 0)
		return err;

	__supplicant_scan(element);

	return 0;
}

static int wifi_disable(struct connman_element *element)
{
	struct wifi_data *data = connman_element_get_data(element);
	GSList *list;

	DBG("element %p name %s", element, element->name);

	if (data->cleanup_timer > 0) {
		g_source_remove(data->cleanup_timer);
		cleanup_pending(data);
	}

	if (data->inactive_timer > 0) {
		g_source_remove(data->inactive_timer);
		data->inactive_timer = 0;
	}

	__supplicant_disconnect(element);

	for (list = data->current; list; list = list->next) {
		struct connman_element *network = list->data;

		connman_element_unref(network);
	}

	g_slist_free(data->current);
	data->current = NULL;

	connman_element_unregister_children(element);

	__supplicant_stop(element);

	return 0;
}

static struct connman_driver wifi_driver = {
	.name		= "wifi-device",
	.type		= CONNMAN_ELEMENT_TYPE_DEVICE,
	.subtype	= CONNMAN_ELEMENT_SUBTYPE_WIFI,
	.probe		= wifi_probe,
	.remove		= wifi_remove,
	.update		= wifi_update,
	.enable		= wifi_enable,
	.disable	= wifi_disable,
};

static GSList *device_list = NULL;

static void wifi_newlink(unsigned short type, int index,
					unsigned flags, unsigned change)
{
	struct connman_element *device;
	GSList *list;
	gboolean exists = FALSE;
	gchar *name, *devname;
	struct iwreq iwr;
	int sk;

	DBG("index %d", index);

	if (type != ARPHRD_ETHER)
		return;

	name = inet_index2ident(index, "dev_");
	devname = inet_index2name(index);

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_ifrn.ifrn_name, devname, IFNAMSIZ);

	sk = socket(PF_INET, SOCK_DGRAM, 0);

	if (ioctl(sk, SIOCGIWNAME, &iwr) < 0) {
		g_free(name);
		close(sk);
		return;
	}

	close(sk);

	for (list = device_list; list; list = list->next) {
		struct connman_element *device = list->data;

		if (device->index == index) {
			exists = TRUE;
			break;
		}
	}

	if (exists == TRUE) {
		g_free(name);
		return;
	}

	device = connman_element_create(NULL);
	device->type = CONNMAN_ELEMENT_TYPE_DEVICE;
	device->subtype = CONNMAN_ELEMENT_SUBTYPE_WIFI;

	device->index = index;
	device->name = name;
	device->devname = devname;

	if (connman_element_register(device, NULL) < 0) {
		connman_element_unregister(device);
		return;
	}

	device_list = g_slist_append(device_list, device);
}

static void wifi_dellink(unsigned short type, int index,
					unsigned flags, unsigned change)
{
	GSList *list;

	DBG("index %d", index);

	for (list = device_list; list; list = list->next) {
		struct connman_element *device = list->data;

		if (device->index == index) {
			device_list = g_slist_remove(device_list, device);
			connman_element_unregister(device);
			connman_element_unref(device);
			break;
		}
	}
}

static struct connman_rtnl wifi_rtnl = {
	.name		= "wifi",
	.newlink	= wifi_newlink,
	.dellink	= wifi_dellink,
};

static void supplicant_connect(DBusConnection *connection, void *user_data)
{
	DBG("connection %p", connection);

	__supplicant_init(connection);

	if (connman_rtnl_register(&wifi_rtnl) < 0)
		return;

	connman_rtnl_send_getlink();
}

static void supplicant_disconnect(DBusConnection *connection, void *user_data)
{
	GSList *list;

	DBG("connection %p", connection);

	connman_rtnl_unregister(&wifi_rtnl);

	for (list = device_list; list; list = list->next) {
		struct connman_element *device = list->data;

		connman_element_unregister(device);
		connman_element_unref(device);
	}

	g_slist_free(device_list);
	device_list = NULL;

	__supplicant_exit();
}

static DBusConnection *connection;
static guint watch;

static int wifi_init(void)
{
	int err;

	connection = connman_dbus_get_connection();
	if (connection == NULL)
		return -EIO;

	err = connman_driver_register(&network_driver);
	if (err < 0) {
		dbus_connection_unref(connection);
		return err;
	}

	err = connman_driver_register(&wifi_driver);
	if (err < 0) {
		connman_driver_unregister(&network_driver);
		dbus_connection_unref(connection);
		return err;
	}

	watch = g_dbus_add_service_watch(connection, SUPPLICANT_NAME,
			supplicant_connect, supplicant_disconnect, NULL, NULL);

	if (g_dbus_check_service(connection, SUPPLICANT_NAME) == TRUE)
		supplicant_connect(connection, NULL);
	else
		__supplicant_activate(connection);

	return 0;
}

static void wifi_exit(void)
{
	connman_driver_unregister(&network_driver);
	connman_driver_unregister(&wifi_driver);

	if (watch > 0)
		g_dbus_remove_watch(connection, watch);

	supplicant_disconnect(connection, NULL);

	dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE(wifi, "WiFi interface plugin", VERSION,
							wifi_init, wifi_exit)
