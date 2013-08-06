/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2012  Intel Corporation. All rights reserved.
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
#include <net/if.h>

#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP	0x10000
#endif

#include <glib.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/technology.h>
#include <connman/plugin.h>
#include <connman/device.h>
#include <connman/inet.h>
#include <connman/rtnl.h>
#include <connman/log.h>
#include <connman/setting.h>

static bool eth_tethering = false;

struct ethernet_data {
	int index;
	unsigned flags;
	unsigned int watch;
	struct connman_network *network;
};

static int cable_probe(struct connman_network *network)
{
	DBG("network %p", network);

	return 0;
}

static void cable_remove(struct connman_network *network)
{
	DBG("network %p", network);
}

static int cable_connect(struct connman_network *network)
{
	DBG("network %p", network);

	connman_network_set_connected(network, true);

	return 0;
}

static int cable_disconnect(struct connman_network *network)
{
	DBG("network %p", network);

	connman_network_set_connected(network, false);

	return 0;
}

static struct connman_network_driver cable_driver = {
	.name		= "cable",
	.type		= CONNMAN_NETWORK_TYPE_ETHERNET,
	.probe		= cable_probe,
	.remove		= cable_remove,
	.connect	= cable_connect,
	.disconnect	= cable_disconnect,
};

static void add_network(struct connman_device *device,
			struct ethernet_data *ethernet)
{
	struct connman_network *network;
	int index;

	network = connman_network_create("carrier",
					CONNMAN_NETWORK_TYPE_ETHERNET);
	if (!network)
		return;

	index = connman_device_get_index(device);
	connman_network_set_index(network, index);

	connman_network_set_name(network, "Wired");

	if (connman_device_add_network(device, network) < 0) {
		connman_network_unref(network);
		return;
	}

	if (!eth_tethering)
		/*
		 * Prevent service from starting the reconnect
		 * procedure as we do not want the DHCP client
		 * to run when tethering.
		 */
		connman_network_set_group(network, "cable");

	ethernet->network = network;
}

static void remove_network(struct connman_device *device,
				struct ethernet_data *ethernet)
{
	if (!ethernet->network)
		return;

	connman_device_remove_network(device, ethernet->network);
	connman_network_unref(ethernet->network);

	ethernet->network = NULL;
}

static void ethernet_newlink(unsigned flags, unsigned change, void *user_data)
{
	struct connman_device *device = user_data;
	struct ethernet_data *ethernet = connman_device_get_data(device);

	DBG("index %d flags %d change %d", ethernet->index, flags, change);

	if ((ethernet->flags & IFF_UP) != (flags & IFF_UP)) {
		if (flags & IFF_UP) {
			DBG("power on");
			connman_device_set_powered(device, true);
		} else {
			DBG("power off");
			connman_device_set_powered(device, false);
		}
	}

	if ((ethernet->flags & IFF_LOWER_UP) != (flags & IFF_LOWER_UP)) {
		if (flags & IFF_LOWER_UP) {
			DBG("carrier on");
			add_network(device, ethernet);
		} else {
			DBG("carrier off");
			remove_network(device, ethernet);
		}
	}

	ethernet->flags = flags;
}

static int ethernet_probe(struct connman_device *device)
{
	struct ethernet_data *ethernet;

	DBG("device %p", device);

	ethernet = g_try_new0(struct ethernet_data, 1);
	if (!ethernet)
		return -ENOMEM;

	connman_device_set_data(device, ethernet);

	ethernet->index = connman_device_get_index(device);
	ethernet->flags = 0;

	ethernet->watch = connman_rtnl_add_newlink_watch(ethernet->index,
						ethernet_newlink, device);

	return 0;
}

static void ethernet_remove(struct connman_device *device)
{
	struct ethernet_data *ethernet = connman_device_get_data(device);

	DBG("device %p", device);

	connman_device_set_data(device, NULL);

	connman_rtnl_remove_watch(ethernet->watch);

	remove_network(device, ethernet);

	g_free(ethernet);
}

static int ethernet_enable(struct connman_device *device)
{
	struct ethernet_data *ethernet = connman_device_get_data(device);

	DBG("device %p", device);

	return connman_inet_ifup(ethernet->index);
}

static int ethernet_disable(struct connman_device *device)
{
	struct ethernet_data *ethernet = connman_device_get_data(device);

	DBG("device %p", device);

	return connman_inet_ifdown(ethernet->index);
}

static struct connman_device_driver ethernet_driver = {
	.name		= "ethernet",
	.type		= CONNMAN_DEVICE_TYPE_ETHERNET,
	.probe		= ethernet_probe,
	.remove		= ethernet_remove,
	.enable		= ethernet_enable,
	.disable	= ethernet_disable,
};

static int gadget_probe(struct connman_device *device)
{
	DBG("device %p", device);
	return 0;
}
static void gadget_remove(struct connman_device *device)
{
	DBG("device %p", device);
}
static int gadget_enable(struct connman_device *device)
{
	DBG("device %p", device);
	return 0;
}
static int gadget_disable(struct connman_device *device)
{
	DBG("device %p", device);
	return 0;
}

static struct connman_device_driver gadget_driver = {
	.name		= "gadget",
	.type		= CONNMAN_DEVICE_TYPE_GADGET,
	.probe		= gadget_probe,
	.remove		= gadget_remove,
	.enable		= gadget_enable,
	.disable	= gadget_disable,
};

static GList *cdc_interface_list = NULL;

static void tech_add_interface(struct connman_technology *technology,
			int index, const char *name, const char *ident)
{
	DBG("index %d name %s ident %s", index, name, ident);

	if (g_list_find(cdc_interface_list, GINT_TO_POINTER((int)index)))
		return;

	cdc_interface_list = g_list_prepend(cdc_interface_list,
					(GINT_TO_POINTER((int) index)));
}

static void tech_remove_interface(struct connman_technology *technology,
								int index)
{
	DBG("index %d", index);

	cdc_interface_list = g_list_remove(cdc_interface_list,
					GINT_TO_POINTER((int) index));
}

static void enable_tethering(struct connman_technology *technology,
						const char *bridge)
{
	GList *list;

	for (list = cdc_interface_list; list; list = list->next) {
		int index = GPOINTER_TO_INT(list->data);

		connman_technology_tethering_notify(technology, true);

		connman_inet_ifup(index);

		connman_inet_add_to_bridge(index, bridge);
	}
}

static void disable_tethering(struct connman_technology *technology,
						const char *bridge)
{
	GList *list;

	for (list = cdc_interface_list; list; list = list->next) {
		int index = GPOINTER_TO_INT(list->data);

		connman_inet_remove_from_bridge(index, bridge);

		connman_inet_ifdown(index);

		connman_technology_tethering_notify(technology, false);
	}
}

static int tech_set_tethering(struct connman_technology *technology,
				const char *identifier, const char *passphrase,
				const char *bridge, bool enabled)
{
	DBG("bridge %s enabled %d", bridge, enabled);

	if (enabled)
		enable_tethering(technology, bridge);
	else
		disable_tethering(technology, bridge);

	return 0;
}

static int tech_probe(struct connman_technology *technology)
{
	return 0;
}

static void tech_remove(struct connman_technology *technology)
{
	g_list_free(cdc_interface_list);

	cdc_interface_list = NULL;
}

static struct connman_technology_driver tech_driver = {
	.name			= "cdc_ethernet",
	.type			= CONNMAN_SERVICE_TYPE_GADGET,
	.probe			= tech_probe,
	.remove			= tech_remove,
	.add_interface		= tech_add_interface,
	.remove_interface	= tech_remove_interface,
	.set_tethering		= tech_set_tethering,
};

static int eth_probe(struct connman_technology *technology)
{
	return 0;
}

static void eth_remove(struct connman_technology *technology)
{
	DBG("");
}

static GList *eth_interface_list = NULL;

static void eth_add_interface(struct connman_technology *technology,
			int index, const char *name, const char *ident)
{
	DBG("index %d name %s ident %s", index, name, ident);

	if (g_list_find(eth_interface_list, GINT_TO_POINTER((int)index)))
		return;

	eth_interface_list = g_list_prepend(eth_interface_list,
					(GINT_TO_POINTER((int) index)));
}

static void eth_remove_interface(struct connman_technology *technology,
								int index)
{
	DBG("index %d", index);

	eth_interface_list = g_list_remove(eth_interface_list,
					GINT_TO_POINTER((int) index));
}

static void eth_enable_tethering(struct connman_technology *technology,
						const char *bridge)
{
	GList *list;

	for (list = eth_interface_list; list; list = list->next) {
		int index = GPOINTER_TO_INT(list->data);
		struct connman_device *device =
			connman_device_find_by_index(index);

		if (device)
			connman_device_disconnect_service(device);

		connman_technology_tethering_notify(technology, true);

		connman_inet_ifup(index);

		connman_inet_add_to_bridge(index, bridge);

		eth_tethering = true;
	}
}

static void eth_disable_tethering(struct connman_technology *technology,
						const char *bridge)
{
	GList *list;

	for (list = eth_interface_list; list; list = list->next) {
		int index = GPOINTER_TO_INT(list->data);
		struct connman_device *device =
			connman_device_find_by_index(index);

		connman_inet_remove_from_bridge(index, bridge);

		connman_inet_ifdown(index);

		connman_technology_tethering_notify(technology, false);

		if (device)
			connman_device_reconnect_service(device);

		eth_tethering = false;
	}
}

static int eth_set_tethering(struct connman_technology *technology,
				const char *identifier, const char *passphrase,
				const char *bridge, bool enabled)
{
	if (!connman_technology_is_tethering_allowed(
			CONNMAN_SERVICE_TYPE_ETHERNET))
		return 0;

	DBG("bridge %s enabled %d", bridge, enabled);

	if (enabled)
		eth_enable_tethering(technology, bridge);
	else
		eth_disable_tethering(technology, bridge);

	return 0;
}

static struct connman_technology_driver eth_driver = {
	.name			= "ethernet",
	.type			= CONNMAN_SERVICE_TYPE_ETHERNET,
	.probe			= eth_probe,
	.remove			= eth_remove,
	.add_interface		= eth_add_interface,
	.remove_interface	= eth_remove_interface,
	.set_tethering		= eth_set_tethering,
};

static int ethernet_init(void)
{
	int err;

	err = connman_technology_driver_register(&eth_driver);
	if (err < 0)
		return err;

	err = connman_network_driver_register(&cable_driver);
	if (err < 0)
		return err;

	err = connman_device_driver_register(&ethernet_driver);
	if (err < 0) {
		connman_network_driver_unregister(&cable_driver);
		return err;
	}

	err = connman_technology_driver_register(&tech_driver);
	if (err < 0) {
		connman_device_driver_unregister(&ethernet_driver);
		connman_network_driver_unregister(&cable_driver);
		return err;
	}

	err = connman_device_driver_register(&gadget_driver);
	if (err < 0) {
		connman_technology_driver_unregister(&tech_driver);
		connman_device_driver_unregister(&ethernet_driver);
		connman_network_driver_unregister(&cable_driver);
		return err;
	}

	return 0;
}

static void ethernet_exit(void)
{
	connman_technology_driver_unregister(&eth_driver);

	connman_technology_driver_unregister(&tech_driver);

	connman_network_driver_unregister(&cable_driver);

	connman_device_driver_unregister(&ethernet_driver);

	connman_device_driver_unregister(&gadget_driver);
}

CONNMAN_PLUGIN_DEFINE(ethernet, "Ethernet interface plugin", VERSION,
		CONNMAN_PLUGIN_PRIORITY_DEFAULT, ethernet_init, ethernet_exit)
