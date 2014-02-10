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
#include <connman/log.h>

static int gadget_dev_probe(struct connman_device *device)
{
	DBG("device %p", device);
	return 0;
}
static void gadget_dev_remove(struct connman_device *device)
{
	DBG("device %p", device);
}
static int gadget_dev_enable(struct connman_device *device)
{
	DBG("device %p", device);
	return 0;
}
static int gadget_dev_disable(struct connman_device *device)
{
	DBG("device %p", device);
	return 0;
}

static struct connman_device_driver gadget_dev_driver = {
	.name		= "gadget",
	.type		= CONNMAN_DEVICE_TYPE_GADGET,
	.probe		= gadget_dev_probe,
	.remove		= gadget_dev_remove,
	.enable		= gadget_dev_enable,
	.disable	= gadget_dev_disable,
};

static GList *cdc_interface_list = NULL;

static void gadget_tech_add_interface(struct connman_technology *technology,
			int index, const char *name, const char *ident)
{
	DBG("index %d name %s ident %s", index, name, ident);

	if (g_list_find(cdc_interface_list, GINT_TO_POINTER((int)index)))
		return;

	cdc_interface_list = g_list_prepend(cdc_interface_list,
					(GINT_TO_POINTER((int) index)));
}

static void gadget_tech_remove_interface(struct connman_technology *technology,
								int index)
{
	DBG("index %d", index);

	cdc_interface_list = g_list_remove(cdc_interface_list,
					GINT_TO_POINTER((int) index));
}

static void gadget_tech_enable_tethering(struct connman_technology *technology,
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

static void gadget_tech_disable_tethering(struct connman_technology *technology,
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

static int gadget_tech_set_tethering(struct connman_technology *technology,
				const char *identifier, const char *passphrase,
				const char *bridge, bool enabled)
{
	DBG("bridge %s enabled %d", bridge, enabled);

	if (enabled)
		gadget_tech_enable_tethering(technology, bridge);
	else
		gadget_tech_disable_tethering(technology, bridge);

	return 0;
}

static int gadget_tech_probe(struct connman_technology *technology)
{
	return 0;
}

static void gadget_tech_remove(struct connman_technology *technology)
{
	g_list_free(cdc_interface_list);

	cdc_interface_list = NULL;
}

static struct connman_technology_driver gadget_tech_driver = {
	.name			= "cdc_ethernet",
	.type			= CONNMAN_SERVICE_TYPE_GADGET,
	.probe			= gadget_tech_probe,
	.remove			= gadget_tech_remove,
	.add_interface		= gadget_tech_add_interface,
	.remove_interface	= gadget_tech_remove_interface,
	.set_tethering		= gadget_tech_set_tethering,
};

static int gadget_init(void)
{
	int err;

	err = connman_technology_driver_register(&gadget_tech_driver);
	if (err < 0) {
		return err;
	}

	err = connman_device_driver_register(&gadget_dev_driver);
	if (err < 0) {
		connman_technology_driver_unregister(&gadget_tech_driver);
		return err;
	}

	return 0;
}

static void gadget_exit(void)
{
	connman_technology_driver_unregister(&gadget_tech_driver);
	connman_device_driver_unregister(&gadget_dev_driver);
}

CONNMAN_PLUGIN_DEFINE(gadget, "Gadget interface plugin", VERSION,
		CONNMAN_PLUGIN_PRIORITY_DEFAULT, gadget_init, gadget_exit)
