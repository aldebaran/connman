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

#include <connman/plugin.h>
#include <connman/driver.h>
#include <connman/log.h>

static void create_element(struct connman_element *parent,
					enum connman_element_type type)
{
	struct connman_element *element;

	DBG("parent %p name %s", parent, parent->name);

	element = connman_element_create(NULL);
	if (element == NULL)
		return;

	element->type = type;
	element->index = parent->index;

	if (parent->parent)
		element->subtype = parent->parent->subtype;
	else
		element->subtype = CONNMAN_ELEMENT_SUBTYPE_UNKNOWN;

	connman_element_register(element, parent);
}

static int netdev_probe(struct connman_element *element)
{
	DBG("element %p name %s", element, element->name);

	create_element(element, CONNMAN_ELEMENT_TYPE_DHCP);
	create_element(element, CONNMAN_ELEMENT_TYPE_ZEROCONF);

	return 0;
}

static void netdev_remove(struct connman_element *element)
{
	DBG("element %p name %s", element, element->name);
}

static struct connman_driver netdev_driver = {
	.name		= "netdev",
	.type		= CONNMAN_ELEMENT_TYPE_DEVICE,
	.subtype	= CONNMAN_ELEMENT_SUBTYPE_NETWORK,
	.probe		= netdev_probe,
	.remove		= netdev_remove,
};

static int netdev_init(void)
{
	return connman_driver_register(&netdev_driver);
}

static void netdev_exit(void)
{
	connman_driver_unregister(&netdev_driver);
}

CONNMAN_PLUGIN_DEFINE(netdev, "Network device plugin", VERSION,
						netdev_init, netdev_exit)
