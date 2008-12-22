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

static int udhcp_probe(struct connman_element *element)
{
	DBG("element %p name %s", element, element->name);

	return -ENODEV;
}

static void udhcp_remove(struct connman_element *element)
{
	DBG("element %p name %s", element, element->name);
}

static struct connman_driver udhcp_driver = {
	.name		= "udhcp",
	.type		= CONNMAN_ELEMENT_TYPE_DHCP,
	.priority	= CONNMAN_DRIVER_PRIORITY_HIGH,
	.probe		= udhcp_probe,
	.remove		= udhcp_remove,
};

static int udhcp_init(void)
{
	return connman_driver_register(&udhcp_driver);
}

static void udhcp_exit(void)
{
	connman_driver_unregister(&udhcp_driver);
}

CONNMAN_PLUGIN_DEFINE(dhclient, "uDHCP client plugin", VERSION,
						udhcp_init, udhcp_exit)
