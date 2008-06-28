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

static int ipv4_probe(struct connman_element *element)
{
	DBG("element %p name %s", element, element->name);

	DBG("address %s", element->ipv4.address);
	DBG("netmask %s", element->ipv4.netmask);
	DBG("gateway %s", element->ipv4.gateway);

	return 0;
}

static void ipv4_remove(struct connman_element *element)
{
	DBG("element %p name %s", element, element->name);
}

static struct connman_driver ipv4_driver = {
	.name		= "ipv4",
	.type		= CONNMAN_ELEMENT_TYPE_IPV4,
	.probe		= ipv4_probe,
	.remove		= ipv4_remove,
};

static int ipv4_init(void)
{
	return connman_driver_register(&ipv4_driver);
}

static void ipv4_exit(void)
{
	connman_driver_unregister(&ipv4_driver);
}

CONNMAN_PLUGIN_DEFINE("ipv4", "IPv4 configuration plugin", VERSION,
							ipv4_init, ipv4_exit)
