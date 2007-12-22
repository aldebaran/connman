/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007  Intel Corporation. All rights reserved.
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

#include <connman/plugin.h>
#include <connman/iface.h>

#include "net.h"

static int iface_probe(struct connman_iface *iface)
{
	char *ifname;

	ifname = __net_ifname(iface->sysfs);
	if (ifname == NULL)
		return -1;

	printf("[802.03] probe interface %s\n", ifname);

	iface->type = CONNMAN_IFACE_TYPE_80203;

	iface->flags = CONNMAN_IFACE_FLAGS_CARRIER_DETECT |
						CONNMAN_IFACE_FLAGS_IPV4;

	__net_free(ifname);

	return 0;
}

static void iface_remove(struct connman_iface *iface)
{
	char *ifname;

	ifname = __net_ifname(iface->sysfs);
	if (ifname == NULL)
		return;

	printf("[802.03] remove interface %s\n", ifname);

	__net_free(ifname);
}

static struct connman_iface_driver iface_driver = {
	.name		= "80203",
	.capability	= "net.80203",
	.probe		= iface_probe,
	.remove		= iface_remove,
};

static int plugin_init(void)
{
	connman_iface_register(&iface_driver);

	return 0;
}

static void plugin_exit(void)
{
	connman_iface_unregister(&iface_driver);
}

CONNMAN_PLUGIN_DEFINE("80203", "IEEE 802.03 interface plugin", VERSION,
						plugin_init, plugin_exit)
