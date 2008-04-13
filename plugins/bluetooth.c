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
#include <connman/iface.h>
#include <connman/log.h>

static int bluetooth_probe(struct connman_iface *iface)
{
	DBG("iface %p", iface);

	iface->type = CONNMAN_IFACE_TYPE_BLUETOOTH;

	iface->flags = CONNMAN_IFACE_FLAG_RTNL |
				CONNMAN_IFACE_FLAG_IPV4;

	return 0;
}

static void bluetooth_remove(struct connman_iface *iface)
{
	DBG("iface %p", iface);
}

static struct connman_iface_driver bluetooth_driver = {
	.name		= "bluetooth",
	.capability	= "bluetooth_hci",
	.probe		= bluetooth_probe,
	.remove		= bluetooth_remove,
};

static int bluetooth_init(void)
{
	return connman_iface_register(&bluetooth_driver);
}

static void bluetooth_exit(void)
{
	connman_iface_unregister(&bluetooth_driver);
}

CONNMAN_PLUGIN_DEFINE("bluetooth", "Bluetooth interface plugin", VERSION,
						bluetooth_init, bluetooth_exit)
