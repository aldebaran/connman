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
#include <errno.h>
#include <sys/stat.h>

#include <connman/plugin.h>
#include <connman/iface.h>
#include <connman/log.h>

static int ethernet_probe(struct connman_iface *iface)
{
	char sysfs_path[PATH_MAX];
	struct stat st;

	DBG("iface %p", iface);

	snprintf(sysfs_path, PATH_MAX, "%s/bridge", iface->sysfs);

	if (stat(sysfs_path, &st) == 0 && (st.st_mode & S_IFDIR))
		return -ENODEV;

	iface->type = CONNMAN_IFACE_TYPE_80203;

	iface->flags = CONNMAN_IFACE_FLAG_RTNL |
				CONNMAN_IFACE_FLAG_IPV4;

	return 0;
}

static void ethernet_remove(struct connman_iface *iface)
{
	DBG("iface %p", iface);
}

static struct connman_iface_driver ethernet_driver = {
	.name		= "80203",
	.capability	= "net.80203",
	.probe		= ethernet_probe,
	.remove		= ethernet_remove,
};

static int ethernet_init(void)
{
	return connman_iface_register(&ethernet_driver);
}

static void ethernet_exit(void)
{
	connman_iface_unregister(&ethernet_driver);
}

CONNMAN_PLUGIN_DEFINE("80203", "IEEE 802.03 interface plugin", VERSION,
						ethernet_init, ethernet_exit)
