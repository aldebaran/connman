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

#include <glib.h>

#include "connman.h"

static GSList *drivers = NULL;

int connman_dhcp_register(struct connman_dhcp_driver *driver)
{
	DBG("driver %p", driver);

	drivers = g_slist_append(drivers, driver);

	return 0;
}

void connman_dhcp_unregister(struct connman_dhcp_driver *driver)
{
	DBG("driver %p", driver);

	drivers = g_slist_remove(drivers, driver);
}

int __connman_dhcp_request(struct connman_iface *iface)
{
	struct connman_dhcp_driver *driver = g_slist_nth_data(drivers, 0);

	if (driver && driver->request)
		return driver->request(iface);

	return -1;
}

int __connman_dhcp_release(struct connman_iface *iface)
{
	struct connman_dhcp_driver *driver = g_slist_nth_data(drivers, 0);

	if (driver && driver->release)
		return driver->release(iface);

	return -1;
}
