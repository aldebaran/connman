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

int connman_resolver_register(struct connman_resolver_driver *driver)
{
	DBG("driver %p", driver);

	drivers = g_slist_append(drivers, driver);

	return 0;
}

void connman_resolver_unregister(struct connman_resolver_driver *driver)
{
	DBG("driver %p", driver);

	drivers = g_slist_remove(drivers, driver);
}

int __connman_resolver_append(struct connman_iface *iface,
						const char *nameserver)
{
	struct connman_resolver_driver *driver = g_slist_nth_data(drivers, 0);

	if (driver && driver->append)
		return driver->append(iface, nameserver);

	return -1;
}

int __connman_resolver_remove(struct connman_iface *iface)
{
	struct connman_resolver_driver *driver = g_slist_nth_data(drivers, 0);

	if (driver && driver->remove)
		return driver->remove(iface);

	return -1;
}
