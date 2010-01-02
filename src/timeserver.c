/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2010  Intel Corporation. All rights reserved.
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

static GSList *driver_list = NULL;

static gint compare_priority(gconstpointer a, gconstpointer b)
{
	const struct connman_timeserver_driver *driver1 = a;
	const struct connman_timeserver_driver *driver2 = b;

	return driver2->priority - driver1->priority;
}

/**
 * connman_timeserver_driver_register:
 * @driver: timeserver driver definition
 *
 * Register a new timeserver driver
 *
 * Returns: %0 on success
 */
int connman_timeserver_driver_register(struct connman_timeserver_driver *driver)
{
	DBG("driver %p name %s", driver, driver->name);

	driver_list = g_slist_insert_sorted(driver_list, driver,
							compare_priority);

	return 0;
}

/**
 * connman_timeserver_driver_unregister:
 * @driver: timeserver driver definition
 *
 * Remove a previously registered timeserver driver
 */
void connman_timeserver_driver_unregister(struct connman_timeserver_driver *driver)
{
	DBG("driver %p name %s", driver, driver->name);

	driver_list = g_slist_remove(driver_list, driver);
}

/**
 * connman_timeserver_append:
 * @server: server address
 *
 * Append time server server address to current list
 */
int connman_timeserver_append(const char *server)
{
	DBG("server %s", server);

	if (server == NULL)
		return -EINVAL;

	connman_info("Adding time server %s", server);

	return 0;
}

/**
 * connman_timeserver_remove:
 * @server: server address
 *
 * Remover time server server address from current list
 */
int connman_timeserver_remove(const char *server)
{
	DBG("server %s", server);

	if (server == NULL)
		return -EINVAL;

	connman_info("Removing time server %s", server);

	return 0;
}
