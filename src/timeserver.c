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
static GHashTable *server_hash = NULL;

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
	GSList *list;

	DBG("server %s", server);

	if (server == NULL)
		return -EINVAL;

	/* This server is already handled by a driver */
	if (g_hash_table_lookup(server_hash, server))
		return 0;

	for (list = driver_list; list; list = list->next) {
		struct connman_timeserver_driver *driver = list->data;
		char *new_server;

		if (driver->append == NULL)
			continue;

		new_server = g_strdup(server);
		if (new_server == NULL)
			return -ENOMEM;

		if (driver->append(server) == 0) {
			g_hash_table_insert(server_hash, new_server, driver);
			return 0;
		}
	}

	return -ENOENT;
}

/**
 * connman_timeserver_remove:
 * @server: server address
 *
 * Remover time server server address from current list
 */
int connman_timeserver_remove(const char *server)
{
	struct connman_timeserver_driver *driver;

	DBG("server %s", server);

	if (server == NULL)
		return -EINVAL;

	driver = g_hash_table_lookup(server_hash, server);
	if (driver == NULL)
		return -EINVAL;

	g_hash_table_remove(server_hash, server);

	if (driver->remove == NULL)
		return -ENOENT;

	return driver->remove(server);
}

void connman_timeserver_sync(void)
{
	GSList *list;

	DBG("");

	for (list = driver_list; list; list = list->next) {
		struct connman_timeserver_driver *driver = list->data;

		if (driver->sync == NULL)
			continue;

		driver->sync();
	}
}

int __connman_timeserver_init(void)
{
	DBG("");

	server_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						g_free, NULL);

	return 0;
}

void __connman_timeserver_cleanup(void)
{
	DBG("");

	g_hash_table_destroy(server_hash);
}
