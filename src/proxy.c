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

static unsigned int next_lookup_token = 1;

static GSList *driver_list = NULL;

struct proxy_lookup {
	unsigned int token;
	connman_proxy_lookup_cb cb;
	void *user_data;
	guint watch;
};

static gboolean lookup_callback(gpointer user_data)
{
	struct proxy_lookup *lookup = user_data;

	lookup->watch = 0;

	if (lookup->cb)
		lookup->cb(NULL, lookup->user_data);

	g_free(lookup);

	return FALSE;
}

unsigned int connman_proxy_lookup(const char *interface, const char *url,
				connman_proxy_lookup_cb cb, void *user_data)
{
	struct proxy_lookup *lookup;

	DBG("interface %s url %s", interface, url);

	if (interface == NULL)
		return 0;

	lookup = g_try_new0(struct proxy_lookup, 1);
	if (lookup == NULL)
		return 0;

	lookup->token = next_lookup_token++;

	lookup->cb = cb;
	lookup->user_data = user_data;

	lookup->watch = g_timeout_add_seconds(0, lookup_callback, lookup);
	if (lookup->watch == 0) {
		g_free(lookup);
		return 0;
	}

	DBG("token %u", lookup->token);

	return lookup->token;
}

void connman_proxy_lookup_cancel(unsigned int token)
{
	DBG("token %u", token);
}

void connman_proxy_driver_lookup_notify(struct connman_service *service,
                                        const char *url, const char *result)
{
	DBG("service %p url %s result %s", service, url, result);

	if (service == NULL)
		return;
}

static gint compare_priority(gconstpointer a, gconstpointer b)
{
	const struct connman_proxy_driver *driver1 = a;
	const struct connman_proxy_driver *driver2 = b;

	return driver2->priority - driver1->priority;
}

/**
 * connman_proxy_driver_register:
 * @driver: Proxy driver definition
 *
 * Register a new proxy driver
 *
 * Returns: %0 on success
 */
int connman_proxy_driver_register(struct connman_proxy_driver *driver)
{
	DBG("driver %p name %s", driver, driver->name);

	driver_list = g_slist_insert_sorted(driver_list, driver,
							compare_priority);

	return 0;
}

/**
 * connman_proxy_driver_unregister:
 * @driver: Proxy driver definition
 *
 * Remove a previously registered proxy driver
 */
void connman_proxy_driver_unregister(struct connman_proxy_driver *driver)
{
	DBG("driver %p name %s", driver, driver->name);

	driver_list = g_slist_remove(driver_list, driver);
}

int __connman_proxy_init(void)
{
	DBG("");

	return 0;
}

void __connman_proxy_cleanup(void)
{
	DBG("");
}
