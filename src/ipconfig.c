/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2009  Intel Corporation. All rights reserved.
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

#include "connman.h"

static GSList *ipconfig_list = NULL;

static gint compare_priority(gconstpointer a, gconstpointer b)
{
	const struct connman_ipconfig *ipconfig1 = a;
	const struct connman_ipconfig *ipconfig2 = b;

	return ipconfig2->priority - ipconfig1->priority;
}

/**
 * connman_ipconfig_register:
 * @ipconfig: IP configuration module
 *
 * Register a new IP configuration module
 *
 * Returns: %0 on success
 */
int connman_ipconfig_register(struct connman_ipconfig *ipconfig)
{
	DBG("ipconfig %p name %s", ipconfig, ipconfig->name);

	ipconfig_list = g_slist_insert_sorted(ipconfig_list, ipconfig,
							compare_priority);

	return 0;
}

/**
 * connman_ipconfig_unregister:
 * @ipconfig: IP configuration module
 *
 * Remove a previously registered IP configuration module.
 */
void connman_ipconfig_unregister(struct connman_ipconfig *ipconfig)
{
	DBG("ipconfig %p name %s", ipconfig, ipconfig->name);

	ipconfig_list = g_slist_remove(ipconfig_list, ipconfig);
}
