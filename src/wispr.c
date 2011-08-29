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

#include <errno.h>

#include "connman.h"

struct connman_wispr_portal_context {
	struct connman_service *service;
	enum connman_ipconfig_type type;
};

struct connman_wispr_portal {
	struct connman_wispr_portal_context *ipv4_context;
	struct connman_wispr_portal_context *ipv6_context;
};

static GHashTable *wispr_portal_list = NULL;

static void free_connman_wispr_portal_context(struct connman_wispr_portal_context *wp_context)
{
	DBG("");

	if (wp_context == NULL)
		return;

	g_free(wp_context);
}

static void free_connman_wispr_portal(gpointer data)
{
	struct connman_wispr_portal *wispr_portal = data;

	DBG("");

	if (wispr_portal == NULL)
		return;

	free_connman_wispr_portal_context(wispr_portal->ipv4_context);
	free_connman_wispr_portal_context(wispr_portal->ipv6_context);

	g_free(wispr_portal);
}

int __connman_wispr_start(struct connman_service *service,
					enum connman_ipconfig_type type)
{
	struct connman_wispr_portal_context *wp_context = NULL;
	struct connman_wispr_portal *wispr_portal = NULL;
	int index;

	DBG("service %p", service);

	if (wispr_portal_list == NULL)
		return -EINVAL;

	index = __connman_service_get_index(service);
	if (index < 0)
		return -EINVAL;

	wispr_portal = g_hash_table_lookup(wispr_portal_list,
					GINT_TO_POINTER(index));
	if (wispr_portal == NULL) {
		wispr_portal = g_try_new0(struct connman_wispr_portal, 1);
		if (wispr_portal == NULL)
			return -ENOMEM;

		g_hash_table_replace(wispr_portal_list,
					GINT_TO_POINTER(index), wispr_portal);
	}

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		wp_context = wispr_portal->ipv4_context;
	else if (type == CONNMAN_IPCONFIG_TYPE_IPV6)
		wp_context = wispr_portal->ipv6_context;
	else
		return -EINVAL;

	if (wp_context == NULL) {
		wp_context = g_try_new0(struct connman_wispr_portal_context, 1);
		if (wp_context == NULL)
			return -ENOMEM;

		wp_context->service = service;
		wp_context->type = type;

		if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
			wispr_portal->ipv4_context = wp_context;
		else
			wispr_portal->ipv6_context = wp_context;
	}

	return 0;
}

void __connman_wispr_stop(struct connman_service *service)
{
	int index;

	DBG("service %p", service);

	if (wispr_portal_list == NULL)
		return;

	index = __connman_service_get_index(service);
	if (index < 0)
		return;

	g_hash_table_remove(wispr_portal_list, GINT_TO_POINTER(index));
}

int __connman_wispr_init(void)
{
	DBG("");

	wispr_portal_list = g_hash_table_new_full(g_direct_hash,
						g_direct_equal, NULL,
						free_connman_wispr_portal);

	return 0;
}

void __connman_wispr_cleanup(void)
{
	DBG("");

	g_hash_table_destroy(wispr_portal_list);
	wispr_portal_list = NULL;
}
