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

#include <connman/service.h>
#include <connman/ondemand.h>
#include <connman/notifier.h>
#include <connman/log.h>

#include "connman.h"

static volatile gint started;
static gboolean connected;
struct connman_service *ondemand_service;

static void ondemand_default_changed(struct connman_service *service)
{
	DBG("service %p", service);

	if (service == NULL) {
		connected = FALSE;
		return;
	}

	connected = TRUE;
}

static struct connman_notifier ondemand_notifier = {
	.name			= "ondemand",
	.default_changed	= ondemand_default_changed,
};

gboolean connman_ondemand_connected(void)
{
	DBG("connected %d", connected);

	return TRUE;
//	return connected;
}

int connman_ondemand_start(const char *bearer, unsigned int idle_timeout)
{
	DBG("");

	if (g_atomic_int_get(&started) > 0)
		return 0;

	g_atomic_int_inc(&started);

	ondemand_service = __connman_session_request(bearer, "__ondemand__");
	if (ondemand_service == NULL)
		g_atomic_int_set(&started, 0);

	/* TODO:
	 * 1) Set IDLETIMER target.
	 * 2) Listen for the sysfs/netlink event.
	 * 3) Stop the session.
	 */

	return 0;
}

int __connman_ondemand_init(void)
{
	DBG("");

	return connman_notifier_register(&ondemand_notifier);
}

void __connman_ondemand_cleanup(void)
{
	DBG("");

	connman_notifier_unregister(&ondemand_notifier);
}
