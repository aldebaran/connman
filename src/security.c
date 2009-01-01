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

static GSList *security_list = NULL;

static gint compare_priority(gconstpointer a, gconstpointer b)
{
	const struct connman_security *security1 = a;
	const struct connman_security *security2 = b;

	return security2->priority - security1->priority;
}

/**
 * connman_security_register:
 * @security: security module
 *
 * Register a new security module
 *
 * Returns: %0 on success
 */
int connman_security_register(struct connman_security *security)
{
	DBG("security %p name %s", security, security->name);

	security_list = g_slist_insert_sorted(security_list, security,
							compare_priority);

	return 0;
}

/**
 * connman_security_unregister:
 * @security: security module
 *
 * Remove a previously registered security module
 */
void connman_security_unregister(struct connman_security *security)
{
	DBG("security %p name %s", security, security->name);

	security_list = g_slist_remove(security_list, security);
}

int __connman_security_check_privileges(DBusMessage *message)
{
	GSList *list;
	const char *sender;
	int err = 0;

	DBG("message %p", message);

	sender = dbus_message_get_sender(message);

	for (list = security_list; list; list = list->next) {
		struct connman_security *security = list->data;

		DBG("%s", security->name);

		if (security->authorize_sender) {
			err = security->authorize_sender(sender);
			break;
		}
	}

	return err;
}
