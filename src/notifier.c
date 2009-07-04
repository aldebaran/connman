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

static GSList *notifier_list = NULL;

static gint compare_priority(gconstpointer a, gconstpointer b)
{
	const struct connman_notifier *notifier1 = a;
	const struct connman_notifier *notifier2 = b;

	return notifier2->priority - notifier1->priority;
}

/**
 * connman_notifier_register:
 * @notifier: notifier module
 *
 * Register a new notifier module
 *
 * Returns: %0 on success
 */
int connman_notifier_register(struct connman_notifier *notifier)
{
	DBG("notifier %p name %s", notifier, notifier->name);

	notifier_list = g_slist_insert_sorted(notifier_list, notifier,
							compare_priority);

	return 0;
}

/**
 * connman_notifier_unregister:
 * @notifier: notifier module
 *
 * Remove a previously registered notifier module
 */
void connman_notifier_unregister(struct connman_notifier *notifier)
{
	DBG("notifier %p name %s", notifier, notifier->name);

	notifier_list = g_slist_remove(notifier_list, notifier);
}

static void device_enabled(enum connman_device_type type,
						connman_bool_t enabled)
{
	GSList *list;

	for (list = notifier_list; list; list = list->next) {
		struct connman_notifier *notifier = list->data;

		if (notifier->device_enabled)
			notifier->device_enabled(type, enabled);
	}

}

static volatile gint enabled[10];

void __connman_notifier_device_type_increase(enum connman_device_type type)
{
	DBG("type %d", type);

	switch (type) {
	case CONNMAN_DEVICE_TYPE_UNKNOWN:
	case CONNMAN_DEVICE_TYPE_MBM:
	case CONNMAN_DEVICE_TYPE_HSO:
	case CONNMAN_DEVICE_TYPE_NOZOMI:
	case CONNMAN_DEVICE_TYPE_HUAWEI:
	case CONNMAN_DEVICE_TYPE_NOVATEL:
	case CONNMAN_DEVICE_TYPE_VENDOR:
		return;
	case CONNMAN_DEVICE_TYPE_ETHERNET:
	case CONNMAN_DEVICE_TYPE_WIFI:
	case CONNMAN_DEVICE_TYPE_WIMAX:
	case CONNMAN_DEVICE_TYPE_BLUETOOTH:
	case CONNMAN_DEVICE_TYPE_GPS:
		if (g_atomic_int_exchange_and_add(&enabled[type], 1) == 0)
			device_enabled(type, TRUE);
		break;
	}
}

void __connman_notifier_device_type_decrease(enum connman_device_type type)
{
	DBG("type %d", type);

	switch (type) {
	case CONNMAN_DEVICE_TYPE_UNKNOWN:
	case CONNMAN_DEVICE_TYPE_MBM:
	case CONNMAN_DEVICE_TYPE_HSO:
	case CONNMAN_DEVICE_TYPE_NOZOMI:
	case CONNMAN_DEVICE_TYPE_HUAWEI:
	case CONNMAN_DEVICE_TYPE_NOVATEL:
	case CONNMAN_DEVICE_TYPE_VENDOR:
		return;
	case CONNMAN_DEVICE_TYPE_ETHERNET:
	case CONNMAN_DEVICE_TYPE_WIFI:
	case CONNMAN_DEVICE_TYPE_WIMAX:
	case CONNMAN_DEVICE_TYPE_BLUETOOTH:
	case CONNMAN_DEVICE_TYPE_GPS:
		if (g_atomic_int_dec_and_test(&enabled[type]) == TRUE)
			device_enabled(type, FALSE);
		break;
	}
}

void __connman_notifier_offline_mode(connman_bool_t enabled)
{
	GSList *list;

	DBG("enabled %d", enabled);

	for (list = notifier_list; list; list = list->next) {
		struct connman_notifier *notifier = list->data;

		if (notifier->offline_mode)
			notifier->offline_mode(enabled);
	}
}

int __connman_notifier_init(void)
{
	DBG("");

	return 0;
}

void __connman_notifier_cleanup(void)
{
	DBG("");
}
