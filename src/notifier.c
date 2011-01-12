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

#include <gdbus.h>

#include "connman.h"

static DBusConnection *connection = NULL;

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

#define MAX_TECHNOLOGIES 10

static volatile gint registered[MAX_TECHNOLOGIES];
static volatile gint enabled[MAX_TECHNOLOGIES];
static volatile gint connected[MAX_TECHNOLOGIES];

void __connman_notifier_list_registered(DBusMessageIter *iter, void *user_data)
{
	int i;

	for (i = 0; i < MAX_TECHNOLOGIES; i++) {
		const char *type = __connman_service_type2string(i);

		if (type == NULL)
			continue;

		if (g_atomic_int_get(&registered[i]) > 0)
			dbus_message_iter_append_basic(iter,
						DBUS_TYPE_STRING, &type);
	}
}

void __connman_notifier_list_enabled(DBusMessageIter *iter, void *user_data)
{
	int i;

	for (i = 0; i < MAX_TECHNOLOGIES; i++) {
		const char *type = __connman_service_type2string(i);

		if (type == NULL)
			continue;

		if (g_atomic_int_get(&enabled[i]) > 0)
			dbus_message_iter_append_basic(iter,
						DBUS_TYPE_STRING, &type);
	}
}

void __connman_notifier_list_connected(DBusMessageIter *iter, void *user_data)
{
	int i;

	for (i = 0; i < MAX_TECHNOLOGIES; i++) {
		const char *type = __connman_service_type2string(i);

		if (type == NULL)
			continue;

		if (g_atomic_int_get(&connected[i]) > 0)
			dbus_message_iter_append_basic(iter,
						DBUS_TYPE_STRING, &type);
	}
}

static void technology_registered(enum connman_service_type type,
						connman_bool_t registered)
{
	DBG("type %d registered %d", type, registered);

	connman_dbus_property_changed_array(CONNMAN_MANAGER_PATH,
		CONNMAN_MANAGER_INTERFACE, "AvailableTechnologies",
		DBUS_TYPE_STRING, __connman_notifier_list_registered, NULL);
}

static void technology_enabled(enum connman_service_type type,
						connman_bool_t enabled)
{
	GSList *list;

	DBG("type %d enabled %d", type, enabled);

	connman_dbus_property_changed_array(CONNMAN_MANAGER_PATH,
		CONNMAN_MANAGER_INTERFACE, "EnabledTechnologies",
		DBUS_TYPE_STRING, __connman_notifier_list_enabled, NULL);

	for (list = notifier_list; list; list = list->next) {
		struct connman_notifier *notifier = list->data;

		if (notifier->service_enabled)
			notifier->service_enabled(type, enabled);
	}
}

unsigned int __connman_notifier_count_connected(void)
{
	unsigned int i, count = 0;

	for (i = 0; i < MAX_TECHNOLOGIES; i++) {
		if (g_atomic_int_get(&connected[i]) > 0)
			count++;
	}

	return count;
}

const char *__connman_notifier_get_state(void)
{
	unsigned int count = __connman_notifier_count_connected();

	if (count > 0)
		return "online";

	return "offline";
}

static void state_changed(void)
{
	unsigned int count = __connman_notifier_count_connected();
	char *state = "offline";
	DBusMessage *signal;

	if (count > 1)
		return;

	if (count > 0)
		state = "online";

	connman_dbus_property_changed_basic(CONNMAN_MANAGER_PATH,
				CONNMAN_MANAGER_INTERFACE, "State",
						DBUS_TYPE_STRING, &state);

	signal = dbus_message_new_signal(CONNMAN_MANAGER_PATH,
				CONNMAN_MANAGER_INTERFACE, "StateChanged");
	if (signal == NULL)
		return;

	dbus_message_append_args(signal, DBUS_TYPE_STRING, &state,
							DBUS_TYPE_INVALID);

	g_dbus_send_message(connection, signal);
}

static void technology_connected(enum connman_service_type type,
						connman_bool_t connected)
{
	DBG("type %d connected %d", type, connected);

	connman_dbus_property_changed_array(CONNMAN_MANAGER_PATH,
		CONNMAN_MANAGER_INTERFACE, "ConnectedTechnologies",
		DBUS_TYPE_STRING, __connman_notifier_list_connected, NULL);

	state_changed();
}

void __connman_notifier_register(enum connman_service_type type)
{
	DBG("type %d", type);

	switch (type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_VPN:
	case CONNMAN_SERVICE_TYPE_GADGET:
		return;
	case CONNMAN_SERVICE_TYPE_ETHERNET:
	case CONNMAN_SERVICE_TYPE_WIFI:
	case CONNMAN_SERVICE_TYPE_WIMAX:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		break;
	}

	if (g_atomic_int_exchange_and_add(&registered[type], 1) == 0)
		technology_registered(type, TRUE);
}

void __connman_notifier_unregister(enum connman_service_type type)
{
	DBG("type %d", type);

	switch (type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_VPN:
	case CONNMAN_SERVICE_TYPE_GADGET:
		return;
	case CONNMAN_SERVICE_TYPE_ETHERNET:
	case CONNMAN_SERVICE_TYPE_WIFI:
	case CONNMAN_SERVICE_TYPE_WIMAX:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		break;
	}

	if (g_atomic_int_dec_and_test(&registered[type]) == TRUE)
		technology_registered(type, FALSE);
}

void __connman_notifier_enable(enum connman_service_type type)
{
	DBG("type %d", type);

	switch (type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_VPN:
	case CONNMAN_SERVICE_TYPE_GADGET:
		return;
	case CONNMAN_SERVICE_TYPE_ETHERNET:
	case CONNMAN_SERVICE_TYPE_WIFI:
	case CONNMAN_SERVICE_TYPE_WIMAX:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		break;
	}

	if (g_atomic_int_exchange_and_add(&enabled[type], 1) == 0)
		technology_enabled(type, TRUE);
}

void __connman_notifier_disable(enum connman_service_type type)
{
	DBG("type %d", type);

	switch (type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_VPN:
	case CONNMAN_SERVICE_TYPE_GADGET:
		return;
	case CONNMAN_SERVICE_TYPE_ETHERNET:
	case CONNMAN_SERVICE_TYPE_WIFI:
	case CONNMAN_SERVICE_TYPE_WIMAX:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		break;
	}

	if (g_atomic_int_dec_and_test(&enabled[type]) == TRUE)
		technology_enabled(type, FALSE);
}

void __connman_notifier_connect(enum connman_service_type type)
{
	DBG("type %d", type);

	switch (type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_VPN:
	case CONNMAN_SERVICE_TYPE_GADGET:
		return;
	case CONNMAN_SERVICE_TYPE_ETHERNET:
	case CONNMAN_SERVICE_TYPE_WIFI:
	case CONNMAN_SERVICE_TYPE_WIMAX:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		break;
	}

	if (g_atomic_int_exchange_and_add(&connected[type], 1) == 0)
		technology_connected(type, TRUE);
}

void __connman_notifier_disconnect(enum connman_service_type type)
{
	DBG("type %d", type);

	switch (type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_VPN:
	case CONNMAN_SERVICE_TYPE_GADGET:
		return;
	case CONNMAN_SERVICE_TYPE_ETHERNET:
	case CONNMAN_SERVICE_TYPE_WIFI:
	case CONNMAN_SERVICE_TYPE_WIMAX:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		break;
	}

	if (g_atomic_int_dec_and_test(&connected[type]) == TRUE)
		technology_connected(type, FALSE);
}

static void technology_default(enum connman_service_type type)
{
	const char *str;

	str = __connman_service_type2string(type);
	if (str == NULL)
		str = "";

	connman_dbus_property_changed_basic(CONNMAN_MANAGER_PATH,
			CONNMAN_MANAGER_INTERFACE, "DefaultTechnology",
						DBUS_TYPE_STRING, &str);
}

void __connman_notifier_default_changed(struct connman_service *service)
{
	enum connman_service_type type = connman_service_get_type(service);
	char *interface;
	GSList *list;

	technology_default(type);

	interface = connman_service_get_interface(service);
	__connman_tethering_update_interface(interface);
	g_free(interface);

	for (list = notifier_list; list; list = list->next) {
		struct connman_notifier *notifier = list->data;

		if (notifier->default_changed)
			notifier->default_changed(service);
	}
}

void __connman_notifier_proxy_changed(struct connman_service *service)
{
	GSList *list;

	for (list = notifier_list; list; list = list->next) {
		struct connman_notifier *notifier = list->data;

		if (notifier->proxy_changed)
			notifier->proxy_changed(service);
	}
}

static void offlinemode_changed(dbus_bool_t enabled)
{
	DBG("enabled %d", enabled);

	connman_dbus_property_changed_basic(CONNMAN_MANAGER_PATH,
				CONNMAN_MANAGER_INTERFACE, "OfflineMode",
						DBUS_TYPE_BOOLEAN, &enabled);
}

void __connman_notifier_offlinemode(connman_bool_t enabled)
{
	GSList *list;

	DBG("enabled %d", enabled);

	__connman_profile_changed(FALSE);

	offlinemode_changed(enabled);

	for (list = notifier_list; list; list = list->next) {
		struct connman_notifier *notifier = list->data;

		if (notifier->offline_mode)
			notifier->offline_mode(enabled);
	}
}

static connman_bool_t technology_supported(enum connman_service_type type)
{
	switch (type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_VPN:
	case CONNMAN_SERVICE_TYPE_GADGET:
		return FALSE;
	case CONNMAN_SERVICE_TYPE_ETHERNET:
	case CONNMAN_SERVICE_TYPE_WIFI:
	case CONNMAN_SERVICE_TYPE_WIMAX:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		break;
	}

	return TRUE;
}

connman_bool_t __connman_notifier_is_registered(enum connman_service_type type)
{
	DBG("type %d", type);

	if (technology_supported(type) == FALSE)
		return FALSE;

	if (g_atomic_int_get(&registered[type]) > 0)
		return TRUE;

	return FALSE;
}

connman_bool_t __connman_notifier_is_enabled(enum connman_service_type type)
{
	DBG("type %d", type);

	if (technology_supported(type) == FALSE)
		return FALSE;

	if (g_atomic_int_get(&enabled[type]) > 0)
		return TRUE;

	return FALSE;
}

int __connman_notifier_init(void)
{
	DBG("");

	connection = connman_dbus_get_connection();

	return 0;
}

void __connman_notifier_cleanup(void)
{
	DBG("");

	dbus_connection_unref(connection);
}
