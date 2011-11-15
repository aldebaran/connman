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
static GHashTable *service_hash = NULL;

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

static void state_changed(connman_bool_t connected)
{
	unsigned int count = __connman_notifier_count_connected();
	char *state = "offline";
	DBusMessage *signal;

	if (count > 1)
		return;

	if (count == 1) {
		if (connected == FALSE)
			return;

		state = "online";
	}

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

	state_changed(connected);
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

	if (g_atomic_int_get(&registered[type]) == 0) {
		connman_error("notifier unregister underflow");
		return;
	}

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

	if (g_atomic_int_get(&enabled[type]) == 0) {
		connman_error("notifier disable underflow");
		return;
	}

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

	if (g_atomic_int_get(&connected[type]) == 0) {
		connman_error("notifier disconnect underflow");
		return;
	}

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

void __connman_notifier_service_add(struct connman_service *service,
					const char *name)
{
	GSList *list;

	for (list = notifier_list; list; list = list->next) {
		struct connman_notifier *notifier = list->data;

		if (notifier->service_add)
			notifier->service_add(service, name);
	}
}

void __connman_notifier_service_remove(struct connman_service *service)
{
	GSList *list;

	if (g_hash_table_lookup(service_hash, service) != NULL) {
		/*
		 * This is a tempory check for consistency. It can be
		 * removed when there are no reports for the following
		 * error message.
		 */
		connman_error("Service state machine inconsistency detected.");

		g_hash_table_remove(service_hash, service);
	}

	for (list = notifier_list; list; list = list->next) {
		struct connman_notifier *notifier = list->data;

		if (notifier->service_remove)
			notifier->service_remove(service);
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

static void notify_idle_state(connman_bool_t idle)
{
	GSList *list;

	DBG("idle %d", idle);

	for (list = notifier_list; list; list = list->next) {
		struct connman_notifier *notifier = list->data;

		if (notifier->idle_state)
			notifier->idle_state(idle);
	}
}

void __connman_notifier_service_state_changed(struct connman_service *service,
					enum connman_service_state state)
{
	GSList *list;
	unsigned int old_size;
	connman_bool_t found;

	for (list = notifier_list; list; list = list->next) {
		struct connman_notifier *notifier = list->data;

		if (notifier->service_state_changed)
			notifier->service_state_changed(service, state);
	}

	old_size = g_hash_table_size(service_hash);
	found = g_hash_table_lookup(service_hash, service) != NULL;

	switch (state) {
	case CONNMAN_SERVICE_STATE_UNKNOWN:
	case CONNMAN_SERVICE_STATE_FAILURE:
	case CONNMAN_SERVICE_STATE_DISCONNECT:
	case CONNMAN_SERVICE_STATE_IDLE:
		if (found == FALSE)
			break;

		g_hash_table_remove(service_hash, service);
		if (old_size == 1)
			notify_idle_state(TRUE);

		break;
	case CONNMAN_SERVICE_STATE_ASSOCIATION:
	case CONNMAN_SERVICE_STATE_CONFIGURATION:
	case CONNMAN_SERVICE_STATE_READY:
	case CONNMAN_SERVICE_STATE_ONLINE:
		if (found == TRUE)
			break;

		g_hash_table_insert(service_hash, service, service);
		if (old_size == 0)
			notify_idle_state(FALSE);

		break;
	}
}

void __connman_notifier_ipconfig_changed(struct connman_service *service,
					struct connman_ipconfig *ipconfig)
{
	GSList *list;

	for (list = notifier_list; list; list = list->next) {
		struct connman_notifier *notifier = list->data;

		if (notifier->ipconfig_changed)
			notifier->ipconfig_changed(service, ipconfig);
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

	service_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal,
						NULL, NULL);


	return 0;
}

void __connman_notifier_cleanup(void)
{
	DBG("");

	g_hash_table_destroy(service_hash);
	service_hash = NULL;

	dbus_connection_unref(connection);
}
