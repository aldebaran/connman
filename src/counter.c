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

static DBusConnection *connection;

static GHashTable *stats_table;
static GHashTable *counter_table;
static GHashTable *owner_mapping;

struct connman_counter {
	char *owner;
	char *path;
	unsigned int interval;
	guint watch;
};

static void remove_counter(gpointer user_data)
{
	struct connman_counter *counter = user_data;

	DBG("owner %s path %s", counter->owner, counter->path);

	if (counter->watch > 0)
		g_dbus_remove_watch(connection, counter->watch);

	__connman_rtnl_update_interval_remove(counter->interval);

	g_free(counter->owner);
	g_free(counter->path);
	g_free(counter);
}

static void owner_disconnect(DBusConnection *connection, void *user_data)
{
	struct connman_counter *counter = user_data;

	DBG("owner %s path %s", counter->owner, counter->path);

	g_hash_table_remove(owner_mapping, counter->owner);
	g_hash_table_remove(counter_table, counter->path);
}

int __connman_counter_register(const char *owner, const char *path,
						unsigned int interval)
{
	struct connman_counter *counter;

	DBG("owner %s path %s interval %u", owner, path, interval);

	counter = g_hash_table_lookup(counter_table, path);
	if (counter != NULL)
		return -EEXIST;

	counter = g_try_new0(struct connman_counter, 1);
	if (counter == NULL)
		return -ENOMEM;

	counter->owner = g_strdup(owner);
	counter->path = g_strdup(path);

	g_hash_table_replace(counter_table, counter->path, counter);
	g_hash_table_replace(owner_mapping, counter->owner, counter);

	counter->interval = interval;
	__connman_rtnl_update_interval_add(counter->interval);

	counter->watch = g_dbus_add_disconnect_watch(connection, owner,
					owner_disconnect, counter, NULL);

	return 0;
}

int __connman_counter_unregister(const char *owner, const char *path)
{
	struct connman_counter *counter;

	DBG("owner %s path %s", owner, path);

	counter = g_hash_table_lookup(counter_table, path);
	if (counter == NULL)
		return -ESRCH;

	if (g_strcmp0(owner, counter->owner) != 0)
		return -EACCES;

	g_hash_table_remove(owner_mapping, counter->owner);
	g_hash_table_remove(counter_table, counter->path);

	return 0;
}

static void send_usage(struct connman_counter *counter,
				struct connman_service *service)
{
	DBusMessage *message;
	DBusMessageIter array, dict;
	const char *service_path;
	unsigned long rx_bytes;
	unsigned long tx_bytes;
	unsigned long time;

	message = dbus_message_new_method_call(counter->owner, counter->path,
					CONNMAN_COUNTER_INTERFACE, "Usage");
	if (message == NULL)
		return;

	dbus_message_set_no_reply(message, TRUE);

	service_path = __connman_service_get_path(service);
	dbus_message_append_args(message, DBUS_TYPE_OBJECT_PATH,
					&service_path, DBUS_TYPE_INVALID);

	dbus_message_iter_init_append(message, &array);

	connman_dbus_dict_open(&array, &dict);

	rx_bytes = __connman_service_stats_get_rx_bytes(service);
	tx_bytes = __connman_service_stats_get_tx_bytes(service);
	time = __connman_service_stats_get_time(service);

	connman_dbus_dict_append_basic(&dict, "RX.Bytes", DBUS_TYPE_UINT32,
				&rx_bytes);
	connman_dbus_dict_append_basic(&dict, "TX.Bytes", DBUS_TYPE_UINT32,
				&tx_bytes);
	connman_dbus_dict_append_basic(&dict, "Time", DBUS_TYPE_UINT32,
				&time);

	connman_dbus_dict_close(&array, &dict);

	g_dbus_send_message(connection, message);
}

void __connman_counter_notify(struct connman_ipconfig *config,
				unsigned int rx_bytes, unsigned int tx_bytes)
{
	struct connman_service *service;
	GHashTableIter iter;
	gpointer key, value;

	service = g_hash_table_lookup(stats_table, config);
	if (service == NULL)
		return;

	__connman_service_stats_update(service, rx_bytes, tx_bytes);

	g_hash_table_iter_init(&iter, counter_table);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		struct connman_counter *counter = value;

		send_usage(counter, service);
	}
}

static void release_counter(gpointer key, gpointer value, gpointer user_data)
{
	struct connman_counter *counter = value;
	DBusMessage *message;

	DBG("owner %s path %s", counter->owner, counter->path);

	message = dbus_message_new_method_call(counter->owner, counter->path,
					CONNMAN_COUNTER_INTERFACE, "Release");
	if (message == NULL)
		return;

	dbus_message_set_no_reply(message, TRUE);

	g_dbus_send_message(connection, message);
}

int __connman_counter_add_service(struct connman_service *service)
{
	struct connman_ipconfig *config;

	config = __connman_service_get_ipconfig(service);
	g_hash_table_replace(stats_table, config, service);

	return 0;
}

void __connman_counter_remove_service(struct connman_service *service)
{
	struct connman_ipconfig *config;

	config = __connman_service_get_ipconfig(service);
	g_hash_table_remove(stats_table, config);
}

int __connman_counter_init(void)
{
	DBG("");

	connection = connman_dbus_get_connection();
	if (connection == NULL)
		return -1;

	stats_table = g_hash_table_new_full(g_direct_hash, g_str_equal,
							NULL, NULL);

	counter_table = g_hash_table_new_full(g_str_hash, g_str_equal,
							NULL, remove_counter);
	owner_mapping = g_hash_table_new_full(g_str_hash, g_str_equal,
								NULL, NULL);

	return 0;
}

void __connman_counter_cleanup(void)
{
	DBG("");

	if (connection == NULL)
		return;

	g_hash_table_foreach(counter_table, release_counter, NULL);

	g_hash_table_destroy(owner_mapping);
	g_hash_table_destroy(counter_table);

	g_hash_table_destroy(stats_table);

	dbus_connection_unref(connection);
}
