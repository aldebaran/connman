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

struct connman_stats {
	char *interface;
	unsigned int rx_bytes;
	unsigned int tx_bytes;
};

struct connman_counter {
	char *owner;
	char *path;
	guint timeout;
	guint watch;
};

static void remove_stats(gpointer user_data)
{
	struct connman_stats *stats = user_data;

	g_free(stats->interface);
	g_free(stats);
}

static void remove_counter(gpointer user_data)
{
	struct connman_counter *counter = user_data;

	DBG("owner %s path %s", counter->owner, counter->path);

	if (counter->watch > 0)
		g_dbus_remove_watch(connection, counter->watch);

	if (counter->timeout > 0)
		g_source_remove(counter->timeout);

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

static gboolean counter_timeout(gpointer user_data)
{
	struct connman_counter *counter = user_data;

	DBG("owner %s path %s", counter->owner, counter->path);

	__connman_rtnl_request_update();

	return TRUE;
}

int __connman_counter_register(const char *owner, const char *path,
						unsigned int interval)
{
	struct connman_counter *counter;

	DBG("owner %s path %s interval %u", owner, path, interval);

	if (interval < 1)
		return -EINVAL;

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

	counter->timeout = g_timeout_add_seconds(interval,
						counter_timeout, counter);

	counter->watch = g_dbus_add_disconnect_watch(connection, owner,
					owner_disconnect, counter, NULL);

	__connman_rtnl_request_update();

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
					struct connman_stats *stats)
{
	DBusMessage *message;
	DBusMessageIter array, dict;

	message = dbus_message_new_method_call(counter->owner, counter->path,
					CONNMAN_COUNTER_INTERFACE, "Usage");
	if (message == NULL)
		return;

	dbus_message_set_no_reply(message, TRUE);

	dbus_message_iter_init_append(message, &array);

	connman_dbus_dict_open(&array, &dict);

	connman_dbus_dict_append_basic(&dict, "Interface",
					DBUS_TYPE_STRING, &stats->interface);
	connman_dbus_dict_append_basic(&dict, "RX.Bytes",
					DBUS_TYPE_UINT32, &stats->rx_bytes);
	connman_dbus_dict_append_basic(&dict, "TX.Bytes",
					DBUS_TYPE_UINT32, &stats->tx_bytes);

	connman_dbus_dict_close(&array, &dict);

	g_dbus_send_message(connection, message);
}

void __connman_counter_notify(const char *interface,
				unsigned int rx_bytes, unsigned int tx_bytes)
{
	struct connman_stats *stats;
	GHashTableIter iter;
	gpointer key, value;

	stats = g_hash_table_lookup(stats_table, interface);
	if (stats != NULL)
		goto update;

	stats = g_try_new0(struct connman_stats, 1);
	if (stats == NULL)
		return;

	stats->interface = g_strdup(interface);

	g_hash_table_replace(stats_table, stats->interface, stats);

update:
	if (stats->rx_bytes == rx_bytes && stats->tx_bytes == tx_bytes)
		return;

	stats->rx_bytes = rx_bytes;
	stats->tx_bytes = tx_bytes;

	g_hash_table_iter_init(&iter, counter_table);

	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		struct connman_counter *counter = value;

		send_usage(counter, stats);
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

int __connman_counter_init(void)
{
	DBG("");

	connection = connman_dbus_get_connection();
	if (connection == NULL)
		return -1;

	stats_table = g_hash_table_new_full(g_str_hash, g_str_equal,
							NULL, remove_stats);

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
