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

#include <glib.h>

#include "connman.h"

struct connman_task {
	char *path;
	pid_t pid;
};

static GHashTable *task_hash = NULL;

static volatile gint task_counter;

static void free_task(gpointer data)
{
	struct connman_task *task = data;

	DBG("task %p", task);

	g_free(task->path);
	g_free(task);
}

struct connman_task *connman_task_create(void)
{
	struct connman_task *task;
	gint counter;

	DBG("");

	task = g_try_new0(struct connman_task, 1);
	if (task == NULL)
		return NULL;

	counter = g_atomic_int_exchange_and_add(&task_counter, 1);

	task->path = g_strdup_printf("/task/%d", counter);
	task->pid = -1;

	DBG("task %p", task);

	g_hash_table_insert(task_hash, task->path, task);

	return task;
}

void connman_task_destroy(struct connman_task *task)
{
	DBG("task %p", task);

	g_hash_table_remove(task_hash, task->path);
}

static DBusHandlerResult task_filter(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct connman_task *task;
	const char *path;

	if (dbus_message_get_type(message) != DBUS_MESSAGE_TYPE_METHOD_CALL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (dbus_message_has_interface(message,
					CONNMAN_TASK_INTERFACE) == FALSE)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	path = dbus_message_get_path(message);
	if (path == NULL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	task = g_hash_table_lookup(task_hash, path);
	if (task == NULL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	return DBUS_HANDLER_RESULT_HANDLED;
}

static const char *task_rule = "type=method_call"
					",interface=" CONNMAN_TASK_INTERFACE;

static DBusConnection *connection;

int __connman_task_init(void)
{
	DBG("");

	connection = connman_dbus_get_connection();

	dbus_connection_add_filter(connection, task_filter, NULL, NULL);

	g_atomic_int_set(&task_counter, 0);

	task_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
							NULL, free_task);

	dbus_bus_add_match(connection, task_rule, NULL);
	dbus_connection_flush(connection);

	return 0;
}

void __connman_task_cleanup(void)
{
	DBG("");

	dbus_bus_remove_match(connection, task_rule, NULL);
	dbus_connection_flush(connection);

	g_hash_table_destroy(task_hash);
	task_hash = NULL;

	dbus_connection_remove_filter(connection, task_filter, NULL);

	dbus_connection_unref(connection);
}
