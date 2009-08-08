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

#include <unistd.h>
#include <sys/wait.h>

#include <glib.h>

#include "connman.h"

struct notify_data {
	connman_task_notify_t func;
	void *data;
};

struct connman_task {
	char *path;
	pid_t pid;
	GPtrArray *argv;
	GPtrArray *envp;
	connman_task_exit_t exit_func;
	void *exit_data;
	GHashTable *notify;
};

static GHashTable *task_hash = NULL;

static volatile gint task_counter;

static DBusConnection *connection;

static void free_pointer(gpointer data, gpointer user_data)
{
	g_free(data);
}

static void free_task(gpointer data)
{
	struct connman_task *task = data;

	DBG("task %p", task);

	g_hash_table_destroy(task->notify);
	task->notify = NULL;

	if (task->pid > 0)
		kill(task->pid, SIGTERM);

	g_ptr_array_foreach(task->envp, free_pointer, NULL);
	g_ptr_array_free(task->envp, TRUE);

	g_ptr_array_foreach(task->argv, free_pointer, NULL);
	g_ptr_array_free(task->argv, TRUE);

	g_free(task->path);
	g_free(task);
}

/**
 * connman_task_create:
 * @program: name of executable
 *
 * Allocate a new task of given #program
 *
 * Returns: a newly-allocated #connman_task structure
 */
struct connman_task *connman_task_create(const char *program)
{
	struct connman_task *task;
	gint counter;
	char *str;

	DBG("");

	task = g_try_new0(struct connman_task, 1);
	if (task == NULL)
		return NULL;

	counter = g_atomic_int_exchange_and_add(&task_counter, 1);

	task->path = g_strdup_printf("/task/%d", counter);
	task->pid = -1;

	task->argv = g_ptr_array_new();
	task->envp = g_ptr_array_new();

	str = g_strdup(program);
	g_ptr_array_add(task->argv, str);

	task->notify = g_hash_table_new_full(g_str_hash, g_str_equal,
							g_free, g_free);

	DBG("task %p", task);

	g_hash_table_insert(task_hash, task->path, task);

	return task;
}

/**
 * connman_task_destory:
 * @task: task structure
 *
 * Remove and destory #task
 */
void connman_task_destroy(struct connman_task *task)
{
	DBG("task %p", task);

	g_hash_table_remove(task_hash, task->path);
}

/**
 * connman_task_add_argument:
 * @task: task structure
 * @argument: argument name
 * @value: optional argument value
 *
 * Add a new command line argument
 */
int connman_task_add_argument(struct connman_task *task,
				const char *argument, const char *value)
{
	char *str;

	DBG("task %p arg %s val %s", task, argument, value);

	if (argument == NULL)
		return -EINVAL;

	str = g_strdup(argument);
	g_ptr_array_add(task->argv, str);

	if (value != NULL) {
		str = g_strdup(value);
		g_ptr_array_add(task->argv, str);
	}

	return 0;
}

/**
 * connman_task_add_variable:
 * @task: task structure
 * @key: variable name
 * @value: optional variable value
 *
 * Add a new environment variable
 */
int connman_task_add_variable(struct connman_task *task,
				const char *key, const char *value)
{
	char *str;

	DBG("task %p key %s val %s", task, key, value);

	if (key == NULL)
		return -EINVAL;

	str = g_strdup_printf("%s=%s", key, value ? value : "");
	g_ptr_array_add(task->envp, str);

	return 0;
}

/**
 * connman_task_set_notify:
 * @task: task structure
 * @member: notifcation method name
 * @function: notification callback
 * @user_data: optional notification user data
 *
 * Set notification handler for #member
 */
int connman_task_set_notify(struct connman_task *task, const char *member,
			connman_task_notify_t function, void *user_data)
{
	struct notify_data *notify;

	DBG("task %p", task);

	notify = g_try_new0(struct notify_data, 1);
	if (notify == NULL)
		return -ENOMEM;

	notify->func = function;
	notify->data = user_data;

	g_hash_table_insert(task->notify, g_strdup(member), notify);

	return 0;
}

static void task_died(GPid pid, gint status, gpointer user_data)
{
	struct connman_task *task = user_data;

	if (WIFEXITED(status))
		DBG("task %p exit status %d", task, WEXITSTATUS(status));
	else
		DBG("task %p signal %d", task, WTERMSIG(status));

	g_spawn_close_pid(pid);
	task->pid = -1;

	if (task->exit_func)
		task->exit_func(task, task->exit_data);
}

static void task_setup(gpointer user_data)
{
	struct connman_task *task = user_data;

	DBG("task %p", task);
}

/**
 * connman_task_run:
 * @task: task structure
 * @function: exit callback
 * @user_data: optional exit user data
 *
 * Execute program specified by #task
 */
int connman_task_run(struct connman_task *task,
			connman_task_exit_t function, void *user_data)
{
	GSpawnFlags flags = G_SPAWN_DO_NOT_REAP_CHILD |
						G_SPAWN_STDOUT_TO_DEV_NULL;
	char **argv, **envp;

	DBG("task %p", task);

	if (task->pid > 0)
		return -EALREADY;

	task->exit_func = function;
	task->exit_data = user_data;

	if (g_ptr_array_index(task->argv, task->argv->len - 1) != NULL)
		g_ptr_array_add(task->argv, NULL);

	if (task->envp->len == 0 || g_ptr_array_index(task->envp,
					task->envp->len - 1) != NULL) {
		if (g_hash_table_size(task->notify) > 0) {
			const char *busname;
			char *str;

			busname = dbus_bus_get_unique_name(connection);
			str = g_strdup_printf("CONNMAN_BUSNAME=%s", busname);
			g_ptr_array_add(task->envp, str);

			str = g_strdup_printf("CONNMAN_INTERFACE=%s",
						CONNMAN_TASK_INTERFACE);
			g_ptr_array_add(task->envp, str);

			str = g_strdup_printf("CONNMAN_PATH=%s", task->path);
			g_ptr_array_add(task->envp, str);
		}

		g_ptr_array_add(task->envp, NULL);
	}

	argv = (char **) task->argv->pdata;
	envp = (char **) task->envp->pdata;

	if (g_spawn_async(NULL, argv, envp, flags,
				task_setup, task, &task->pid, NULL) == FALSE) {
		connman_error("Failed to spawn %s", argv[0]);
		return -EIO;
	}

	g_child_watch_add(task->pid, task_died, task);

	return 0;
}

/**
 * connman_task_stop:
 * @task: task structure
 *
 * Stop program specified by #task
 */
int connman_task_stop(struct connman_task *task)
{
	DBG("task %p", task);

	if (task->pid > 0)
		kill(task->pid, SIGTERM);

	return 0;
}

static DBusHandlerResult task_filter(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct connman_task *task;
	struct notify_data *notify;
	const char *path, *member;

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

	if (dbus_message_get_no_reply(message) == FALSE) {
		DBusMessage *reply;
		dbus_bool_t result;

		reply = dbus_message_new_method_return(message);
		if (reply == NULL)
			return DBUS_HANDLER_RESULT_NEED_MEMORY;

		result = dbus_connection_send(connection, reply, NULL);

		dbus_message_unref(reply);
	}

	member = dbus_message_get_member(message);
	if (member == NULL)
		return DBUS_HANDLER_RESULT_HANDLED;

	notify = g_hash_table_lookup(task->notify, member);
	if (notify == NULL)
		return DBUS_HANDLER_RESULT_HANDLED;

	if (notify->func)
		notify->func(task, message, notify->data);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static const char *task_rule = "type=method_call"
					",interface=" CONNMAN_TASK_INTERFACE;

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
