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

#include <unistd.h>
#include <sys/wait.h>

#include <glib.h>

#include <connman/log.h>

#include "task.h"

struct task_data {
	pid_t pid;
	int index;
	task_cb_t callback;
	void *user_data;
};

static GSList *task_list = NULL;

struct task_data *task_find_by_pid(pid_t pid)
{
	GSList *list;

	for (list = task_list; list; list = list->next) {
		struct task_data *task = list->data;

		if (task->pid == pid)
			return task;
	}

	return NULL;
}

struct task_data *task_find_by_index(int index)
{
	GSList *list;

	for (list = task_list; list; list = list->next) {
		struct task_data *task = list->data;

		if (task->index == index)
			return task;
	}

	return NULL;
}

static void task_died(GPid pid, gint status, gpointer user_data)
{
	struct task_data *task = user_data;

	if (WIFEXITED(status))
		DBG("task %p exit status %d", task, WEXITSTATUS(status));
	else
		DBG("task %p signal %d", task, WTERMSIG(status));

	g_spawn_close_pid(pid);
	task->pid = 0;

	task_list = g_slist_remove(task_list, task);

	if (task->callback)
		task->callback(task->index, task->user_data);

	g_free(task);
}

static void task_setup(gpointer user_data)
{
	struct task_data *task = user_data;

	DBG("task %p", task);
}

struct task_data *task_spawn(int index, char **argv, char **envp,
					task_cb_t callback, void *user_data)
{
	GSpawnFlags flags = G_SPAWN_DO_NOT_REAP_CHILD |
						G_SPAWN_STDOUT_TO_DEV_NULL;
	struct task_data *task;

	DBG("index %d", index);

	task = g_try_new0(struct task_data, 1);
	if (task == NULL)
		return NULL;

	task->index = index;

	task->callback  = callback;
	task->user_data = user_data;

	if (g_spawn_async(NULL, argv, envp, flags,
				task_setup, task, &task->pid, NULL) == FALSE) {
		connman_error("Failed to spawn task");
		return NULL;
	}

	task_list = g_slist_append(task_list, task);

	g_child_watch_add(task->pid, task_died, task);

	DBG("task %p pid %d", task, task->pid);

	return task;
}

int task_kill(struct task_data *task)
{
	DBG("task %p", task);

	if (task->pid > 0)
		kill(task->pid, SIGTERM);

	return 0;
}

void *task_get_data(struct task_data *task)
{
	return task->user_data;
}
