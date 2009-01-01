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

#include <sys/types.h>

struct task_data;

typedef void (* task_cb_t) (int index, void *user_data);

struct task_data *task_find_by_pid(pid_t pid);
struct task_data *task_find_by_index(int index);

struct task_data *task_spawn(int index, char **argv, char **envp,
					task_cb_t callback, void *user_data);
int task_kill(struct task_data *task);

void *task_get_data(struct task_data *task);
