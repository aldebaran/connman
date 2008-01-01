/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007  Intel Corporation. All rights reserved.
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

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <net/if.h>

#include <glib.h>

#include "supplicant.h"

struct supplicant_task {
	GPid pid;
	int ifindex;
	char *ifname;
	struct connman_iface *iface;
	int socket;
	GIOChannel *channel;
};

static GSList *tasks = NULL;

static struct supplicant_task *find_task(int ifindex)
{
	GSList *list;

	for (list = tasks; list; list = list->next) {
		struct supplicant_task *task = list->data;

		if (task->ifindex == ifindex) 
			return task;
	}

	return NULL;
}

static int exec_cmd(struct supplicant_task *task, char *cmd)
{
	write(task->socket, cmd, strlen(cmd));

	return 0;
}

static gboolean control_event(GIOChannel *chan,
				GIOCondition cond, gpointer data)
{
	struct supplicant_task *task = data;
	char buf[256];
	gsize len;
	GIOError err;

	if (cond & (G_IO_NVAL | G_IO_HUP | G_IO_ERR)) {
		g_io_channel_unref(chan);
		return FALSE;
	}

	memset(buf, 0, sizeof(buf));

	err = g_io_channel_read(chan, buf, sizeof(buf), &len);
	if (err) {
		if (err == G_IO_ERROR_AGAIN)
			return TRUE;
		g_io_channel_unref(chan);
		return FALSE;
	}

	if (buf[0] != '<')
		return TRUE;

	printf("[SUPPLICANT] %s\n", buf + 3);

	if (g_str_has_prefix(buf + 3, "CTRL-EVENT-CONNECTED") == TRUE) {
		printf("[SUPPLICANT] connected\n");
		connman_iface_update(task->iface,
					CONNMAN_IFACE_STATE_CONNECTED);
	}

	if (g_str_has_prefix(buf + 3, "CTRL-EVENT-DISCONNECTED") == TRUE) {
		printf("[SUPPLICANT] disconnected\n");
	}

	if (g_str_has_prefix(buf + 3, "CTRL-EVENT-TERMINATING") == TRUE) {
		printf("[SUPPLICANT] terminating\n");
	}

	return TRUE;
}

static int open_control(struct supplicant_task *task)
{
	struct sockaddr_un addr;
	int sk;

	printf("[SUPPLICANT] open control for %s\n", task->ifname);

	sk = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (sk < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path),
					"%s/%s.cli", STATEDIR, task->ifname);
	//unlink(addr.sun_path);

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(sk);
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path),
					"%s/%s", STATEDIR, task->ifname);

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(sk);
		return -1;
	}

	task->socket = sk;

	task->channel = g_io_channel_unix_new(sk);
	g_io_channel_set_close_on_unref(task->channel, TRUE);

	g_io_add_watch(task->channel,
			G_IO_IN | G_IO_NVAL | G_IO_HUP | G_IO_ERR,
						control_event, task);

	exec_cmd(task, "ATTACH");
	exec_cmd(task, "ADD_NETWORK");

	g_io_channel_unref(task->channel);

	return 0;
}

int __supplicant_start(struct connman_iface *iface)
{
	struct ifreq ifr;
	struct supplicant_task *task;
	char *argv[9];
	int sk, err;

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0)
		return -EIO;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = iface->index;

	err = ioctl(sk, SIOCGIFNAME, &ifr);

	close(sk);

	if (err < 0)
		return -EIO;

	printf("[SUPPLICANT] start %s\n", ifr.ifr_name);

	task = g_try_new0(struct supplicant_task, 1);
	if (task == NULL)
		return -ENOMEM;

	task->ifindex = iface->index;
	task->ifname = strdup(ifr.ifr_name);
	task->iface = iface;

	if (task->ifname == NULL) {
		g_free(task);
		return -ENOMEM;
	}

	argv[0] = "/sbin/wpa_supplicant";
	argv[1] = "-qq";
	argv[2] = "-C";
	argv[3] = STATEDIR;
	argv[4] = "-D";
	argv[5] = "wext";
	argv[6] = "-i";
	argv[7] = task->ifname;
	argv[8] = NULL;

	if (g_spawn_async(NULL, argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD,
				NULL, NULL, &task->pid, NULL) == FALSE) {
		printf("Failed to spawn wpa_supplicant\n");
		return -1;
	}

	tasks = g_slist_append(tasks, task);

	printf("[SUPPLICANT] executed with pid %d\n", task->pid);

	sleep(1);

	task->socket = -1;

	if (open_control(task) < 0)
		printf("[SUPPLICANT] control failed\n");

	return 0;
}

int __supplicant_stop(struct connman_iface *iface)
{
	struct supplicant_task *task;
	char pathname[PATH_MAX];

	task = find_task(iface->index);
	if (task == NULL)
		return -ENODEV;

	printf("[SUPPLICANT] stop %s\n", task->ifname);

	tasks = g_slist_remove(tasks, task);

	exec_cmd(task, "DETACH");

	//close(task->socket);
	g_io_channel_unref(task->channel);

	snprintf(pathname, sizeof(pathname),
					"%s/%s.cli", STATEDIR, task->ifname);
	unlink(pathname);

	kill(task->pid, SIGTERM);

	free(task->ifname);

	g_free(task);

	return 0;
}

int __supplicant_connect(struct connman_iface *iface)
{
	struct supplicant_task *task;

	task = find_task(iface->index);
	if (task == NULL)
		return -ENODEV;

	printf("[SUPPLICANT] connect %s\n", task->ifname);

	exec_cmd(task, "DISABLE_NETWORK 0");

	return 0;
}
