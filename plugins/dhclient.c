/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2008  Intel Corporation. All rights reserved.
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
#include <string.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <glib.h>
#include <gdbus.h>

#include <connman/plugin.h>
#include <connman/dhcp.h>

#define DHCLIENT_INTF "org.isc.dhclient"
#define DHCLIENT_PATH "/org/isc/dhclient"

static const char *busname;

struct dhclient_task {
	GPid pid;
	int ifindex;
	char *ifname;
	struct connman_iface *iface;
};

static GSList *tasks = NULL;

static struct dhclient_task *find_task_by_pid(GPid pid)
{
	GSList *list;

	for (list = tasks; list; list = list->next) {
		struct dhclient_task *task = list->data;

		if (task->pid == pid)
			return task;
	}

	return NULL;
}

static struct dhclient_task *find_task_by_index(int index)
{
	GSList *list;

	for (list = tasks; list; list = list->next) {
		struct dhclient_task *task = list->data;

		if (task->ifindex == index)
			return task;
	}

	return NULL;
}

static void kill_task(struct dhclient_task *task)
{
	if (task->pid > 0)
		kill(task->pid, SIGTERM);
}

static void task_died(GPid pid, gint status, gpointer data)
{
	struct dhclient_task *task = data;
	char pathname[PATH_MAX];

	if (WIFEXITED(status))
		printf("[DHCP] exit status %d for %s\n",
					WEXITSTATUS(status), task->ifname);
	else
		printf("[DHCP] signal %d killed %s\n",
					WTERMSIG(status), task->ifname);

	g_spawn_close_pid(pid);
	task->pid = 0;

	tasks = g_slist_remove(tasks, task);

	snprintf(pathname, sizeof(pathname) - 1,
			"%s/dhclient.%s.pid", STATEDIR, task->ifname);
	unlink(pathname);

	snprintf(pathname, sizeof(pathname) - 1,
			"%s/dhclient.%s.leases", STATEDIR, task->ifname);
	unlink(pathname);

	free(task->ifname);

	g_free(task);
}

static void task_setup(gpointer data)
{
	struct dhclient_task *task = data;

	printf("[DHCP] setup %s\n", task->ifname);
}

static int dhclient_request(struct connman_iface *iface)
{
	struct ifreq ifr;
	struct dhclient_task *task;
	char *argv[16], *envp[1], address[128], pidfile[PATH_MAX];
	char leases[PATH_MAX], config[PATH_MAX], script[PATH_MAX];
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

	task = g_try_new0(struct dhclient_task, 1);
	if (task == NULL)
		return -ENOMEM;

	task->ifindex = iface->index;
	task->ifname = strdup(ifr.ifr_name);
	task->iface = iface;

	if (task->ifname == NULL) {
		g_free(task);
		return -ENOMEM;
	}

	printf("[DHCP] request %s\n", task->ifname);

	snprintf(address, sizeof(address) - 1, "BUSNAME=%s", busname);
	snprintf(pidfile, sizeof(pidfile) - 1,
			"%s/dhclient.%s.pid", STATEDIR, task->ifname);
	snprintf(leases, sizeof(leases) - 1,
			"%s/dhclient.%s.leases", STATEDIR, task->ifname);
	snprintf(config, sizeof(config) - 1, "%s/dhclient.conf", SCRIPTDIR);
	snprintf(script, sizeof(script) - 1, "%s/dhclient-script", SCRIPTDIR);

	argv[0] = DHCLIENT;
	argv[1] = "-d";
	argv[2] = "-q";
	argv[3] = "-n";
	argv[4] = "-e";
	argv[5] = address;
	argv[6] = "-pf";
	argv[7] = pidfile;
	argv[8] = "-lf";
	argv[9] = leases;
	argv[10] = "-cf";
	argv[11] = config;
	argv[12] = "-sf";
	argv[13] = script;
	argv[14] = task->ifname;
	argv[15] = NULL;

	envp[0] = NULL;

	if (g_spawn_async(NULL, argv, envp, G_SPAWN_DO_NOT_REAP_CHILD,
				task_setup, task, &task->pid, NULL) == FALSE) {
		printf("Failed to spawn dhclient\n");
		return -1;
	}

	tasks = g_slist_append(tasks, task);

	g_child_watch_add(task->pid, task_died, task);

	printf("[DHCP] executed %s with pid %d\n", DHCLIENT, task->pid);

	return 0;
}

static int dhclient_release(struct connman_iface *iface)
{
	struct dhclient_task *task;

	task = find_task_by_index(iface->index);
	if (task == NULL)
		return -ENODEV;

	printf("[DHCP] release %s\n", task->ifname);

	tasks = g_slist_remove(tasks, task);

	kill_task(task);

	return 0;
}

static struct connman_dhcp_driver dhclient_driver = {
	.name		= "dhclient",
	.request	= dhclient_request,
	.release	= dhclient_release,
};

static DBusHandlerResult dhclient_filter(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessageIter iter, dict;
	dbus_uint32_t pid;
	struct dhclient_task *task;
	struct connman_ipv4 ipv4;
	const char *text, *key, *value;

	if (dbus_message_is_method_call(msg, DHCLIENT_INTF, "notify") == FALSE)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	memset(&ipv4, 0, sizeof(ipv4));

	dbus_message_iter_init(msg, &iter);

	dbus_message_iter_get_basic(&iter, &pid);
	dbus_message_iter_next(&iter);

	dbus_message_iter_get_basic(&iter, &text);
	dbus_message_iter_next(&iter);

	printf("[DHCP] change %d to %s\n", pid, text);

	task = find_task_by_pid(pid);
	if (task == NULL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	dbus_message_iter_recurse(&iter, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);
		dbus_message_iter_get_basic(&entry, &value);

		printf("[DHCP] %s = %s\n", key, value);

		if (strcmp(key, "new_ip_address") == 0)
			inet_aton(value, &ipv4.address);

		if (strcmp(key, "new_subnet_mask") == 0)
			inet_aton(value, &ipv4.netmask);

		if (strcmp(key, "new_routers") == 0)
			inet_aton(value, &ipv4.gateway);

		if (strcmp(key, "new_network_number") == 0)
			inet_aton(value, &ipv4.network);

		if (strcmp(key, "new_broadcast_address") == 0)
			inet_aton(value, &ipv4.broadcast);

		if (strcmp(key, "new_domain_name_servers") == 0)
			inet_aton(value, &ipv4.nameserver);

		dbus_message_iter_next(&dict);
	}

	if (strcmp(text, "PREINIT") == 0)
		connman_dhcp_update(task->iface,
					CONNMAN_DHCP_STATE_INIT, &ipv4);
	else if (strcmp(text, "BOUND") == 0 || strcmp(text, "REBOOT") == 0)
		connman_dhcp_update(task->iface,
					CONNMAN_DHCP_STATE_BOUND, &ipv4);
	else if (strcmp(text, "RENEW") == 0 || strcmp(text, "REBIND") == 0)
		connman_dhcp_update(task->iface,
					CONNMAN_DHCP_STATE_RENEW, &ipv4);
	else
		connman_dhcp_update(task->iface,
					CONNMAN_DHCP_STATE_FAILED, NULL);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusConnection *connection;

static int plugin_init(void)
{
	gchar *filter;

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);

	busname = dbus_bus_get_unique_name(connection);

	busname = "org.freedesktop.connman";

	dbus_connection_add_filter(connection, dhclient_filter, NULL, NULL);

	filter = g_strdup_printf("interface=%s,path=%s",
						DHCLIENT_INTF, DHCLIENT_PATH);

	dbus_bus_add_match(connection, filter, NULL);

	g_free(filter);

	connman_dhcp_register(&dhclient_driver);

	return 0;
}

static void plugin_exit(void)
{
	GSList *list;

	for (list = tasks; list; list = list->next) {
		struct dhclient_task *task = list->data;

		printf("[DHCP] killing process %d\n", task->pid);

		kill_task(task);
	}

	g_slist_free(tasks);

	connman_dhcp_unregister(&dhclient_driver);

	dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE("dhclient", "ISC DHCP client plugin", VERSION,
						plugin_init, plugin_exit)
