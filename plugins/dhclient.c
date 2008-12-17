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

#include <sys/wait.h>
#include <glib/gstdio.h>

#include <connman/plugin.h>
#include <connman/driver.h>
#include <connman/dbus.h>
#include <connman/log.h>

#include "inet.h"

#define DHCLIENT_INTF "org.isc.dhclient"
#define DHCLIENT_PATH "/org/isc/dhclient"

static const char *busname;

struct dhclient_task {
	GPid pid;
	int ifindex;
	gchar *ifname;
	struct connman_element *element;
};

static GSList *task_list = NULL;

static struct dhclient_task *find_task_by_pid(GPid pid)
{
	GSList *list;

	for (list = task_list; list; list = list->next) {
		struct dhclient_task *task = list->data;

		if (task->pid == pid)
			return task;
	}

	return NULL;
}

static struct dhclient_task *find_task_by_index(int index)
{
	GSList *list;

	for (list = task_list; list; list = list->next) {
		struct dhclient_task *task = list->data;

		if (task->ifindex == index)
			return task;
	}

	return NULL;
}

static void kill_task(struct dhclient_task *task)
{
	DBG("task %p name %s pid %d", task, task->ifname, task->pid);

	if (task->pid > 0)
		kill(task->pid, SIGTERM);
}

static void unlink_task(struct dhclient_task *task)
{
	gchar *pathname;

	DBG("task %p name %s pid %d", task, task->ifname, task->pid);

	pathname = g_strdup_printf("%s/dhclient.%s.pid",
						STATEDIR, task->ifname);
	g_unlink(pathname);
	g_free(pathname);

	pathname = g_strdup_printf("%s/dhclient.%s.leases",
						STATEDIR, task->ifname);
	g_unlink(pathname);
	g_free(pathname);
}

static void task_died(GPid pid, gint status, gpointer data)
{
	struct dhclient_task *task = data;

	if (WIFEXITED(status))
		DBG("exit status %d for %s", WEXITSTATUS(status), task->ifname);
	else
		DBG("signal %d killed %s", WTERMSIG(status), task->ifname);

	g_spawn_close_pid(pid);
	task->pid = 0;

	task_list = g_slist_remove(task_list, task);

	unlink_task(task);

	g_free(task->ifname);
	g_free(task);
}

static void task_setup(gpointer data)
{
	struct dhclient_task *task = data;

	DBG("task %p name %s", task, task->ifname);
}

static int dhclient_probe(struct connman_element *element)
{
	struct dhclient_task *task;
	char *argv[16], *envp[1], address[128], pidfile[PATH_MAX];
	char leases[PATH_MAX], config[PATH_MAX], script[PATH_MAX];

	DBG("element %p name %s", element, element->name);

	task = g_try_new0(struct dhclient_task, 1);
	if (task == NULL)
		return -ENOMEM;

	task->ifindex = element->index;
	task->ifname = inet_index2name(element->index);
	task->element = element;

	if (task->ifname == NULL) {
		g_free(task);
		return -ENOMEM;
	}

	DBG("request %s", task->ifname);

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
		connman_error("Failed to spawn dhclient");
		return -1;
	}

	task_list = g_slist_append(task_list, task);

	g_child_watch_add(task->pid, task_died, task);

	DBG("executed %s with pid %d", DHCLIENT, task->pid);

	return 0;
}

static void dhclient_remove(struct connman_element *element)
{
	struct dhclient_task *task;

	DBG("element %p name %s", element, element->name);

	task = find_task_by_index(element->index);
	if (task != NULL)
		task_list = g_slist_remove(task_list, task);

	if (task == NULL)
		return;

	DBG("release %s", task->ifname);

	kill_task(task);
}

static struct connman_driver dhclient_driver = {
	.name		= "dhclient",
	.type		= CONNMAN_ELEMENT_TYPE_DHCP,
	.probe		= dhclient_probe,
	.remove		= dhclient_remove,
};

static DBusHandlerResult dhclient_filter(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessageIter iter, dict;
	dbus_uint32_t pid;
	struct dhclient_task *task;
	const char *text, *key, *value;

	if (dbus_message_is_method_call(msg, DHCLIENT_INTF, "notify") == FALSE)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	dbus_message_iter_init(msg, &iter);

	dbus_message_iter_get_basic(&iter, &pid);
	dbus_message_iter_next(&iter);

	dbus_message_iter_get_basic(&iter, &text);
	dbus_message_iter_next(&iter);

	DBG("change %d to %s", pid, text);

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

		DBG("%s = %s", key, value);

		if (g_ascii_strcasecmp(key, "new_ip_address") == 0) {
			g_free(task->element->ipv4.address);
			task->element->ipv4.address = g_strdup(value);
		}

		if (g_ascii_strcasecmp(key, "new_subnet_mask") == 0) {
			g_free(task->element->ipv4.netmask);
			task->element->ipv4.netmask = g_strdup(value);
		}

		if (g_ascii_strcasecmp(key, "new_routers") == 0) {
			g_free(task->element->ipv4.gateway);
			task->element->ipv4.gateway = g_strdup(value);
		}

		if (g_ascii_strcasecmp(key, "new_network_number") == 0) {
			g_free(task->element->ipv4.network);
			task->element->ipv4.network = g_strdup(value);
		}

		if (g_ascii_strcasecmp(key, "new_broadcast_address") == 0) {
			g_free(task->element->ipv4.broadcast);
			task->element->ipv4.broadcast = g_strdup(value);
		}

		if (g_ascii_strcasecmp(key, "new_domain_name_servers") == 0) {
			g_free(task->element->ipv4.nameserver);
			task->element->ipv4.nameserver = g_strdup(value);
		}

		dbus_message_iter_next(&dict);
	}

	if (g_ascii_strcasecmp(text, "PREINIT") == 0) {
	} else if (g_ascii_strcasecmp(text, "BOUND") == 0 ||
				g_ascii_strcasecmp(text, "REBOOT") == 0) {
		struct connman_element *element;
		element = connman_element_create(NULL);
		element->type = CONNMAN_ELEMENT_TYPE_IPV4;
		element->index = task->ifindex;
		connman_element_update(task->element);
		if (connman_element_register(element, task->element) < 0)
			connman_element_unref(element);
	} else if (g_ascii_strcasecmp(text, "RENEW") == 0 ||
				g_ascii_strcasecmp(text, "REBIND") == 0) {
		connman_element_update(task->element);
	} else {
	}

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusConnection *connection;

static int dhclient_init(void)
{
	gchar *filter;
	int err;

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);

	busname = dbus_bus_get_unique_name(connection);
	busname = CONNMAN_SERVICE;

	dbus_connection_add_filter(connection, dhclient_filter, NULL, NULL);

	filter = g_strdup_printf("interface=%s,path=%s",
						DHCLIENT_INTF, DHCLIENT_PATH);

	dbus_bus_add_match(connection, filter, NULL);

	g_free(filter);

	err = connman_driver_register(&dhclient_driver);
	if (err < 0) {
		dbus_connection_unref(connection);
		return err;
	}

	return 0;
}

static void dhclient_exit(void)
{
	GSList *list;

	for (list = task_list; list; list = list->next) {
		struct dhclient_task *task = list->data;

		DBG("killing process %d", task->pid);

		kill_task(task);
		unlink_task(task);
	}

	g_slist_free(task_list);

	connman_driver_unregister(&dhclient_driver);

	dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE(dhclient, "ISC DHCP client plugin", VERSION,
						dhclient_init, dhclient_exit)
