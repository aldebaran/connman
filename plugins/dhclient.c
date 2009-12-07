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

#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <glib/gstdio.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/dhcp.h>
#include <connman/dbus.h>
#include <connman/log.h>

#define DHCLIENT_INTF "org.isc.dhclient"
#define DHCLIENT_PATH "/org/isc/dhclient"

static const char *busname;

struct dhclient_task {
	GPid pid;
	gboolean killed;
	int ifindex;
	gchar *ifname;
	struct dhclient_task *pending;
	struct connman_dhcp *dhcp;
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

	if (task->killed == TRUE)
		return;

	if (task->pid > 0) {
		task->killed = TRUE;
		kill(task->pid, SIGTERM);
	}
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

static int start_dhclient(struct dhclient_task *task);

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

	if (task->pending != NULL)
		start_dhclient(task->pending);

	connman_dhcp_unref(task->dhcp);

	g_free(task->ifname);
	g_free(task);
}

static void task_setup(gpointer data)
{
	struct dhclient_task *task = data;

	DBG("task %p name %s", task, task->ifname);

	task->killed = FALSE;
}

static int start_dhclient(struct dhclient_task *task)
{
	char *argv[16], *envp[1], address[128], pidfile[PATH_MAX];
	char leases[PATH_MAX], config[PATH_MAX], script[PATH_MAX];

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
	argv[3] = "-e";
	argv[4] = address;
	argv[5] = "-pf";
	argv[6] = pidfile;
	argv[7] = "-lf";
	argv[8] = leases;
	argv[9] = "-cf";
	argv[10] = config;
	argv[11] = "-sf";
	argv[12] = script;
	argv[13] = task->ifname;
	argv[14] = "-n";
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

static int dhclient_request(struct connman_dhcp *dhcp)
{
	struct dhclient_task *task, *previous;

	DBG("dhcp %p", dhcp);

	if (access(DHCLIENT, X_OK) < 0)
		return -errno;

	task = g_try_new0(struct dhclient_task, 1);
	if (task == NULL)
		return -ENOMEM;

	task->ifindex = connman_dhcp_get_index(dhcp);
	task->ifname  = connman_dhcp_get_interface(dhcp);

	if (task->ifname == NULL) {
		g_free(task);
		return -ENOMEM;
	}

	task->dhcp = connman_dhcp_ref(dhcp);

	previous= find_task_by_index(task->ifindex);
	if (previous != NULL) {
		previous->pending = task;
		kill_task(previous);
		return 0;
	}

	return start_dhclient(task);
}

static int dhclient_release(struct connman_dhcp *dhcp)
{
	struct dhclient_task *task;
	int index;

	DBG("dhcp %p", dhcp);

	index = connman_dhcp_get_index(dhcp);

	task = find_task_by_index(index);
	if (task == NULL)
		return -EINVAL;

	DBG("release %s", task->ifname);

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

		if (g_strcmp0(key, "new_ip_address") == 0) {
			connman_dhcp_set_value(task->dhcp, "Address", value);
		} else if (g_ascii_strcasecmp(key, "new_subnet_mask") == 0) {
			connman_dhcp_set_value(task->dhcp, "Netmask", value);
		} else if (g_ascii_strcasecmp(key, "new_routers") == 0) {
			connman_dhcp_set_value(task->dhcp, "Gateway", value);
		} else if (g_ascii_strcasecmp(key, "new_network_number") == 0) {
			connman_dhcp_set_value(task->dhcp, "Network", value);
		} else if (g_ascii_strcasecmp(key, "new_broadcast_address") == 0) {
			connman_dhcp_set_value(task->dhcp, "Broadcast", value);
		} else if (g_ascii_strcasecmp(key, "new_domain_name_servers") == 0) {
			connman_dhcp_set_value(task->dhcp, "Nameserver", value);
		} else if (g_ascii_strcasecmp(key, "new_domain_name") == 0) {
		} else if (g_ascii_strcasecmp(key, "new_domain_search") == 0) {
		} else if (g_ascii_strcasecmp(key, "new_host_name") == 0) {
		}

		dbus_message_iter_next(&dict);
	}

	if (g_ascii_strcasecmp(text, "PREINIT") == 0) {
	} else if (g_ascii_strcasecmp(text, "BOUND") == 0 ||
				g_ascii_strcasecmp(text, "REBOOT") == 0) {
		connman_dhcp_bound(task->dhcp);
	} else if (g_ascii_strcasecmp(text, "RENEW") == 0 ||
				g_ascii_strcasecmp(text, "REBIND") == 0) {
		connman_dhcp_renew(task->dhcp);
	} else if (g_ascii_strcasecmp(text, "FAIL") == 0) {
		connman_dhcp_fail(task->dhcp);
	} else {
	}

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusConnection *connection;

static const char *dhclient_rule = "path=" DHCLIENT_PATH
						",interface=" DHCLIENT_INTF;

static int dhclient_init(void)
{
	int err;

	connection = connman_dbus_get_connection();

	busname = dbus_bus_get_unique_name(connection);
	busname = CONNMAN_SERVICE;

	dbus_connection_add_filter(connection, dhclient_filter, NULL, NULL);

	dbus_bus_add_match(connection, dhclient_rule, NULL);

	err = connman_dhcp_driver_register(&dhclient_driver);
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

	connman_dhcp_driver_unregister(&dhclient_driver);

	dbus_bus_remove_match(connection, dhclient_rule, NULL);

	dbus_connection_remove_filter(connection, dhclient_filter, NULL);

	dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE(dhclient, "ISC DHCP client plugin", VERSION,
		CONNMAN_PLUGIN_PRIORITY_DEFAULT, dhclient_init, dhclient_exit)
