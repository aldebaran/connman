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
#include <unistd.h>

#include <connman/plugin.h>
#include <connman/driver.h>
#include <connman/dbus.h>
#include <connman/log.h>

#include "inet.h"
#include "task.h"

#define UDHCPC_INTF  "org.busybox.udhcpc"
#define UDHCPC_PATH  "/org/busybox/udhcpc"

static int udhcp_probe(struct connman_element *element)
{
	struct task_data *task;
	char *argv[9], *envp[2], *ifname;
	char pidfile[PATH_MAX], script[PATH_MAX];

	DBG("element %p name %s", element, element->name);

	if (access(UDHCPC, X_OK) < 0)
		return -errno;

	ifname = inet_index2name(element->index);
	if (ifname == NULL)
		return -ENOMEM;

	snprintf(pidfile, sizeof(pidfile) - 1,
				"%s/udhcpc.%s.pid", STATEDIR, ifname);
	snprintf(script, sizeof(script) - 1, "%s/udhcpc-script", SCRIPTDIR);

	argv[0] = UDHCPC;
	argv[1] = "-f";
	argv[2] = "-i";
	argv[3] = ifname;
	argv[4] = "-p";
	argv[5] = pidfile;
	argv[6] = "-s";
	argv[7] = script;
	argv[8] = NULL;

	envp[0] = NULL;

	task = task_spawn(element->index, argv, envp, NULL, element);
	if (task == NULL) {
		g_free(ifname);
		return -EIO;
	}

	g_free(ifname);

	return 0;
}

static void udhcp_remove(struct connman_element *element)
{
	struct task_data *task;

	DBG("element %p name %s", element, element->name);

	task = task_find_by_index(element->index);
	if (task == NULL)
		return;

	task_kill(task);
}

static struct connman_driver udhcp_driver = {
	.name		= "udhcp",
	.type		= CONNMAN_ELEMENT_TYPE_DHCP,
	.priority	= CONNMAN_DRIVER_PRIORITY_HIGH,
	.probe		= udhcp_probe,
	.remove		= udhcp_remove,
};

static void udhcp_bound(DBusMessage *msg, gboolean renew)
{
	struct task_data *task;
	struct connman_element *element, *parent;
	const char *interface, *address, *netmask, *broadcast, *gateway, *dns;
	int index;

	dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &interface,
					DBUS_TYPE_STRING, &address,
					DBUS_TYPE_STRING, &netmask,
					DBUS_TYPE_STRING, &broadcast,
					DBUS_TYPE_STRING, &gateway,
					DBUS_TYPE_STRING, &dns,
							DBUS_TYPE_INVALID);

	DBG("%s ==> address %s gateway %s", interface, address, gateway);

	index = inet_name2index(interface);
	if (index < 0)
		return;

	task = task_find_by_index(index);
	if (task == NULL)
		return;

	parent = task_get_data(task);
	if (parent == NULL)
		return;

	g_free(parent->ipv4.address);
	parent->ipv4.address = g_strdup(address);

	g_free(parent->ipv4.netmask);
	parent->ipv4.netmask = g_strdup(netmask);

	g_free(parent->ipv4.broadcast);
	parent->ipv4.broadcast = g_strdup(broadcast);

	g_free(parent->ipv4.gateway);
	parent->ipv4.gateway = g_strdup(gateway);

	g_free(parent->ipv4.nameserver);
	parent->ipv4.nameserver = g_strdup(dns);

	connman_element_update(parent);

	if (renew == TRUE)
		return;

	element = connman_element_create(NULL);
	if (element == NULL)
		return;

	element->type = CONNMAN_ELEMENT_TYPE_IPV4;
	element->index = index;

	if (connman_element_register(element, parent) < 0)
		connman_element_unref(element);
}

static DBusHandlerResult udhcp_filter(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	if (dbus_message_is_method_call(msg, UDHCPC_INTF, "bound") == TRUE) {
		udhcp_bound(msg, FALSE);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (dbus_message_is_method_call(msg, UDHCPC_INTF, "renew") == TRUE) {
		udhcp_bound(msg, TRUE);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusConnection *connection;

static const char *udhcp_rule = "path=" UDHCPC_PATH ",interface=" UDHCPC_INTF;

static int udhcp_init(void)
{
	int err;

	connection = connman_dbus_get_connection();

	dbus_connection_add_filter(connection, udhcp_filter, NULL, NULL);

	dbus_bus_add_match(connection, udhcp_rule, NULL);

	err = connman_driver_register(&udhcp_driver);
	if (err < 0) {
		dbus_connection_unref(connection);
		return err;
	}

	return 0;
}

static void udhcp_exit(void)
{
	connman_driver_unregister(&udhcp_driver);

	dbus_bus_remove_match(connection, udhcp_rule, NULL);

	dbus_connection_remove_filter(connection, udhcp_filter, NULL);

	dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE(dhclient, "uDHCP client plugin", VERSION,
						udhcp_init, udhcp_exit)
