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

#include <errno.h>
#include <unistd.h>

#include <gdbus.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/utsname.h>
#include <connman/dhcp.h>
#include <connman/task.h>
#include <connman/log.h>

struct udhcp_data {
	struct connman_task *task;
	struct connman_dhcp *dhcp;
	char *ifname;
};

static void udhcp_unlink(const char *ifname)
{
	char *pathname;

	pathname = g_strdup_printf("%s/udhcpc.%s.pid",
						STATEDIR, ifname);
	unlink(pathname);
	g_free(pathname);
}

static void udhcp_notify(struct connman_task *task,
				DBusMessage *msg, void *user_data)
{
	struct connman_dhcp *dhcp = user_data;
	const char *interface, *address, *netmask, *broadcast, *gateway, *dns, *action;

	DBG("");

	dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &interface,
					DBUS_TYPE_STRING, &address,
					DBUS_TYPE_STRING, &netmask,
					DBUS_TYPE_STRING, &broadcast,
					DBUS_TYPE_STRING, &gateway,
					DBUS_TYPE_STRING, &dns,
					DBUS_TYPE_STRING, &action,
							DBUS_TYPE_INVALID);

	DBG("%s address %s gateway %s", action, address, gateway);

	connman_dhcp_set_value(dhcp, "Address", address);
	connman_dhcp_set_value(dhcp, "Netmask", netmask);
	connman_dhcp_set_value(dhcp, "Gateway", gateway);
	connman_dhcp_set_value(dhcp, "Broadcast", broadcast);
	connman_dhcp_set_value(dhcp, "Nameserver", dns);

	if (g_strcmp0(action, "bound") == 0) {
		connman_dhcp_bound(dhcp);
	} else if (g_strcmp0(action, "renew") == 0) {
		connman_dhcp_bound(dhcp);
	} else {
		connman_error("Unknown action %s", action);
	}
}

static void udhcp_died(struct connman_task *task, void *user_data)
{
	struct udhcp_data *udhcpc = user_data;

	connman_dhcp_set_data(udhcpc->dhcp, NULL);

	connman_dhcp_unref(udhcpc->dhcp);

	connman_task_destroy(udhcpc->task);
	udhcpc->task = NULL;

	udhcp_unlink(udhcpc->ifname);

	g_free(udhcpc->ifname);
	g_free(udhcpc);
}


static void udhcp_setup(struct connman_task *task, const char *ifname)
{
	const char *path, *hostname;

	path = connman_task_get_path(task);

	DBG("path %s", path);

	connman_task_add_argument(task, "-f", NULL);
	connman_task_add_argument(task, "-i", "%s", ifname);
	connman_task_add_argument(task, "-p", "%s/udhcpc.%s.pid", STATEDIR, ifname);
	connman_task_add_argument(task, "-s", "%s/udhcpc-script", SCRIPTDIR);

	hostname = connman_utsname_get_hostname();
	if (hostname != NULL)
		connman_task_add_argument(task, "-H", hostname);

	connman_task_add_variable(task, "PATH", path);

}


static int udhcp_request(struct connman_dhcp *dhcp)
{
	struct udhcp_data *udhcpc;

	DBG("dhcp %p %s", dhcp, UDHCPC);

	if (access(UDHCPC, X_OK) < 0)
		return -EIO;

	udhcpc = g_try_new0(struct udhcp_data, 1);
	if (udhcpc == NULL)
		return -ENOMEM;

	udhcpc->task = connman_task_create(UDHCPC);
	if (udhcpc->task == NULL) {
		g_free(udhcpc);
		return -ENOMEM;
	}

	udhcpc->dhcp = connman_dhcp_ref(dhcp);
	udhcpc->ifname = connman_dhcp_get_interface(dhcp);

	udhcp_setup(udhcpc->task, udhcpc->ifname);

	connman_dhcp_set_data(dhcp, udhcpc);

	connman_task_set_notify(udhcpc->task, "Notify",
						udhcp_notify, dhcp);

	connman_task_run(udhcpc->task, udhcp_died, udhcpc,
					NULL, NULL, NULL);

	return 0;
}

static int udhcp_release(struct connman_dhcp *dhcp)
{
	struct udhcp_data *udhcpc = connman_dhcp_get_data(dhcp);

	DBG("udhcp %p", udhcpc);

	if (udhcpc == NULL)
		return -ESRCH;

	if (udhcpc->task != NULL)
		connman_task_stop(udhcpc->task);

	udhcp_unlink(udhcpc->ifname);

	return 0;
}


static struct connman_dhcp_driver udhcp_driver = {
	.name		= "udhcp",
	.priority	= CONNMAN_DHCP_PRIORITY_LOW,
	.request	= udhcp_request,
	.release	= udhcp_release,
};

static int udhcp_init(void)
{
	return connman_dhcp_driver_register(&udhcp_driver);
}

static void udhcp_exit(void)
{
	connman_dhcp_driver_unregister(&udhcp_driver);
}

CONNMAN_PLUGIN_DEFINE(udhcp, "uDHCP client plugin", VERSION,
		CONNMAN_PLUGIN_PRIORITY_LOW, udhcp_init, udhcp_exit)
