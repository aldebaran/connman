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

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <glib.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/dhcp.h>
#include <connman/task.h>
#include <connman/log.h>

#if 0
static unsigned char netmask2prefixlen(const char *netmask)
{
	unsigned char bits = 0;
	in_addr_t mask = inet_network(netmask);
	in_addr_t host = ~mask;

	/* a valid netmask must be 2^n - 1 */
	if ((host & (host + 1)) != 0)
		return -1;

	for (; mask; mask <<= 1)
		++bits;

	return bits;
}
#endif

static void dhclient_notify(struct connman_task *task,
					DBusMessage *msg, void *user_data)
{
	struct connman_dhcp *dhcp = user_data;
	DBusMessageIter iter, dict;
	dbus_uint32_t pid;
	const char *text, *key, *value;

	dbus_message_iter_init(msg, &iter);

	dbus_message_iter_get_basic(&iter, &pid);
	dbus_message_iter_next(&iter);

	dbus_message_iter_get_basic(&iter, &text);
	dbus_message_iter_next(&iter);

	DBG("change %d to %s", pid, text);

	dbus_message_iter_recurse(&iter, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);
		dbus_message_iter_get_basic(&entry, &value);

		DBG("%s = %s", key, value);

		if (g_strcmp0(key, "new_ip_address") == 0) {
			connman_dhcp_set_value(dhcp, "Address", value);
		} else if (g_strcmp0(key, "new_subnet_mask") == 0) {
			connman_dhcp_set_value(dhcp, "Netmask", value);
		} else if (g_strcmp0(key, "new_routers") == 0) {
			connman_dhcp_set_value(dhcp, "Gateway", value);
		} else if (g_strcmp0(key, "new_network_number") == 0) {
			connman_dhcp_set_value(dhcp, "Network", value);
		} else if (g_strcmp0(key, "new_broadcast_address") == 0) {
			connman_dhcp_set_value(dhcp, "Broadcast", value);
		} else if (g_strcmp0(key, "new_domain_name_servers") == 0) {
			connman_dhcp_set_value(dhcp, "Nameserver", value);
		} else if (g_ascii_strcasecmp(key, "new_domain_name") == 0) {
			connman_dhcp_set_value(dhcp, "Domainname", value);
		} else if (g_ascii_strcasecmp(key, "new_domain_search") == 0) {
		} else if (g_ascii_strcasecmp(key, "new_host_name") == 0) {
			connman_dhcp_set_value(dhcp, "Hostname", value);
		} else if (g_ascii_strcasecmp(key, "new_ntp_servers") == 0) {
			connman_dhcp_set_value(dhcp, "Timeserver", value);
		} else if (g_ascii_strcasecmp(key, "new_interface_mtu") == 0) {
			connman_dhcp_set_value(dhcp, "MTU", value);
		}

		dbus_message_iter_next(&dict);
	}

	if (g_strcmp0(text, "PREINIT") == 0) {
	} else if (g_strcmp0(text, "BOUND") == 0 ||
				g_strcmp0(text, "REBOOT") == 0) {
		connman_dhcp_bound(dhcp);
	} else if (g_strcmp0(text, "RENEW") == 0 ||
				g_strcmp0(text, "REBIND") == 0) {
		connman_dhcp_renew(dhcp);
	} else if (g_strcmp0(text, "FAIL") == 0) {
		connman_dhcp_fail(dhcp);
	} else {
	}
}

struct dhclient_data {
	struct connman_task *task;
	struct connman_dhcp *dhcp;
	char *ifname;
};

static void dhclient_died(struct connman_task *task, void *user_data)
{
	struct dhclient_data *dhclient = user_data;

	connman_dhcp_unref(dhclient->dhcp);

	connman_task_destroy(dhclient->task);
	dhclient->task = NULL;

	g_free(dhclient->ifname);
	g_free(dhclient);
}

static void dhclient_setup(struct connman_task *task, const char *ifname)
{
	const char *path, *intf = "org.moblin.connman.Task";

	path = connman_task_get_path(task);

	connman_task_add_argument(task, "-d", NULL);
	connman_task_add_argument(task, "-q", NULL);
	connman_task_add_argument(task, "-e", "BUSNAME=org.moblin.connman");
	connman_task_add_argument(task, "-e", "BUSINTF=%s", intf);
	connman_task_add_argument(task, "-e", "BUSPATH=%s", path);
	connman_task_add_argument(task, "-pf", "%s/dhclient.%s.pid",
							STATEDIR, ifname);
	connman_task_add_argument(task, "-lf", "%s/dhclient.%s.leases",
							STATEDIR, ifname);
	connman_task_add_argument(task, "-cf", "%s/dhclient.conf", SCRIPTDIR);
	connman_task_add_argument(task, "-sf", "%s/dhclient-script", SCRIPTDIR);
	connman_task_add_argument(task, ifname, NULL);
	connman_task_add_argument(task, "-n", NULL);
}

static void dhclient_unlink(const char *ifname)
{
	char *pathname;

	pathname = g_strdup_printf("%s/dhclient.%s.pid",
						STATEDIR, ifname);
	unlink(pathname);
	g_free(pathname);

	pathname = g_strdup_printf("%s/dhclient.%s.leases",
						STATEDIR, ifname);
	unlink(pathname);
	g_free(pathname);
}

static int dhclient_request(struct connman_dhcp *dhcp)
{
	struct dhclient_data *dhclient;

	DBG("dhcp %p", dhcp);

	if (access(DHCLIENT, X_OK) < 0)
		return -EIO;

	dhclient = g_try_new0(struct dhclient_data, 1);
	if (dhclient == NULL)
		return -ENOMEM;

	dhclient->task = connman_task_create(DHCLIENT);
	if (dhclient->task == NULL) {
		g_free(dhclient);
		return -ENOMEM;
	}

	dhclient->dhcp = connman_dhcp_ref(dhcp);
	dhclient->ifname = connman_dhcp_get_interface(dhcp);

	dhclient_setup(dhclient->task, dhclient->ifname);

	connman_dhcp_set_data(dhcp, dhclient);

	connman_task_set_notify(dhclient->task, "Notify",
						dhclient_notify, dhcp);

	connman_task_run(dhclient->task, dhclient_died, dhclient);

	return 0;
}

static int dhclient_release(struct connman_dhcp *dhcp)
{
	struct dhclient_data *dhclient = connman_dhcp_get_data(dhcp);

	DBG("dhcp %p", dhcp);

	if (dhclient->task != NULL)
		connman_task_stop(dhclient->task);

	dhclient_unlink(dhclient->ifname);

	return 0;
}

static struct connman_dhcp_driver dhclient_driver = {
	.name		= "dhclient",
	.request	= dhclient_request,
	.release	= dhclient_release,
};

static int dhclient_init(void)
{
	return connman_dhcp_driver_register(&dhclient_driver);
}

static void dhclient_exit(void)
{
	connman_dhcp_driver_unregister(&dhclient_driver);
}

CONNMAN_PLUGIN_DEFINE(dhclient, "ISC DHCP client plugin", VERSION,
		CONNMAN_PLUGIN_PRIORITY_DEFAULT, dhclient_init, dhclient_exit)
