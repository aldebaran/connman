/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2010  BMW Car IT GmbH. All rights reserved.
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

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <net/if.h>

#include <glib.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/provider.h>
#include <connman/log.h>
#include <connman/task.h>
#include <connman/dbus.h>

#include "vpn.h"

static DBusConnection *connection;

static int ov_notify(DBusMessage *msg, struct connman_provider *provider)
{
	DBusMessageIter iter, dict;
	const char *reason, *key, *value;
	const char *domain = NULL;
	char *dns_entries = NULL;

	dbus_message_iter_init(msg, &iter);

	dbus_message_iter_get_basic(&iter, &reason);
	dbus_message_iter_next(&iter);

	dbus_message_iter_init(msg, &iter);

	dbus_message_iter_get_basic(&iter, &reason);
	dbus_message_iter_next(&iter);

	if (!provider) {
		connman_error("No provider found");
		return VPN_STATE_FAILURE;
	}

	if (strcmp(reason, "up"))
		return VPN_STATE_DISCONNECT;

	domain = connman_provider_get_string(provider, "VPN.Domain");

	dbus_message_iter_recurse(&iter, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);
		dbus_message_iter_get_basic(&entry, &value);

		DBG("%s = %s", key, value);

		if (!strcmp(key, "trusted_ip"))
			connman_provider_set_string(provider, "Gateway", value);

		if (!strcmp(key, "ifconfig_local"))
			connman_provider_set_string(provider, "Address", value);

		if (!strcmp(key, "route_vpn_gateway"))
			connman_provider_set_string(provider, "Peer", value);

		if (g_str_has_prefix(key, "foreign_option_")) {
			gchar **options;

			options = g_strsplit(value, " ", 3);
			if (options[0] != NULL &&
					!strcmp(options[0], "dhcp-option") &&
					options[1] != NULL &&
					!strcmp(options[1], "DNS") &&
					options[2] != NULL) {

				if (dns_entries != NULL) {
					char *tmp;

					tmp = g_strjoin(" ", dns_entries,
							options[2], NULL);
					g_free(dns_entries);
					dns_entries = tmp;
				} else {
					dns_entries = g_strdup(options[2]);
				}
			}

			g_strfreev(options);
		}

		dbus_message_iter_next(&dict);
	}

	if (dns_entries != NULL) {
		connman_provider_set_string(provider, "DNS", dns_entries);
		g_free(dns_entries);
	}

	return VPN_STATE_CONNECT;
}

static int ov_connect(struct connman_provider *provider,
		struct connman_task *task, const char *if_name)
{
	const char *vpnhost, *cafile, *mtu, *certfile, *keyfile;
	int err, fd;

	vpnhost = connman_provider_get_string(provider, "Host");
	if (!vpnhost) {
		connman_error("Host not set; cannot enable VPN");
		return -EINVAL;
	}

	cafile = connman_provider_get_string(provider, "OpenVPN.CACert");
	certfile = connman_provider_get_string(provider, "OpenVPN.Cert");
	keyfile = connman_provider_get_string(provider, "OpenVPN.Key");
	mtu = connman_provider_get_string(provider, "VPN.MTU");

	if (mtu)
		connman_task_add_argument(task, "--mtu", (char *)mtu);

	connman_task_add_argument(task, "--syslog", NULL);

	connman_task_add_argument(task, "--script-security", "2");

	connman_task_add_argument(task, "--up",
					SCRIPTDIR "/openvpn-script");
	connman_task_add_argument(task, "--up-restart", NULL);

	connman_task_add_argument(task, "--setenv", NULL);
	connman_task_add_argument(task, "CONNMAN_BUSNAME",
					dbus_bus_get_unique_name(connection));

	connman_task_add_argument(task, "--setenv", NULL);
	connman_task_add_argument(task, "CONNMAN_INTERFACE",
					CONNMAN_TASK_INTERFACE);

	connman_task_add_argument(task, "--setenv", NULL);
	connman_task_add_argument(task, "CONNMAN_PATH",
					connman_task_get_path(task));

	connman_task_add_argument(task, "--dev", if_name);
	connman_task_add_argument(task, "--dev-type", "tun");

	connman_task_add_argument(task, "--tls-client", NULL);
	connman_task_add_argument(task, "--remote", (char *)vpnhost);
	connman_task_add_argument(task, "--nobind", NULL);
	connman_task_add_argument(task, "--persist-key", NULL);
	connman_task_add_argument(task, "--persist-tun", NULL);

	connman_task_add_argument(task, "--route-noexec", NULL);
	connman_task_add_argument(task, "--ifconfig-noexec", NULL);

	/*
	 * Disable client restarts because we can't handle this at the
	 * moment. The problem is that when OpenVPN decides to switch
	 * from CONNECTED state to RECONNECTING and then to RESOLVE,
	 * it is not possible to do a DNS lookup. The DNS server is
	 * not accessable through the tunnel anymore and so we end up
	 * trying to resolve the OpenVPN servers address.
	 */
	connman_task_add_argument(task, "--ping-restart", "0");

	connman_task_add_argument(task, "--client", NULL);

	if (cafile) {
		connman_task_add_argument(task, "--ca",
						(char *)cafile);
	}

	if (certfile) {
		connman_task_add_argument(task, "--cert",
						(char *)certfile);
	}

	if (keyfile) {
		connman_task_add_argument(task, "--key",
						(char *)keyfile);
	}

	fd = fileno(stderr);
	err = connman_task_run(task, vpn_died, provider,
			NULL, &fd, &fd);
	if (err < 0) {
		connman_error("openvpn failed to start");
		return -EIO;
	}

	return 0;
}

static struct vpn_driver vpn_driver = {
	.notify	= ov_notify,
	.connect	= ov_connect,
};

static int openvpn_init(void)
{
	connection = connman_dbus_get_connection();

	return vpn_register("openvpn", &vpn_driver, OPENVPN);
}

static void openvpn_exit(void)
{
	vpn_unregister("openvpn");

	dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE(openvpn, "OpenVPN plugin", VERSION,
	CONNMAN_PLUGIN_PRIORITY_DEFAULT, openvpn_init, openvpn_exit)
