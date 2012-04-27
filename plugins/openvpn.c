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
#include <connman/ipconfig.h>

#include "vpn.h"

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

static DBusConnection *connection;

struct {
	const char *cm_opt;
	const char *ov_opt;
	char       has_value;
} ov_options[] = {
	{ "Host", "--remote", 1 },
	{ "OpenVPN.CACert", "--ca", 1 },
	{ "OpenVPN.Cert", "--cert", 1 },
	{ "OpenVPN.Key", "--key", 1 },
	{ "OpenVPN.MTU", "--mtu", 1 },
	{ "OpenVPN.Proto", "--proto", 1 },
	{ "OpenVPN.Port", "--port", 1 },
	{ "OpenVPN.AuthUserPass", "--auth-user-pass", 1 },
	{ "OpenVPN.TLSRemote", "--tls-remote", 1 },
	{ "OpenVPN.Cipher", "--cipher", 1 },
	{ "OpenVPN.Auth", "--auth", 1 },
	{ "OpenVPN.CompLZO", "--comp-lzo", 0 },
	{ "OpenVPN.RemoteCertTls", "--remote-cert-tls", 1 },
};

static void ov_append_dns_entries(const char *key, const char *value,
					char **dns_entries)
{
	gchar **options;

	if (g_str_has_prefix(key, "foreign_option_") == FALSE)
		return;

	options = g_strsplit(value, " ", 3);
	if (options[0] != NULL &&
		!strcmp(options[0], "dhcp-option") &&
			options[1] != NULL &&
			!strcmp(options[1], "DNS") &&
				options[2] != NULL) {

		if (*dns_entries != NULL) {
			char *tmp;

			tmp = g_strjoin(" ", *dns_entries,
						options[2], NULL);
			g_free(*dns_entries);
			*dns_entries = tmp;
		} else {
			*dns_entries = g_strdup(options[2]);
		}
	}

	g_strfreev(options);
}

static int ov_notify(DBusMessage *msg, struct connman_provider *provider)
{
	DBusMessageIter iter, dict;
	const char *reason, *key, *value;
	char *nameservers = NULL;
	char *address = NULL, *gateway = NULL, *peer = NULL;
	struct connman_ipaddress *ipaddress;

	dbus_message_iter_init(msg, &iter);

	dbus_message_iter_get_basic(&iter, &reason);
	dbus_message_iter_next(&iter);

	if (!provider) {
		connman_error("No provider found");
		return VPN_STATE_FAILURE;
	}

	if (strcmp(reason, "up"))
		return VPN_STATE_DISCONNECT;

	dbus_message_iter_recurse(&iter, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);
		dbus_message_iter_get_basic(&entry, &value);

		DBG("%s = %s", key, value);

		if (!strcmp(key, "trusted_ip")) {
			connman_provider_set_string(provider, "Gateway", value);
			gateway = g_strdup(value);
		}

		if (!strcmp(key, "ifconfig_local")) {
			connman_provider_set_string(provider, "Address", value);
			address = g_strdup(value);
		}

		if (!strcmp(key, "ifconfig_remote")) {
			connman_provider_set_string(provider, "Peer", value);
			peer = g_strdup(value);
		}

		if (g_str_has_prefix(key, "route_") == TRUE)
			connman_provider_append_route(provider, key, value);

		ov_append_dns_entries(key, value, &nameservers);

		dbus_message_iter_next(&dict);
	}

	ipaddress = connman_ipaddress_alloc(AF_INET);
	if (ipaddress == NULL) {
		g_free(nameservers);
		g_free(address);
		g_free(gateway);
		g_free(peer);

		return VPN_STATE_FAILURE;
	}

	connman_ipaddress_set_ipv4(ipaddress, address, NULL, gateway);
	connman_ipaddress_set_peer(ipaddress, peer);
	connman_provider_set_ipaddress(provider, ipaddress);

	connman_provider_set_nameservers(provider, nameservers);

	g_free(nameservers);
	g_free(address);
	g_free(gateway);
	g_free(peer);
	connman_ipaddress_free(ipaddress);

	return VPN_STATE_CONNECT;
}

static int ov_save(struct connman_provider *provider, GKeyFile *keyfile)
{
	const char *option;
	int i;

	for (i = 0; i < (int)ARRAY_SIZE(ov_options); i++) {
		if (strncmp(ov_options[i].cm_opt, "OpenVPN.", 8) == 0) {
			option = connman_provider_get_string(provider,
							ov_options[i].cm_opt);
			if (option == NULL)
				continue;

			g_key_file_set_string(keyfile,
					connman_provider_get_save_group(provider),
					ov_options[i].cm_opt, option);
		}
	}
	return 0;
}

static int task_append_config_data(struct connman_provider *provider,
					struct connman_task *task)
{
	const char *option;
	int i;

	for (i = 0; i < (int)ARRAY_SIZE(ov_options); i++) {
		option = connman_provider_get_string(provider,
					ov_options[i].cm_opt);
		if (option == NULL)
			continue;

		if (connman_task_add_argument(task,
					ov_options[i].ov_opt,
					ov_options[i].has_value ? option : NULL) < 0) {
			return -EIO;
		}
	}

	return 0;
}

static int ov_connect(struct connman_provider *provider,
		struct connman_task *task, const char *if_name)
{
	const char *option;
	int err, fd;

	option = connman_provider_get_string(provider, "Host");
	if (option == NULL) {
		connman_error("Host not set; cannot enable VPN");
		return -EINVAL;
	}

	task_append_config_data(provider, task);

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
	.save		= ov_save,
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
