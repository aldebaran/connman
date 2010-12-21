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

struct ov_route {
	char *host;
	char *netmask;
	char *gateway;
};

static void destroy_route(gpointer user_data)
{
	struct ov_route *route = user_data;

	g_free(route->host);
	g_free(route->netmask);
	g_free(route->gateway);
	g_free(route);
}

static void ov_provider_append_routes(gpointer key, gpointer value,
					gpointer user_data)
{
	struct ov_route *route = value;
	struct connman_provider *provider = user_data;

	connman_provider_append_route(provider, route->host, route->netmask,
					route->gateway);
}

static struct ov_route *ov_route_lookup(const char *key, const char *prefix_key,
					GHashTable *routes)
{
	unsigned long idx;
	const char *start;
	char *end;
	struct ov_route *route;

	if (g_str_has_prefix(key, prefix_key) == FALSE)
		return NULL;

	start = key + strlen(prefix_key);
	idx = g_ascii_strtoull(start, &end, 10);

	if (idx == 0 && start == end) {
		connman_error("string conversion failed %s", start);
		return NULL;
	}

	route = g_hash_table_lookup(routes, GINT_TO_POINTER(idx));
	if (route == NULL) {
		route = g_try_new0(struct ov_route, 1);
		if (route == NULL) {
			connman_error("out of memory");
			return NULL;
		}

		g_hash_table_replace(routes, GINT_TO_POINTER(idx),
						route);
	}

	return  route;
}

static void ov_append_route(const char *key, const char *value, GHashTable *routes)
{
	struct ov_route *route;

	/*
	 * OpenVPN pushes routing tupples (host, nw, gw) as several
	 * environment values, e.g.
	 *
	 * route_gateway_2 = 10.242.2.13
	 * route_netmask_2 = 255.255.0.0
	 * route_network_2 = 192.168.0.0
	 * route_gateway_1 = 10.242.2.13
	 * route_netmask_1 = 255.255.255.255
	 * route_network_1 = 10.242.2.1
	 *
	 * The hash table is used to group the separate environment
	 * variables together. It also makes sure all tupples are
	 * complete even when OpenVPN pushes the information in a
	 * wrong order (unlikely).
	 */

	route = ov_route_lookup(key, "route_network_", routes);
	if (route != NULL) {
		route->host = g_strdup(value);
		return;
	}

	route = ov_route_lookup(key, "route_netmask_", routes);
	if (route != NULL) {
		route->netmask = g_strdup(value);
		return;
	}

	route = ov_route_lookup(key, "route_gateway_", routes);
	if (route != NULL)
		route->gateway = g_strdup(value);
}

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
	const char *domain = NULL;
	char *dns_entries = NULL;
	GHashTable *routes;

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

	routes = g_hash_table_new_full(g_direct_hash, g_direct_equal,
					NULL, destroy_route);

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

		if (!strcmp(key, "ifconfig_remote"))
			connman_provider_set_string(provider, "Peer", value);

		ov_append_route(key, value, routes);

		ov_append_dns_entries(key, value, &dns_entries);

		dbus_message_iter_next(&dict);
	}

	if (dns_entries != NULL) {
		connman_provider_set_string(provider, "DNS", dns_entries);
		g_free(dns_entries);
	}

	g_hash_table_foreach(routes, ov_provider_append_routes, provider);

	g_hash_table_destroy(routes);

	return VPN_STATE_CONNECT;
}

static int ov_connect(struct connman_provider *provider,
		struct connman_task *task, const char *if_name)
{
	const char *vpnhost, *cafile, *mtu, *certfile, *keyfile;
	const char *proto, *port, *auth_user_pass;
	const char *tls_remote, *cipher, *auth, *comp_lzo;
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
	proto = connman_provider_get_string(provider, "OpenVPN.Proto");
	port = connman_provider_get_string(provider, "OpenVPN.Port");
	auth_user_pass = connman_provider_get_string(provider,
							"OpenVPN.AuthUserPass");
	tls_remote = connman_provider_get_string(provider, "OpenVPN.TLSRemote");
	cipher = connman_provider_get_string(provider, "OpenVPN.Cipher");
	auth = connman_provider_get_string(provider, "OpenVPN.Auth");
	comp_lzo = connman_provider_get_string(provider, "OpenVPN.CompLZO");

	if (mtu != NULL)
		connman_task_add_argument(task, "--mtu", (char *)mtu);

	if (proto != NULL)
		connman_task_add_argument(task, "--proto", (char *)proto);

	if (port != NULL)
		connman_task_add_argument(task, "--port", (char *)port);

	if (auth_user_pass != NULL) {
		connman_task_add_argument(task, "--auth-user-pass",
						(char *)auth_user_pass);
	}

	if (tls_remote != NULL) {
		connman_task_add_argument(task, "--tls-remote",
						(char *)tls_remote);
	}

	if (cipher != NULL)
		connman_task_add_argument(task, "--cipher", (char *)cipher);

	if (auth != NULL)
		connman_task_add_argument(task, "--auth", (char *)auth);

	if (comp_lzo)
		connman_task_add_argument(task, "--comp-lzo", (char *)comp_lzo);

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
