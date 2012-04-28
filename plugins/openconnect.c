/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2012  Intel Corporation. All rights reserved.
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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>

#include <glib.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/provider.h>
#include <connman/log.h>
#include <connman/task.h>
#include <connman/ipconfig.h>

#include "vpn.h"

static int oc_notify(DBusMessage *msg, struct connman_provider *provider)
{
	DBusMessageIter iter, dict;
	const char *reason, *key, *value;
	const char *domain = NULL;
	char *addressv4 = NULL, *addressv6 = NULL;
	char *netmask = NULL, *gateway = NULL;
	unsigned char prefix_len = 0;
	struct connman_ipaddress *ipaddress;

	dbus_message_iter_init(msg, &iter);

	dbus_message_iter_get_basic(&iter, &reason);
	dbus_message_iter_next(&iter);

	if (!provider) {
		connman_error("No provider found");
		return VPN_STATE_FAILURE;
	}

	if (strcmp(reason, "connect"))
		return VPN_STATE_DISCONNECT;

	domain = connman_provider_get_string(provider, "VPN.Domain");

	dbus_message_iter_recurse(&iter, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);
		dbus_message_iter_get_basic(&entry, &value);

		if (strcmp(key, "CISCO_CSTP_OPTIONS"))
			DBG("%s = %s", key, value);

		if (!strcmp(key, "VPNGATEWAY"))
			gateway = g_strdup(value);

		if (!strcmp(key, "INTERNAL_IP4_ADDRESS"))
			addressv4 = g_strdup(value);

		if (!strcmp(key, "INTERNAL_IP6_ADDRESS")) {
			addressv6 = g_strdup(value);
			prefix_len = 128;
		}

		if (!strcmp(key, "INTERNAL_IP4_NETMASK"))
			netmask = g_strdup(value);

		if (!strcmp(key, "INTERNAL_IP6_NETMASK")) {
			char *sep;

			/* The netmask contains the address and the prefix */
			sep = strchr(value, '/');
			if (sep != NULL) {
				unsigned char ip_len = sep - value;

				addressv6 = g_strndup(value, ip_len);
				prefix_len = (unsigned char)
						strtol(sep + 1, NULL, 10);
			}
		}

		if (!strcmp(key, "INTERNAL_IP4_DNS") ||
				!strcmp(key, "INTERNAL_IP6_DNS"))
			connman_provider_set_nameservers(provider, value);

		if (!strcmp(key, "CISCO_PROXY_PAC"))
			connman_provider_set_pac(provider, value);

		if (domain == NULL && !strcmp(key, "CISCO_DEF_DOMAIN"))
			domain = value;

		if (g_str_has_prefix(key, "CISCO_SPLIT_INC") == TRUE ||
			g_str_has_prefix(key, "CISCO_IPV6_SPLIT_INC") == TRUE)
			connman_provider_append_route(provider, key, value);

		dbus_message_iter_next(&dict);
	}

	DBG("%p %p", addressv4, addressv6);

	if (addressv4 != NULL)
		ipaddress = connman_ipaddress_alloc(AF_INET);
	else if (addressv6 != NULL)
		ipaddress = connman_ipaddress_alloc(AF_INET6);
	else
		ipaddress = NULL;

	if (ipaddress == NULL) {
		g_free(addressv4);
		g_free(addressv6);
		g_free(netmask);
		g_free(gateway);

		return VPN_STATE_FAILURE;
	}

	if (addressv4 != NULL)
		connman_ipaddress_set_ipv4(ipaddress, addressv4,
						netmask, gateway);
	else
		connman_ipaddress_set_ipv6(ipaddress, addressv6,
						prefix_len, gateway);
	connman_provider_set_ipaddress(provider, ipaddress);
	connman_provider_set_domain(provider, domain);

	g_free(addressv4);
	g_free(addressv6);
	g_free(netmask);
	g_free(gateway);
	connman_ipaddress_free(ipaddress);

	return VPN_STATE_CONNECT;
}

static int oc_connect(struct connman_provider *provider,
			struct connman_task *task, const char *if_name)
{
	const char *vpnhost, *vpncookie, *cafile, *certsha1, *mtu;
	int fd, err;

	vpnhost = connman_provider_get_string(provider, "Host");
	if (!vpnhost) {
		connman_error("Host not set; cannot enable VPN");
		return -EINVAL;
	}

	vpncookie = connman_provider_get_string(provider, "OpenConnect.Cookie");
	if (!vpncookie) {
		connman_error("OpenConnect.Cookie not set; cannot enable VPN");
		return -EINVAL;
	}

	certsha1 = connman_provider_get_string(provider,
						"OpenConnect.ServerCert");
	if (certsha1)
		connman_task_add_argument(task, "--servercert",
							(char *)certsha1);

	cafile = connman_provider_get_string(provider, "OpenConnect.CACert");
	mtu = connman_provider_get_string(provider, "VPN.MTU");

	if (cafile)
		connman_task_add_argument(task, "--cafile",
							(char *)cafile);
	if (mtu)
		connman_task_add_argument(task, "--mtu", (char *)mtu);

	connman_task_add_argument(task, "--syslog", NULL);
	connman_task_add_argument(task, "--cookie-on-stdin", NULL);

	connman_task_add_argument(task, "--script",
				  SCRIPTDIR "/openconnect-script");

	connman_task_add_argument(task, "--interface", if_name);

	connman_task_add_argument(task, (char *)vpnhost, NULL);

	err = connman_task_run(task, vpn_died, provider,
			       &fd, NULL, NULL);
	if (err < 0) {
		connman_error("openconnect failed to start");
		return -EIO;
	}

	if (write(fd, vpncookie, strlen(vpncookie)) !=
			(ssize_t)strlen(vpncookie) ||
			write(fd, "\n", 1) != 1) {
		connman_error("openconnect failed to take cookie on stdin");
		return -EIO;
	}

	return 0;
}

static int oc_save (struct connman_provider *provider, GKeyFile *keyfile)
{
	const char *setting;

	setting = connman_provider_get_string(provider,
					"OpenConnect.ServerCert");
	if (setting != NULL)
		g_key_file_set_string(keyfile,
				connman_provider_get_save_group(provider),
				"OpenConnect.ServerCert", setting);

	setting = connman_provider_get_string(provider,
					"OpenConnect.CACert");
	if (setting != NULL)
		g_key_file_set_string(keyfile,
				connman_provider_get_save_group(provider),
				"OpenConnect.CACert", setting);

	setting = connman_provider_get_string(provider,
					"VPN.MTU");
	if (setting != NULL)
		g_key_file_set_string(keyfile,
				connman_provider_get_save_group(provider),
				"VPN.MTU", setting);

	return 0;
}

static int oc_error_code(int exit_code)
{

	switch (exit_code) {
	case 1:
		return CONNMAN_PROVIDER_ERROR_CONNECT_FAILED;
	case 2:
		return CONNMAN_PROVIDER_ERROR_LOGIN_FAILED;
	default:
		return CONNMAN_PROVIDER_ERROR_UNKNOWN;
	}
}

static struct vpn_driver vpn_driver = {
	.notify         = oc_notify,
	.connect	= oc_connect,
	.error_code	= oc_error_code,
	.save		= oc_save,
};

static int openconnect_init(void)
{
	return vpn_register("openconnect", &vpn_driver, OPENCONNECT);
}

static void openconnect_exit(void)
{
	vpn_unregister("openconnect");
}

CONNMAN_PLUGIN_DEFINE(openconnect, "OpenConnect VPN plugin", VERSION,
	CONNMAN_PLUGIN_PRIORITY_DEFAULT, openconnect_init, openconnect_exit)
