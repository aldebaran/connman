/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2010  BMW Car IT GmbH. All rights reserved.
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
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
#include <connman/inet.h>

#include "vpn.h"

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

enum {
	OPT_STRING = 1,
	OPT_BOOL = 2,
};

struct {
	const char *cm_opt;
	const char *pptp_opt;
	const char *vpnc_default;
	int type;
} pptp_options[] = {
	{ "PPTP.User", "user", NULL, OPT_STRING },
	{ "PPTP.EchoFailure", "lcp-echo-failure", "0", OPT_STRING },
	{ "PPTP.EchoInterval", "lcp-echo-interval", "0", OPT_STRING },
	{ "PPTP.Debug", "debug", NULL, OPT_STRING },
	{ "PPTP.RefuseEAP", "refuse-eap", NULL, OPT_BOOL },
	{ "PPTP.RefusePAP", "refuse-pap", NULL, OPT_BOOL },
	{ "PPTP.RefuseCHAP", "refuse-chap", NULL, OPT_BOOL },
	{ "PPTP.RefuseMSCHAP", "refuse-mschap", NULL, OPT_BOOL },
	{ "PPTP.RefuseMSCHAP2", "refuse-mschapv2", NULL, OPT_BOOL },
	{ "PPTP.NoBSDComp", "nobsdcomp", NULL, OPT_BOOL },
	{ "PPTP.NoDeflate", "nodeflatey", NULL, OPT_BOOL },
	{ "PPTP.RequirMPPE", "require-mppe", NULL, OPT_BOOL },
	{ "PPTP.RequirMPPE40", "require-mppe-40", NULL, OPT_BOOL },
	{ "PPTP.RequirMPPE128", "require-mppe-128", NULL, OPT_BOOL },
	{ "PPTP.RequirMPPEStateful", "mppe-stateful", NULL, OPT_BOOL },
	{ "PPTP.NoVJ", "no-vj-comp", NULL, OPT_BOOL },
};

static DBusConnection *connection;

static DBusMessage *pptp_get_sec(struct connman_task *task,
				DBusMessage *msg, void *user_data)
{
	const char *user, *passwd;
	struct connman_provider *provider = user_data;
	DBusMessage *reply;

	if (dbus_message_get_no_reply(msg) == TRUE)
		return NULL;

	user = connman_provider_get_string(provider, "PPTP.User");
	passwd = connman_provider_get_string(provider, "PPTP.Password");
	if (user == NULL || strlen(user) == 0 ||
				passwd == NULL || strlen(passwd) == 0)
		return NULL;

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &user,
				DBUS_TYPE_STRING, &passwd,
				DBUS_TYPE_INVALID);
	return reply;
}

static int pptp_notify(DBusMessage *msg, struct connman_provider *provider)
{
	DBusMessageIter iter, dict;
	const char *reason, *key, *value;
	char *addressv4 = NULL, *netmask = NULL, *gateway = NULL;
	char *ifname = NULL, *nameservers = NULL;
	struct connman_ipaddress *ipaddress = NULL;

	dbus_message_iter_init(msg, &iter);

	dbus_message_iter_get_basic(&iter, &reason);
	dbus_message_iter_next(&iter);

	if (provider == NULL) {
		connman_error("No provider found");
		return VPN_STATE_FAILURE;
	}

	if (strcmp(reason, "auth failed") == 0)
		return VPN_STATE_AUTH_FAILURE;

	if (strcmp(reason, "connect"))
		return VPN_STATE_DISCONNECT;

	dbus_message_iter_recurse(&iter, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);
		dbus_message_iter_get_basic(&entry, &value);

		DBG("%s = %s", key, value);

		if (!strcmp(key, "INTERNAL_IP4_ADDRESS")) {
			connman_provider_set_string(provider, "Address", value);
			addressv4 = g_strdup(value);
		}

		if (!strcmp(key, "INTERNAL_IP4_NETMASK")) {
			connman_provider_set_string(provider, "Netmask", value);
			netmask = g_strdup(value);
		}

		if (!strcmp(key, "INTERNAL_IP4_DNS")) {
			connman_provider_set_string(provider, "DNS", value);
			nameservers = g_strdup(value);
		}

		if (!strcmp(key, "INTERNAL_IFNAME"))
			ifname = g_strdup(value);

		dbus_message_iter_next(&dict);
	}

	if (vpn_set_ifname(provider, ifname) < 0) {
		g_free(ifname);
		g_free(addressv4);
		g_free(netmask);
		g_free(nameservers);
		return VPN_STATE_FAILURE;
	}

	if (addressv4 != NULL)
		ipaddress = connman_ipaddress_alloc(AF_INET);

	g_free(ifname);

	if (ipaddress == NULL) {
		connman_error("No IP address for provider");
		g_free(addressv4);
		g_free(netmask);
		g_free(nameservers);
		return VPN_STATE_FAILURE;
	}

	value = connman_provider_get_string(provider, "Host");
	if (value != NULL) {
		connman_provider_set_string(provider, "Gateway", value);
		gateway = g_strdup(value);
	}

	if (addressv4 != NULL)
		connman_ipaddress_set_ipv4(ipaddress, addressv4, netmask,
					gateway);

	connman_provider_set_ipaddress(provider, ipaddress);
	connman_provider_set_nameservers(provider, nameservers);

	g_free(addressv4);
	g_free(netmask);
	g_free(gateway);
	g_free(nameservers);
	connman_ipaddress_free(ipaddress);

	return VPN_STATE_CONNECT;
}

static int pptp_save(struct connman_provider *provider, GKeyFile *keyfile)
{
	const char *option;
	int i;

	for (i = 0; i < (int)ARRAY_SIZE(pptp_options); i++) {
		if (strncmp(pptp_options[i].cm_opt, "PPTP.", 5) == 0) {
			option = connman_provider_get_string(provider,
							pptp_options[i].cm_opt);
			if (option == NULL)
				continue;

			g_key_file_set_string(keyfile,
					connman_provider_get_save_group(provider),
					pptp_options[i].cm_opt, option);
		}
	}
	return 0;
}

static void pptp_write_bool_option(struct connman_task *task,
				const char *key, const char *value)
{
	if (key != NULL && value != NULL) {
		if (strcmp(value, "yes") == 0)
			connman_task_add_argument(task, key, NULL);
	}
}

static int pptp_connect(struct connman_provider *provider,
		struct connman_task *task, const char *if_name)
{
	const char *opt_s, *host;
	char *str;
	int err, i;

	if (connman_task_set_notify(task, "getsec",
					pptp_get_sec, provider))
		return -ENOMEM;

	host = connman_provider_get_string(provider, "Host");
	if (host == NULL) {
		connman_error("Host not set; cannot enable VPN");
		return -EINVAL;
	}

	str = g_strdup_printf("%s %s --nolaunchpppd --loglevel 2",
				PPTP, host);
	if (str == NULL) {
		connman_error("can not allocate memory");
		return -ENOMEM;
	}

	connman_task_add_argument(task, "pty", str);
	g_free(str);

	connman_task_add_argument(task, "nodetach", NULL);
	connman_task_add_argument(task, "lock", NULL);
	connman_task_add_argument(task, "usepeerdns", NULL);
	connman_task_add_argument(task, "noipdefault", NULL);
	connman_task_add_argument(task, "noauth", NULL);
	connman_task_add_argument(task, "nodefaultroute", NULL);
	connman_task_add_argument(task, "ipparam", "pptp_plugin");

	for (i = 0; i < (int)ARRAY_SIZE(pptp_options); i++) {
		opt_s = connman_provider_get_string(provider,
					pptp_options[i].cm_opt);
		if (opt_s == NULL)
			opt_s = pptp_options[i].vpnc_default;

		if (opt_s == NULL)
			continue;

		if (pptp_options[i].type == OPT_STRING)
			connman_task_add_argument(task,
					pptp_options[i].pptp_opt, opt_s);
		else if (pptp_options[i].type == OPT_BOOL)
			pptp_write_bool_option(task,
					pptp_options[i].pptp_opt, opt_s);
	}

	connman_task_add_argument(task, "plugin",
				SCRIPTDIR "/libppp-plugin.so");

	err = connman_task_run(task, vpn_died, provider,
				NULL, NULL, NULL);
	if (err < 0) {
		connman_error("pptp failed to start");
		return -EIO;
	}

	return 0;
}

static int pptp_error_code(int exit_code)
{

	switch (exit_code) {
	case 1:
		return CONNMAN_PROVIDER_ERROR_CONNECT_FAILED;
	case 2:
		return CONNMAN_PROVIDER_ERROR_LOGIN_FAILED;
	case 16:
		return CONNMAN_PROVIDER_ERROR_AUTH_FAILED;
	default:
		return CONNMAN_PROVIDER_ERROR_UNKNOWN;
	}
}

static struct vpn_driver vpn_driver = {
	.flags		= VPN_FLAG_NO_TUN,
	.notify		= pptp_notify,
	.connect	= pptp_connect,
	.error_code     = pptp_error_code,
	.save		= pptp_save,
};

static int pptp_init(void)
{
	connection = connman_dbus_get_connection();

	return vpn_register("pptp", &vpn_driver, PPPD);
}

static void pptp_exit(void)
{
	vpn_unregister("pptp");

	dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE(pptp, "pptp plugin", VERSION,
	CONNMAN_PLUGIN_PRIORITY_DEFAULT, pptp_init, pptp_exit)
