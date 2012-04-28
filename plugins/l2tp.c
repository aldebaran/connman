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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

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

enum {
	OPT_ALL = 1,
	OPT_L2G = 2,
	OPT_L2	= 3,
	OPT_PPPD = 4,
};

struct {
	const char *cm_opt;
	const char *pppd_opt;
	int sub;
	const char *vpn_default;
	int type;
} pppd_options[] = {
	{ "L2TP.User", "name", OPT_ALL, NULL, OPT_STRING },
	{ "L2TP.BPS", "bps", OPT_L2, NULL, OPT_STRING },
	{ "L2TP.LengthBit", "length bit", OPT_L2, NULL, OPT_STRING },
	{ "L2TP.Challenge", "challenge", OPT_L2, NULL, OPT_STRING },
	{ "L2TP.DefaultRoute", "defaultroute", OPT_L2, NULL, OPT_STRING },
	{ "L2TP.FlowBit", "flow bit", OPT_L2, NULL, OPT_STRING },
	{ "L2TP.TunnelRWS", "tunnel rws", OPT_L2, NULL, OPT_STRING },
	{ "L2TP.Exclusive", "exclusive", OPT_L2, NULL, OPT_STRING },
	{ "L2TP.Autodial", "autodial", OPT_L2, "yes", OPT_STRING },
	{ "L2TP.Redial", "redial", OPT_L2, "yes", OPT_STRING },
	{ "L2TP.RedialTimeout", "redial timeout", OPT_L2, "10", OPT_STRING },
	{ "L2TP.MaxRedials", "max redials", OPT_L2, NULL, OPT_STRING },
	{ "L2TP.RequirePAP", "require pap", OPT_L2, "no", OPT_STRING },
	{ "L2TP.RequireCHAP", "require chap", OPT_L2, "yes", OPT_STRING },
	{ "L2TP.ReqAuth", "require authentication", OPT_L2, "no", OPT_STRING },
	{ "L2TP.AccessControl", "access control", OPT_L2G, "yes", OPT_STRING },
	{ "L2TP.AuthFile", "auth file", OPT_L2G, NULL, OPT_STRING },
	{ "L2TP.ForceUserSpace", "force userspace", OPT_L2G, NULL, OPT_STRING },
	{ "L2TP.ListenAddr", "listen-addr", OPT_L2G, NULL, OPT_STRING },
	{ "L2TP.Rand Source", "rand source", OPT_L2G, NULL, OPT_STRING },
	{ "L2TP.IPsecSaref", "ipsec saref", OPT_L2G, NULL, OPT_STRING },
	{ "L2TP.Port", "port", OPT_L2G, NULL, OPT_STRING },
	{ "L2TP.EchoFailure", "lcp-echo-failure", OPT_PPPD, "0", OPT_STRING },
	{ "L2TP.EchoInterval", "lcp-echo-interval", OPT_PPPD, "0", OPT_STRING },
	{ "L2TP.Debug", "debug", OPT_PPPD, NULL, OPT_STRING },
	{ "L2TP.RefuseEAP", "refuse-eap", OPT_PPPD, NULL, OPT_BOOL },
	{ "L2TP.RefusePAP", "refuse-pap", OPT_PPPD, NULL, OPT_BOOL },
	{ "L2TP.RefuseCHAP", "refuse-chap", OPT_PPPD, NULL, OPT_BOOL },
	{ "L2TP.RefuseMSCHAP", "refuse-mschap", OPT_PPPD, NULL, OPT_BOOL },
	{ "L2TP.RefuseMSCHAP2", "refuse-mschapv2", OPT_PPPD, NULL, OPT_BOOL },
	{ "L2TP.NoBSDComp", "nobsdcomp", OPT_PPPD, NULL, OPT_BOOL },
	{ "L2TP.NoPcomp", "nopcomp", OPT_PPPD, NULL, OPT_BOOL },
	{ "L2TP.UseAccomp", "accomp", OPT_PPPD, NULL, OPT_BOOL },
	{ "L2TP.NoDeflate", "nodeflatey", OPT_PPPD, NULL, OPT_BOOL },
	{ "L2TP.ReqMPPE", "require-mppe", OPT_PPPD, NULL, OPT_BOOL },
	{ "L2TP.ReqMPPE40", "require-mppe-40", OPT_PPPD, NULL, OPT_BOOL },
	{ "L2TP.ReqMPPE128", "require-mppe-128", OPT_PPPD, NULL, OPT_BOOL },
	{ "L2TP.ReqMPPEStateful", "mppe-stateful", OPT_PPPD, NULL, OPT_BOOL },
	{ "L2TP.NoVJ", "no-vj-comp", OPT_PPPD, NULL, OPT_BOOL },
};

static DBusConnection *connection;

static DBusMessage *l2tp_get_sec(struct connman_task *task,
			DBusMessage *msg, void *user_data)
{
	const char *user, *passwd;
	struct connman_provider *provider = user_data;

	if (dbus_message_get_no_reply(msg) == FALSE) {
		DBusMessage *reply;

		user = connman_provider_get_string(provider, "L2TP.User");
		passwd = connman_provider_get_string(provider, "L2TP.Password");

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

	return NULL;
}

static int l2tp_notify(DBusMessage *msg, struct connman_provider *provider)
{
	DBusMessageIter iter, dict;
	const char *reason, *key, *value;
	char *addressv4 = NULL, *netmask = NULL, *gateway = NULL;
	char *ifname = NULL, *nameservers = NULL;
	struct connman_ipaddress *ipaddress = NULL;

	dbus_message_iter_init(msg, &iter);

	dbus_message_iter_get_basic(&iter, &reason);
	dbus_message_iter_next(&iter);

	if (!provider) {
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

static int l2tp_save(struct connman_provider *provider, GKeyFile *keyfile)
{
	const char *option;
	int i;

	for (i = 0; i < (int)ARRAY_SIZE(pppd_options); i++) {
		if (strncmp(pppd_options[i].cm_opt, "L2TP.", 5) == 0) {
			option = connman_provider_get_string(provider,
							pppd_options[i].cm_opt);
			if (option == NULL)
				continue;

			g_key_file_set_string(keyfile,
					connman_provider_get_save_group(provider),
					pppd_options[i].cm_opt, option);
		}
	}
	return 0;
}

static ssize_t full_write(int fd, const void *buf, size_t len)
{
	ssize_t byte_write;

	while (len) {
		byte_write = write(fd, buf, len);
		if (byte_write < 0) {
			connman_error("failed to write config to l2tp: %s\n",
					strerror(errno));
			return byte_write;
		}
		len -= byte_write;
		buf += byte_write;
	}

	return 0;
}

static ssize_t l2tp_write_bool_option(int fd,
					const char *key, const char *value)
{
	gchar *buf;
	ssize_t ret = 0;

	if (key != NULL && value != NULL) {
		if (strcmp(value, "yes") == 0) {
			buf = g_strdup_printf("%s\n", key);
			ret = full_write(fd, buf, strlen(buf));

			g_free(buf);
		}
	}

	return ret;
}

static int l2tp_write_option(int fd, const char *key, const char *value)
{
	gchar *buf;
	ssize_t ret = 0;

	if (key != NULL) {
		if (value != NULL)
			buf = g_strdup_printf("%s %s\n", key, value);
		else
			buf = g_strdup_printf("%s\n", key);

		ret = full_write(fd, buf, strlen(buf));

		g_free(buf);
	}

	return ret;
}

static int l2tp_write_section(int fd, const char *key, const char *value)
{
	gchar *buf;
	ssize_t ret = 0;

	if (key != NULL && value != NULL) {
		buf = g_strdup_printf("%s = %s\n", key, value);
		ret = full_write(fd, buf, strlen(buf));

		g_free(buf);
	}

	return ret;
}

static int write_pppd_option(struct connman_provider *provider, int fd)
{
	int i;
	const char *opt_s;

	l2tp_write_option(fd, "nodetach", NULL);
	l2tp_write_option(fd, "lock", NULL);
	l2tp_write_option(fd, "usepeerdns", NULL);
	l2tp_write_option(fd, "noipdefault", NULL);
	l2tp_write_option(fd, "noauth", NULL);
	l2tp_write_option(fd, "nodefaultroute", NULL);
	l2tp_write_option(fd, "ipparam", "l2tp_plugin");

	for (i = 0; i < (int)ARRAY_SIZE(pppd_options); i++) {
		if (pppd_options[i].sub != OPT_ALL &&
			pppd_options[i].sub != OPT_PPPD)
			continue;

		opt_s = connman_provider_get_string(provider,
					pppd_options[i].cm_opt);
		if (!opt_s)
			opt_s = pppd_options[i].vpn_default;

		if (!opt_s)
			continue;

		if (pppd_options[i].type == OPT_STRING)
			l2tp_write_option(fd,
				pppd_options[i].pppd_opt, opt_s);
		else if (pppd_options[i].type == OPT_BOOL)
			l2tp_write_bool_option(fd,
				pppd_options[i].pppd_opt, opt_s);
	}

	l2tp_write_option(fd, "plugin",
				SCRIPTDIR "/libppp-plugin.so");

	return 0;
}


static int l2tp_write_fields(struct connman_provider *provider,
						int fd, int sub)
{
	int i;
	const char *opt_s;

	for (i = 0; i < (int)ARRAY_SIZE(pppd_options); i++) {
		if (pppd_options[i].sub != sub)
			continue;

		opt_s = connman_provider_get_string(provider,
					pppd_options[i].cm_opt);
		if (!opt_s)
			opt_s = pppd_options[i].vpn_default;

		if (!opt_s)
			continue;

		if (pppd_options[i].type == OPT_STRING)
			l2tp_write_section(fd,
				pppd_options[i].pppd_opt, opt_s);
		else if (pppd_options[i].type == OPT_BOOL)
			l2tp_write_bool_option(fd,
				pppd_options[i].pppd_opt, opt_s);
	}

	return 0;
}

static int l2tp_write_config(struct connman_provider *provider,
					const char *pppd_name, int fd)
{
	const char *option;

	l2tp_write_option(fd, "[global]", NULL);
	l2tp_write_fields(provider, fd, OPT_L2G);

	l2tp_write_option(fd, "[lac l2tp]", NULL);

	option = connman_provider_get_string(provider, "Host");
	l2tp_write_option(fd, "lns =", option);

	l2tp_write_fields(provider, fd, OPT_ALL);
	l2tp_write_fields(provider, fd, OPT_L2);

	l2tp_write_option(fd, "pppoptfile =", pppd_name);

	return 0;
}

static void l2tp_died(struct connman_task *task, int exit_code, void *user_data)
{
	char *conf_file;

	vpn_died(task, exit_code, user_data);

	conf_file = g_strdup_printf("/var/run/connman/connman-xl2tpd.conf");
	unlink(conf_file);
	g_free(conf_file);

	conf_file = g_strdup_printf("/var/run/connman/connman-ppp-option.conf");
	unlink(conf_file);
	g_free(conf_file);
}

static int l2tp_connect(struct connman_provider *provider,
		struct connman_task *task, const char *if_name)
{
	const char *host;
	char *l2tp_name, *pppd_name;
	int l2tp_fd, pppd_fd;
	int err;

	if (connman_task_set_notify(task, "getsec",
					l2tp_get_sec, provider))
		return -ENOMEM;

	host = connman_provider_get_string(provider, "Host");
	if (host == NULL) {
		connman_error("Host not set; cannot enable VPN");
		return -EINVAL;
	}

	l2tp_name = g_strdup_printf("/var/run/connman/connman-xl2tpd.conf");

	l2tp_fd = open(l2tp_name, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
	if (l2tp_fd < 0) {
		g_free(l2tp_name);
		connman_error("Error writing l2tp config");
		return -EIO;
	}

	pppd_name = g_strdup_printf("/var/run/connman/connman-ppp-option.conf");

	pppd_fd = open(pppd_name, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
	if (pppd_fd < 0) {
		connman_error("Error writing pppd config");
		g_free(l2tp_name);
		g_free(pppd_name);
		close(l2tp_fd);
		return -EIO;
	}

	l2tp_write_config(provider, pppd_name, l2tp_fd);

	write_pppd_option(provider, pppd_fd);

	connman_task_add_argument(task, "-D", NULL);
	connman_task_add_argument(task, "-c", l2tp_name);

	g_free(l2tp_name);
	g_free(pppd_name);

	err = connman_task_run(task, l2tp_died, provider,
				NULL, NULL, NULL);
	if (err < 0) {
		connman_error("l2tp failed to start");
		return -EIO;
	}

	return 0;
}

static int l2tp_error_code(int exit_code)
{
	switch (exit_code) {
	case 1:
		return CONNMAN_PROVIDER_ERROR_CONNECT_FAILED;
	default:
		return CONNMAN_PROVIDER_ERROR_UNKNOWN;
	}
}

static struct vpn_driver vpn_driver = {
	.flags		= VPN_FLAG_NO_TUN,
	.notify		= l2tp_notify,
	.connect	= l2tp_connect,
	.error_code	= l2tp_error_code,
	.save		= l2tp_save,
};

static int l2tp_init(void)
{
	connection = connman_dbus_get_connection();

	return vpn_register("l2tp", &vpn_driver, L2TP);
}

static void l2tp_exit(void)
{
	vpn_unregister("l2tp");

	dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE(l2tp, "l2tp plugin", VERSION,
	CONNMAN_PLUGIN_PRIORITY_DEFAULT, l2tp_init, l2tp_exit)
