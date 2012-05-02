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
#include <connman/ipconfig.h>
#include <connman/dbus.h>

#include "vpn.h"

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

static DBusConnection *connection;

enum {
	OPT_STRING = 1,
	OPT_BOOLEAN = 2,
};

struct {
	const char *cm_opt;
	const char *vpnc_opt;
	const char *vpnc_default;
	int type;
	connman_bool_t cm_save;
} vpnc_options[] = {
	{ "Host", "IPSec gateway", NULL, OPT_STRING, TRUE },
	{ "VPNC.IPSec.ID", "IPSec ID", NULL, OPT_STRING, TRUE },
	{ "VPNC.IPSec.Secret", "IPSec secret", NULL, OPT_STRING, FALSE },
	{ "VPNC.Xauth.Username", "Xauth username", NULL, OPT_STRING, FALSE },
	{ "VPNC.Xauth.Password", "Xauth password", NULL, OPT_STRING, FALSE },
	{ "VPNC.IKE.Authmode", "IKE Authmode", NULL, OPT_STRING, TRUE },
	{ "VPNC.IKE.DHGroup", "IKE DH Group", NULL, OPT_STRING, TRUE },
	{ "VPNC.PFS", "Perfect Forward Secrecy", NULL, OPT_STRING, TRUE },
	{ "VPNC.Domain", "Domain", NULL, OPT_STRING, TRUE },
	{ "VPNC.Vendor", "Vendor", NULL, OPT_STRING, TRUE },
	{ "VPNC.LocalPort", "Local Port", "0", OPT_STRING, TRUE, },
	{ "VPNC.CiscoPort","Cisco UDP Encapsulation Port", "0", OPT_STRING,
	  TRUE },
	{ "VPNC.AppVersion", "Application Version", NULL, OPT_STRING, TRUE },
	{ "VPNC.NATTMode", "NAT Traversal Mode", "cisco-udp", OPT_STRING,
	  TRUE },
	{ "VPNC.DPDTimeout", "DPD idle timeout (our side)", NULL, OPT_STRING,
	  TRUE },
	{ "VPNC.SingleDES", "Enable Single DES", NULL, OPT_BOOLEAN, TRUE },
	{ "VPNC.NoEncryption", "Enable no encryption", NULL, OPT_BOOLEAN,
	  TRUE },
};

static int vc_notify(DBusMessage *msg, struct connman_provider *provider)
{
	DBusMessageIter iter, dict;
	char *address = NULL, *netmask = NULL, *gateway = NULL;
	struct connman_ipaddress *ipaddress;
	const char *reason, *key, *value;

	dbus_message_iter_init(msg, &iter);

	dbus_message_iter_get_basic(&iter, &reason);
	dbus_message_iter_next(&iter);

	if (!provider) {
		connman_error("No provider found");
		return VPN_STATE_FAILURE;
	}

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

		if (!strcmp(key, "VPNGATEWAY"))
			gateway = g_strdup(value);

		if (!strcmp(key, "INTERNAL_IP4_ADDRESS"))
			address = g_strdup(value);

		if (!strcmp(key, "INTERNAL_IP4_NETMASK"))
			netmask = g_strdup(value);

		if (!strcmp(key, "INTERNAL_IP4_DNS"))
			connman_provider_set_nameservers(provider, value);

		if (!strcmp(key, "CISCO_DEF_DOMAIN"))
			connman_provider_set_domain(provider, value);

		if (g_str_has_prefix(key, "CISCO_SPLIT_INC") == TRUE ||
			g_str_has_prefix(key, "CISCO_IPV6_SPLIT_INC") == TRUE)
			connman_provider_append_route(provider, key, value);

		dbus_message_iter_next(&dict);
	}


	ipaddress = connman_ipaddress_alloc(AF_INET);
	if (ipaddress == NULL) {
		g_free(address);
		g_free(netmask);
		g_free(gateway);

		return VPN_STATE_FAILURE;
	}

	connman_ipaddress_set_ipv4(ipaddress, address, netmask, gateway);
	connman_provider_set_ipaddress(provider, ipaddress);

	g_free(address);
	g_free(netmask);
	g_free(gateway);
	connman_ipaddress_free(ipaddress);

	return VPN_STATE_CONNECT;
}

static ssize_t full_write(int fd, const void *buf, size_t len)
{
	ssize_t byte_write;

	while (len) {
		byte_write = write(fd, buf, len);
		if (byte_write < 0) {
			connman_error("failed to write config to vpnc: %s\n",
					strerror(errno));
			return byte_write;
		}
		len -= byte_write;
		buf += byte_write;
	}

	return 0;
}

static ssize_t write_option(int fd, const char *key, const char *value)
{
	gchar *buf;
	ssize_t ret = 0;

	if (key != NULL && value != NULL) {
		buf = g_strdup_printf("%s %s\n", key, value);
		ret = full_write(fd, buf, strlen(buf));

		g_free(buf);
	}

	return ret;
}

static ssize_t write_bool_option(int fd, const char *key, const char *value)
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

static int vc_write_config_data(struct connman_provider *provider, int fd)
{
	const char *opt_s;
	int i;

	for (i = 0; i < (int)ARRAY_SIZE(vpnc_options); i++) {
		opt_s = connman_provider_get_string(provider,
					vpnc_options[i].cm_opt);
		if (!opt_s)
			opt_s= vpnc_options[i].vpnc_default;

		if(!opt_s)
			continue;

		if (vpnc_options[i].type == OPT_STRING) {
			if (write_option(fd,
					vpnc_options[i].vpnc_opt, opt_s) < 0)
				return -EIO;
		} else if (vpnc_options[i].type == OPT_BOOLEAN) {
			if (write_bool_option(fd,
					vpnc_options[i].vpnc_opt, opt_s) < 0)
				return -EIO;
		}

	}

	return 0;
}

static int vc_save(struct connman_provider *provider, GKeyFile *keyfile)
{
	const char *option;
	int i;

	for (i = 0; i < (int)ARRAY_SIZE(vpnc_options); i++) {
		if (strncmp(vpnc_options[i].cm_opt, "VPNC.", 5) == 0) {

			if (vpnc_options[i].cm_save == FALSE)
				continue;

			option = connman_provider_get_string(provider,
							vpnc_options[i].cm_opt);
			if (option == NULL)
				continue;

			g_key_file_set_string(keyfile,
					connman_provider_get_save_group(provider),
					vpnc_options[i].cm_opt, option);
		}
	}
	return 0;
}

static int vc_connect(struct connman_provider *provider,
		struct connman_task *task, const char *if_name)
{
	const char *option;
	int err, fd;

	option = connman_provider_get_string(provider, "Host");
	if (option == NULL) {
		connman_error("Host not set; cannot enable VPN");
		return -EINVAL;
	}
	option = connman_provider_get_string(provider, "VPNC.IPSec.ID");
	if (option == NULL) {
		connman_error("Group not set; cannot enable VPN");
		return -EINVAL;
	}

	connman_task_add_argument(task, "--non-inter", NULL);
	connman_task_add_argument(task, "--no-detach", NULL);

	connman_task_add_argument(task, "--ifname", if_name);
	connman_task_add_argument(task, "--ifmode", "tun");

	connman_task_add_argument(task, "--script",
				SCRIPTDIR "/openconnect-script");

	option = connman_provider_get_string(provider, "VPNC.Debug");
	if (option != NULL)
		connman_task_add_argument(task, "--debug", option);

	connman_task_add_argument(task, "-", NULL);

	err = connman_task_run(task, vpn_died, provider,
				&fd, NULL, NULL);
	if (err < 0) {
		connman_error("vpnc failed to start");
		return -EIO;
	}

	err = vc_write_config_data(provider, fd);

	close(fd);

	return err;
}

static int vc_error_code(int exit_code)
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
	.notify		= vc_notify,
	.connect	= vc_connect,
	.error_code	= vc_error_code,
	.save		= vc_save,
};

static int vpnc_init(void)
{
	connection = connman_dbus_get_connection();

	return vpn_register("vpnc", &vpn_driver, VPNC);
}

static void vpnc_exit(void)
{
	vpn_unregister("vpnc");

	dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE(vpnc, "vpnc plugin", VERSION,
	CONNMAN_PLUGIN_PRIORITY_DEFAULT, vpnc_init, vpnc_exit)
