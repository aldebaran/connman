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

#include <string.h>
#include <errno.h>
#include <unistd.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/provider.h>
#include <connman/log.h>
#include <connman/task.h>

#include "vpn.h"

static int oc_notify(DBusMessage *msg, struct connman_provider *provider)
{
	DBusMessageIter iter, dict;
	struct oc_data *data;
	const char *reason, *key, *value;
	const char *domain = NULL;

	dbus_message_iter_init(msg, &iter);

	dbus_message_iter_get_basic(&iter, &reason);
	dbus_message_iter_next(&iter);

	if (!provider) {
		connman_error("No provider found");
		return VPN_STATE_FAILURE;
	}

	data = connman_provider_get_data(provider);
	if (!data) {
		DBG("provider %p no data", provider);
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
			connman_provider_set_string(provider, "Gateway", value);

		if (!strcmp(key, "INTERNAL_IP4_ADDRESS"))
			connman_provider_set_string(provider, "Address", value);

		if (!strcmp(key, "INTERNAL_IP4_NETMASK"))
			connman_provider_set_string(provider, "Netmask", value);

		if (!strcmp(key, "INTERNAL_IP4_DNS"))
			connman_provider_set_string(provider, "DNS", value);

		if (!strcmp(key, "CISCO_PROXY_PAC"))
			connman_provider_set_string(provider, "PAC", value);

		if (domain == NULL && !strcmp(key, "CISCO_DEF_DOMAIN"))
			domain = value;

		dbus_message_iter_next(&dict);
	}

	connman_provider_set_string(provider, "Domain", domain);

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

static struct vpn_driver vpn_driver = {
	.notify         = oc_notify,
	.connect	= oc_connect,
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
