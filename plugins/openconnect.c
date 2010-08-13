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
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdio.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <stdint.h>

#include <glib/garray.h>
#include <glib/gerror.h>
#include <glib/gmain.h>
#include <glib/gspawn.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/device.h>
#include <connman/element.h>
#include <connman/provider.h>
#include <connman/log.h>
#include <connman/element.h>
#include <connman/rtnl.h>
#include <connman/task.h>

#include "inet.h"

enum oc_state {
	OC_STATE_UNKNOWN       = 0,
	OC_STATE_IDLE          = 1,
	OC_STATE_CONNECT       = 2,
	OC_STATE_READY         = 3,
	OC_STATE_DISCONNECT    = 4,
	OC_STATE_FAILURE       = 5,
};

struct oc_data {
	struct connman_provider *provider;
	char *if_name;
	unsigned flags;
	unsigned int watch;
	unsigned int state;
	struct connman_task *task;
};

static int kill_tun(char *tun_name)
{
	struct ifreq ifr;
	int fd, err;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	sprintf(ifr.ifr_name, "%s", tun_name);

	fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0) {
		err = -errno;
		connman_error("Failed to open /dev/net/tun to device %s: %s",
			      tun_name, strerror(errno));
		return err;
	}

	if (ioctl(fd, TUNSETIFF, (void *)&ifr)) {
		err = -errno;
		connman_error("Failed to TUNSETIFF for device %s to it: %s",
			      tun_name, strerror(errno));
		close(fd);
		return err;
	}

	if (ioctl(fd, TUNSETPERSIST, 0)) {
		err = -errno;
		connman_error("Failed to set tun device %s nonpersistent: %s",
			      tun_name, strerror(errno));
		close(fd);
		return err;
	}
	close(fd);
	DBG("Killed tun device %s", tun_name);
	return 0;
}

static void openconnect_died(struct connman_task *task, void *user_data)
{
	struct connman_provider *provider = user_data;
	struct oc_data *data = connman_provider_get_data(provider);
	int state = data->state;

	DBG("provider %p data %p", provider, data);

	if (!data)
		goto oc_exit;

	kill_tun(data->if_name);
	connman_provider_set_data(provider, NULL);
	connman_rtnl_remove_watch(data->watch);
	connman_provider_unref(data->provider);
	g_free(data);

 oc_exit:
	if (state != OC_STATE_READY && state != OC_STATE_DISCONNECT)
		connman_provider_set_state(provider,
						CONNMAN_PROVIDER_STATE_FAILURE);
	else
		connman_provider_set_state(provider,
						CONNMAN_PROVIDER_STATE_IDLE);

	connman_provider_set_index(provider, -1);
	connman_task_destroy(task);
}

static void vpn_newlink(unsigned flags, unsigned change, void *user_data)
{
	struct connman_provider *provider = user_data;
	struct oc_data *data = connman_provider_get_data(provider);

	if ((data->flags & IFF_UP) != (flags & IFF_UP)) {
		if (flags & IFF_UP) {
			data->state = OC_STATE_READY;
			connman_provider_set_state(provider,
					CONNMAN_PROVIDER_STATE_READY);
		}
	}
	data->flags = flags;
}

static void openconnect_task_notify(struct connman_task *task,
				    DBusMessage *msg, void *user_data)
{
	DBusMessageIter iter, dict;
	struct connman_provider *provider = user_data;
	struct oc_data *data;
	const char *reason, *key, *value;
	const char *domain = NULL;
	int index;

	dbus_message_iter_init(msg, &iter);

	dbus_message_iter_get_basic(&iter, &reason);
	dbus_message_iter_next(&iter);

	if (!provider) {
		connman_error("No provider found");
		return;
	}

	data = connman_provider_get_data(provider);
	if (!data) {
		DBG("provider %p no data", provider);
		return;
	}

	if (strcmp(reason, "connect")) {
		connman_provider_set_state(provider,
					CONNMAN_PROVIDER_STATE_DISCONNECT);
		return;
	}

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

	index = connman_provider_get_index(provider);
	connman_provider_set_string(provider, "Domain", domain);
	data->watch = connman_rtnl_add_newlink_watch(index,
						     vpn_newlink, provider);

	connman_inet_ifup(index);
}

static int oc_connect(struct connman_provider *provider)
{
	struct oc_data *data = connman_provider_get_data(provider);
	struct ifreq ifr;
	int oc_fd, fd, i, index;
	const char *vpnhost, *vpncookie, *cafile, *mtu;
	int ret = 0;

	if (data != NULL)
		return -EISCONN;

	data = g_try_new0(struct oc_data, 1);
	if (data == NULL)
		return -ENOMEM;

	data->provider = connman_provider_ref(provider);
	data->watch = 0;
	data->flags = 0;
	data->task = NULL;
	data->state = OC_STATE_IDLE;

	connman_provider_set_data(provider, data);

	vpnhost = connman_provider_get_string(provider, "Host");
	if (!vpnhost) {
		connman_error("Host not set; cannot enable VPN");
		ret = -EINVAL;
		goto exist_err;
	}

	vpncookie = connman_provider_get_string(provider, "OpenConnect.Cookie");
	if (!vpncookie) {
		connman_error("OpenConnect.Cookie not set; cannot enable VPN");
		ret = -EINVAL;
		goto exist_err;
	}

	cafile = connman_provider_get_string(provider, "OpenConnect.CACert");
	mtu = connman_provider_get_string(provider, "VPN.MTU");

	fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0) {
		i = -errno;
		connman_error("Failed to open /dev/net/tun: %s",
			      strerror(errno));
		ret = i;
		goto exist_err;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	for (i = 0; i < 256; i++) {
		sprintf(ifr.ifr_name, "vpn%d", i);

		if (!ioctl(fd, TUNSETIFF, (void *)&ifr))
			break;
	}

	if (i == 256) {
		connman_error("Failed to find available tun device");
		close(fd);
		ret = -ENODEV;
		goto exist_err;
	}

	data->if_name = (char *)g_strdup(ifr.ifr_name);
	if (!data->if_name) {
		ret = -ENOMEM;
		goto exist_err;
	}

	if (ioctl(fd, TUNSETPERSIST, 1)) {
		i = -errno;
		connman_error("Failed to set tun persistent: %s",
			      strerror(errno));
		close(fd);
		ret = i;
		goto exist_err;
	}

	close(fd);

	index = connman_inet_ifindex(data->if_name);
	if (index < 0) {
		connman_error("Failed to get tun ifindex");
		kill_tun(data->if_name);
		ret = -EIO;
		goto exist_err;
	}
	connman_provider_set_index(provider, index);

	data->task = connman_task_create(OPENCONNECT);

	if (data->task == NULL) {
		ret = -ENOMEM;
		kill_tun(data->if_name);
		goto exist_err;
	}

	if (connman_task_set_notify(data->task, "notify",
					openconnect_task_notify, provider)) {
		ret = -ENOMEM;
		kill_tun(data->if_name);
		connman_task_destroy(data->task);
		data->task = NULL;
		goto exist_err;
	}

	if (cafile)
		connman_task_add_argument(data->task, "--cafile",
							(char *)cafile);
	if (mtu)
		connman_task_add_argument(data->task, "--mtu", (char *)mtu);

	connman_task_add_argument(data->task, "--syslog", NULL);
	connman_task_add_argument(data->task, "--cookie-on-stdin", NULL);

	connman_task_add_argument(data->task, "--script",
				  SCRIPTDIR "/openconnect-script");

	connman_task_add_argument(data->task, "--interface", data->if_name);

	connman_task_add_argument(data->task, (char *)vpnhost, NULL);

	ret = connman_task_run(data->task, openconnect_died, provider,
			       &oc_fd, NULL, NULL);
	if (ret) {
		connman_error("Openconnect failed to start");
		kill_tun(data->if_name);
		ret = -EIO;
		connman_task_destroy(data->task);
		data->task = NULL;
		goto exist_err;
	}

	DBG("openconnect started with dev %s", data->if_name);

	if (write(oc_fd, vpncookie, strlen(vpncookie)) !=
	    (ssize_t)strlen(vpncookie) ||
	    write(oc_fd, "\n", 1) != 1) {
		connman_error("openconnect failed to take cookie on stdin");
		connman_provider_set_data(provider, NULL);
		connman_task_stop(data->task);
		ret = -EIO;
		goto exist_err;
	}

	data->state = OC_STATE_CONNECT;

	return -EINPROGRESS;

 exist_err:
	connman_provider_set_index(provider, -1);
	connman_provider_set_data(provider, NULL);
	connman_provider_unref(data->provider);
	g_free(data);

	return ret;
}

static int oc_probe(struct connman_provider *provider)
{
	return 0;
}

static int oc_disconnect(struct connman_provider *provider)
{
	struct oc_data *data = connman_provider_get_data(provider);

	DBG("disconnect provider %p:", provider);

	if (data == NULL)
		return 0;

	if (data->watch != 0)
		connman_rtnl_remove_watch(data->watch);

	data->watch = 0;
	data->state = OC_STATE_DISCONNECT;
	connman_task_stop(data->task);

	return 0;
}

static int oc_remove(struct connman_provider *provider)
{
	struct oc_data *data;

	data = connman_provider_get_data(provider);
	connman_provider_set_data(provider, NULL);
	if (data == NULL)
		return 0;

	if (data->watch != 0)
		connman_rtnl_remove_watch(data->watch);
	data->watch = 0;
	connman_task_stop(data->task);

	g_usleep(G_USEC_PER_SEC);
	kill_tun(data->if_name);
	return 0;
}

static struct connman_provider_driver provider_driver = {
	.name		= "openconnect",
	.disconnect	= oc_disconnect,
	.connect	= oc_connect,
	.probe		= oc_probe,
	.remove		= oc_remove,
};

static int openconnect_init(void)
{
	connman_provider_driver_register(&provider_driver);

	return 0;
}

static void openconnect_exit(void)
{
	connman_provider_driver_unregister(&provider_driver);
}

CONNMAN_PLUGIN_DEFINE(openconnect, "OpenConnect VPN plugin", VERSION,
	CONNMAN_PLUGIN_PRIORITY_DEFAULT, openconnect_init, openconnect_exit)
