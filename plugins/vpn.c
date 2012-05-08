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

#define _GNU_SOURCE
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdio.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <linux/if_tun.h>
#include <net/if.h>

#include <dbus/dbus.h>

#include <glib/gprintf.h>

#include <connman/provider.h>
#include <connman/log.h>
#include <connman/rtnl.h>
#include <connman/task.h>
#include <connman/inet.h>

#include "vpn.h"

struct vpn_data {
	struct connman_provider *provider;
	char *if_name;
	unsigned flags;
	unsigned int watch;
	unsigned int state;
	struct connman_task *task;
};

struct vpn_driver_data {
	const char *name;
	const char *program;
	struct vpn_driver *vpn_driver;
	struct connman_provider_driver provider_driver;
};

GHashTable *driver_hash = NULL;

static int stop_vpn(struct connman_provider *provider)
{
	struct vpn_data *data = connman_provider_get_data(provider);
	struct vpn_driver_data *vpn_driver_data;
	const char *name;
	struct ifreq ifr;
	int fd, err;

	if (data == NULL)
		return -EINVAL;

	name = connman_provider_get_driver_name(provider);
	if (name == NULL)
		return -EINVAL;

	vpn_driver_data = g_hash_table_lookup(driver_hash, name);

	if (vpn_driver_data != NULL && vpn_driver_data->vpn_driver != NULL &&
			vpn_driver_data->vpn_driver->flags == VPN_FLAG_NO_TUN)
		return 0;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	sprintf(ifr.ifr_name, "%s", data->if_name);

	fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		err = -errno;
		connman_error("Failed to open /dev/net/tun to device %s: %s",
			      data->if_name, strerror(errno));
		return err;
	}

	if (ioctl(fd, TUNSETIFF, (void *)&ifr)) {
		err = -errno;
		connman_error("Failed to TUNSETIFF for device %s to it: %s",
			      data->if_name, strerror(errno));
		close(fd);
		return err;
	}

	if (ioctl(fd, TUNSETPERSIST, 0)) {
		err = -errno;
		connman_error("Failed to set tun device %s nonpersistent: %s",
			      data->if_name, strerror(errno));
		close(fd);
		return err;
	}
	close(fd);
	DBG("Killed tun device %s", data->if_name);
	return 0;
}

void vpn_died(struct connman_task *task, int exit_code, void *user_data)
{
	struct connman_provider *provider = user_data;
	struct vpn_data *data = connman_provider_get_data(provider);
	int state = VPN_STATE_FAILURE;
	enum connman_provider_error ret;

	DBG("provider %p data %p", provider, data);

	if (data == NULL)
		goto vpn_exit;

	state = data->state;

	stop_vpn(provider);
	connman_provider_set_data(provider, NULL);

	if (data->watch != 0) {
		connman_provider_unref(provider);
		connman_rtnl_remove_watch(data->watch);
		data->watch = 0;
	}

vpn_exit:
	if (state != VPN_STATE_READY && state != VPN_STATE_DISCONNECT) {
		const char *name;
		struct vpn_driver_data *vpn_data = NULL;

		name = connman_provider_get_driver_name(provider);
		if (name != NULL)
			vpn_data = g_hash_table_lookup(driver_hash, name);

		if (vpn_data != NULL &&
				vpn_data->vpn_driver->error_code != NULL)
			ret = vpn_data->vpn_driver->error_code(exit_code);
		else
			ret = CONNMAN_PROVIDER_ERROR_UNKNOWN;

		connman_provider_indicate_error(provider, ret);
	} else
		connman_provider_set_state(provider,
						CONNMAN_PROVIDER_STATE_IDLE);

	connman_provider_set_index(provider, -1);

	if (data != NULL) {
		connman_provider_unref(data->provider);
		g_free(data->if_name);
		g_free(data);
	}

	connman_task_destroy(task);
}

int vpn_set_ifname(struct connman_provider *provider, const char *ifname)
{
	struct vpn_data *data = connman_provider_get_data(provider);
	int index;

	if (ifname == NULL || data == NULL)
		return  -EIO;

	index = connman_inet_ifindex(ifname);
	if (index < 0)
		return  -EIO;

	if (data->if_name != NULL)
		g_free(data->if_name);

	data->if_name = (char *)g_strdup(ifname);
	connman_provider_set_index(provider, index);

	return 0;
}

static void vpn_newlink(unsigned flags, unsigned change, void *user_data)
{
	struct connman_provider *provider = user_data;
	struct vpn_data *data = connman_provider_get_data(provider);

	if ((data->flags & IFF_UP) != (flags & IFF_UP)) {
		if (flags & IFF_UP) {
			data->state = VPN_STATE_READY;
			connman_provider_set_state(provider,
					CONNMAN_PROVIDER_STATE_READY);
		}
	}
	data->flags = flags;
}

static DBusMessage *vpn_notify(struct connman_task *task,
			DBusMessage *msg, void *user_data)
{
	struct connman_provider *provider = user_data;
	struct vpn_data *data;
	struct vpn_driver_data *vpn_driver_data;
	const char *name;
	int state, index;

	data = connman_provider_get_data(provider);

	name = connman_provider_get_driver_name(provider);
	if (name == NULL)
		return NULL;

	vpn_driver_data = g_hash_table_lookup(driver_hash, name);
	if (vpn_driver_data == NULL)
		return NULL;

	state = vpn_driver_data->vpn_driver->notify(msg, provider);
	switch (state) {
	case VPN_STATE_CONNECT:
	case VPN_STATE_READY:
		index = connman_provider_get_index(provider);
		connman_provider_ref(provider);
		data->watch = connman_rtnl_add_newlink_watch(index,
						     vpn_newlink, provider);
		connman_inet_ifup(index);
		break;

	case VPN_STATE_UNKNOWN:
	case VPN_STATE_IDLE:
	case VPN_STATE_DISCONNECT:
	case VPN_STATE_FAILURE:
		connman_provider_set_state(provider,
					CONNMAN_PROVIDER_STATE_DISCONNECT);
		break;

	case VPN_STATE_AUTH_FAILURE:
		connman_provider_indicate_error(provider,
					CONNMAN_PROVIDER_ERROR_AUTH_FAILED);
		break;
	}

	return NULL;
}

static int vpn_create_tun(struct connman_provider *provider)
{
	struct vpn_data *data = connman_provider_get_data(provider);
	struct ifreq ifr;
	int i, fd, index;
	int ret = 0;

	if (data == NULL)
		return -EISCONN;

	fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
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
	if (data->if_name == NULL) {
		connman_error("Failed to allocate memory");
		close(fd);
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
		stop_vpn(provider);
		ret = -EIO;
		goto exist_err;
	}
	connman_provider_set_index(provider, index);

	return 0;

exist_err:
	return ret;
}

static int vpn_connect(struct connman_provider *provider)
{
	struct vpn_data *data = connman_provider_get_data(provider);
	struct vpn_driver_data *vpn_driver_data;
	const char *name;
	int ret = 0;

	if (data != NULL)
		return -EISCONN;

	data = g_try_new0(struct vpn_data, 1);
	if (data == NULL)
		return -ENOMEM;

	data->provider = connman_provider_ref(provider);
	data->watch = 0;
	data->flags = 0;
	data->task = NULL;
	data->state = VPN_STATE_IDLE;

	connman_provider_set_data(provider, data);

	name = connman_provider_get_driver_name(provider);
	if (name == NULL)
		return -EINVAL;

	vpn_driver_data = g_hash_table_lookup(driver_hash, name);

	if (vpn_driver_data == NULL || vpn_driver_data->vpn_driver == NULL) {
		ret = -EINVAL;
		goto exist_err;
	}

	if (vpn_driver_data->vpn_driver->flags != VPN_FLAG_NO_TUN) {
		ret = vpn_create_tun(provider);
		if (ret < 0)
			goto exist_err;
	}

	data->task = connman_task_create(vpn_driver_data->program);

	if (data->task == NULL) {
		ret = -ENOMEM;
		stop_vpn(provider);
		goto exist_err;
	}

	if (connman_task_set_notify(data->task, "notify",
					vpn_notify, provider)) {
		ret = -ENOMEM;
		stop_vpn(provider);
		connman_task_destroy(data->task);
		data->task = NULL;
		goto exist_err;
	}

	ret = vpn_driver_data->vpn_driver->connect(provider, data->task,
							data->if_name);
	if (ret < 0) {
		stop_vpn(provider);
		connman_task_destroy(data->task);
		data->task = NULL;
		goto exist_err;
	}

	DBG("%s started with dev %s",
		vpn_driver_data->provider_driver.name, data->if_name);

	data->state = VPN_STATE_CONNECT;

	return -EINPROGRESS;

exist_err:
	connman_provider_set_index(provider, -1);
	connman_provider_set_data(provider, NULL);
	connman_provider_unref(data->provider);
	g_free(data->if_name);
	g_free(data);

	return ret;
}

static int vpn_probe(struct connman_provider *provider)
{
	return 0;
}

static int vpn_disconnect(struct connman_provider *provider)
{
	struct vpn_data *data = connman_provider_get_data(provider);
	struct vpn_driver_data *vpn_driver_data;
	const char *name;

	DBG("disconnect provider %p:", provider);

	if (data == NULL)
		return 0;

	name = connman_provider_get_driver_name(provider);
	if (name == NULL)
		return 0;

	vpn_driver_data = g_hash_table_lookup(driver_hash, name);
	if (vpn_driver_data->vpn_driver->disconnect)
		vpn_driver_data->vpn_driver->disconnect();

	if (data->watch != 0) {
		connman_provider_unref(provider);
		connman_rtnl_remove_watch(data->watch);
		data->watch = 0;
	}

	data->state = VPN_STATE_DISCONNECT;
	connman_task_stop(data->task);

	return 0;
}

static int vpn_remove(struct connman_provider *provider)
{
	struct vpn_data *data;

	data = connman_provider_get_data(provider);
	if (data == NULL)
		return 0;

	if (data->watch != 0) {
		connman_provider_unref(provider);
		connman_rtnl_remove_watch(data->watch);
		data->watch = 0;
	}

	connman_task_stop(data->task);

	g_usleep(G_USEC_PER_SEC);
	stop_vpn(provider);
	return 0;
}

static int vpn_save (struct connman_provider *provider, GKeyFile *keyfile)
{
	struct vpn_driver_data *vpn_driver_data;
	const char *name;

	name = connman_provider_get_driver_name(provider);
	vpn_driver_data = g_hash_table_lookup(driver_hash, name);
	if (vpn_driver_data != NULL &&
			vpn_driver_data->vpn_driver->save != NULL)
		return vpn_driver_data->vpn_driver->save(provider, keyfile);

	return 0;
}

int vpn_register(const char *name, struct vpn_driver *vpn_driver,
			const char *program)
{
	struct vpn_driver_data *data;

	data = g_try_new0(struct vpn_driver_data, 1);
	if (data == NULL)
		return -ENOMEM;

	data->name = name;
	data->program = program;

	data->vpn_driver = vpn_driver;

	data->provider_driver.name = name;
	data->provider_driver.disconnect = vpn_disconnect;
	data->provider_driver.connect = vpn_connect;
	data->provider_driver.probe = vpn_probe;
	data->provider_driver.remove = vpn_remove;
	data->provider_driver.save = vpn_save;

	if (driver_hash == NULL)
		driver_hash = g_hash_table_new_full(g_str_hash,
							g_str_equal,
							NULL, g_free);

	if (driver_hash == NULL) {
		connman_error("driver_hash not initialized for %s", name);
		g_free(data);
		return -ENOMEM;
	}

	g_hash_table_replace(driver_hash, (char *)name, data);

	connman_provider_driver_register(&data->provider_driver);

	return 0;
}

void vpn_unregister(const char *name)
{
	struct vpn_driver_data *data;

	data = g_hash_table_lookup(driver_hash, name);
	if (data == NULL)
		return;

	connman_provider_driver_unregister(&data->provider_driver);

	g_hash_table_remove(driver_hash, name);

	if (g_hash_table_size(driver_hash) == 0)
		g_hash_table_destroy(driver_hash);
}
