/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2008  Intel Corporation. All rights reserved.
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

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_arp.h>
#include <linux/wireless.h>

#include <connman/plugin.h>
#include <connman/device.h>
#include <connman/rtnl.h>
#include <connman/log.h>

#include "inet.h"

static GSList *device_list = NULL;

static struct connman_device *find_device(int index)
{
	GSList *list;

	for (list = device_list; list; list = list->next) {
		struct connman_device *device = list->data;

		if (connman_device_get_index(device) == index)
			return device;
	}

	return NULL;
}

static void rtnllink_newlink(unsigned short type, int index,
					unsigned flags, unsigned change)
{
	enum connman_device_type devtype = CONNMAN_DEVICE_TYPE_UNKNOWN;
	struct connman_device *device;
	gchar *name, *devname;

	DBG("index %d", index);

	device = find_device(index);
	if (device != NULL)
		return;

	devname = inet_index2name(index);

	if (type == ARPHRD_ETHER) {
		char bridge_path[PATH_MAX], wimax_path[PATH_MAX];
		struct stat st;
		struct iwreq iwr;
		int sk;

		snprintf(bridge_path, PATH_MAX,
					"/sys/class/net/%s/bridge", devname);
		snprintf(wimax_path, PATH_MAX,
					"/sys/class/net/%s/wimax", devname);

		memset(&iwr, 0, sizeof(iwr));
		strncpy(iwr.ifr_ifrn.ifrn_name, devname, IFNAMSIZ);

		sk = socket(PF_INET, SOCK_DGRAM, 0);

		if (g_str_has_prefix(devname, "bnep") == TRUE)
			devtype = CONNMAN_DEVICE_TYPE_UNKNOWN;
		else if (stat(bridge_path, &st) == 0 && (st.st_mode & S_IFDIR))
			devtype = CONNMAN_DEVICE_TYPE_UNKNOWN;
		else if (stat(wimax_path, &st) == 0 && (st.st_mode & S_IFDIR))
			devtype = CONNMAN_DEVICE_TYPE_WIMAX;
		else if (ioctl(sk, SIOCGIWNAME, &iwr) == 0)
			devtype = CONNMAN_DEVICE_TYPE_UNKNOWN;
		else
			devtype = CONNMAN_DEVICE_TYPE_ETHERNET;

		close(sk);
	}

	if (devtype == CONNMAN_DEVICE_TYPE_UNKNOWN) {
		g_free(devname);
		return;
	}

	name = inet_index2ident(index, "dev_");

	device = connman_device_create(name, devtype);
	if (device == NULL) {
		g_free(devname);
		g_free(name);
		return;
	}

	connman_device_set_index(device, index);
	connman_device_set_interface(device, devname);

	g_free(devname);
	g_free(name);

	if (connman_device_register(device) < 0) {
		connman_device_unref(device);
		return;
	}

	device_list = g_slist_append(device_list, device);
}

static void rtnllink_dellink(unsigned short type, int index,
					unsigned flags, unsigned change)
{
	struct connman_device *device;

	DBG("index %d", index);

	device = find_device(index);
	if (device == NULL)
		return;

	device_list = g_slist_remove(device_list, device);

	connman_device_unregister(device);
	connman_device_unref(device);
}

static struct connman_rtnl rtnllink_rtnl = {
	.name		= "rtnllink",
	.newlink	= rtnllink_newlink,
	.dellink	= rtnllink_dellink,
};

static int rtnllink_init(void)
{
	int err;

	err = connman_rtnl_register(&rtnllink_rtnl);
	if (err < 0)
		return err;

	connman_rtnl_send_getlink();

	return 0;
}

static void rtnllink_exit(void)
{
	GSList *list;

	connman_rtnl_unregister(&rtnllink_rtnl);

	for (list = device_list; list; list = list->next) {
		struct connman_device *device = list->data;

		connman_device_unregister(device);
		connman_device_unref(device);
	}

	g_slist_free(device_list);
	device_list = NULL;
}

CONNMAN_PLUGIN_DEFINE(rtnllink, "RTNL link detection plugin", VERSION,
						rtnllink_init, rtnllink_exit)
