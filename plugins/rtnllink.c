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
#include <connman/element.h>
#include <connman/rtnl.h>
#include <connman/log.h>

#include "inet.h"

static GSList *device_list = NULL;

static void rtnllink_newlink(unsigned short type, int index,
					unsigned flags, unsigned change)
{
	enum connman_element_subtype subtype = CONNMAN_ELEMENT_SUBTYPE_UNKNOWN;
	struct connman_element *device;
	GSList *list;
	gboolean exists = FALSE;
	gchar *name, *devname;

	DBG("index %d", index);

	for (list = device_list; list; list = list->next) {
		struct connman_element *device = list->data;

		if (device->index == index) {
			exists = TRUE;
			break;
		}
	}

	if (exists == TRUE)
		return;

	name = inet_index2ident(index, "dev_");
	devname = inet_index2name(index);

	if (type == ARPHRD_ETHER) {
		char bridge_path[PATH_MAX], wimax_path[PATH_MAX];
		struct stat st;
		struct iwreq iwr;
		int sk;

		snprintf(bridge_path, PATH_MAX,
					"/sys/class/net/%s/bridge", name);
		snprintf(wimax_path, PATH_MAX,
					"/sys/class/net/%s/wimax", name);

		memset(&iwr, 0, sizeof(iwr));
		strncpy(iwr.ifr_ifrn.ifrn_name, devname, IFNAMSIZ);

		sk = socket(PF_INET, SOCK_DGRAM, 0);

		if (g_str_has_prefix(name, "bnep") == TRUE)
			subtype = CONNMAN_ELEMENT_SUBTYPE_UNKNOWN;
		else if (stat(bridge_path, &st) == 0 && (st.st_mode & S_IFDIR))
			subtype = CONNMAN_ELEMENT_SUBTYPE_UNKNOWN;
		else if (stat(wimax_path, &st) == 0 && (st.st_mode & S_IFDIR))
			subtype = CONNMAN_ELEMENT_SUBTYPE_WIMAX;
		else if (ioctl(sk, SIOCGIWNAME, &iwr) == 0)
			subtype = CONNMAN_ELEMENT_SUBTYPE_UNKNOWN;
		else
			subtype = CONNMAN_ELEMENT_SUBTYPE_ETHERNET;

		close(sk);
	}

	if (subtype == CONNMAN_ELEMENT_SUBTYPE_UNKNOWN) {
		g_free(name);
		return;
	}

	device = connman_element_create(NULL);
	device->type = CONNMAN_ELEMENT_TYPE_DEVICE;
	device->subtype = subtype;

	device->index = index;
	device->name = name;
	device->devname = devname;

	connman_element_register(device, NULL);
	device_list = g_slist_append(device_list, device);
}

static void rtnllink_dellink(unsigned short type, int index,
					unsigned flags, unsigned change)
{
	GSList *list;

	DBG("index %d", index);

	for (list = device_list; list; list = list->next) {
		struct connman_element *device = list->data;

		if (device->index == index) {
			device_list = g_slist_remove(device_list, device);
			connman_element_unregister(device);
			connman_element_unref(device);
			break;
		}
	}
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
		struct connman_element *device = list->data;

		connman_element_unregister(device);
		connman_element_unref(device);
	}

	g_slist_free(device_list);
	device_list = NULL;
}

CONNMAN_PLUGIN_DEFINE(rtnllink, "RTNL link detection plugin", VERSION,
						rtnllink_init, rtnllink_exit)
