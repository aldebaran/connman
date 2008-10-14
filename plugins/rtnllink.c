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

#include <connman/plugin.h>
#include <connman/element.h>
#include <connman/rtnl.h>
#include <connman/log.h>

#include "inet.h"

static GStaticMutex device_mutex = G_STATIC_MUTEX_INIT;
static GSList *device_list = NULL;

static void rtnllink_newlink(unsigned short type, int index,
					unsigned flags, unsigned change)
{
	struct connman_element *device;
	enum connman_element_subtype subtype;
	GSList *list;
	gboolean exists = FALSE;
	gchar *name;

	DBG("index %d", index);

	g_static_mutex_lock(&device_mutex);

	for (list = device_list; list; list = list->next) {
		struct connman_element *device = list->data;

		if (device->index == index) {
			exists = TRUE;
			break;
		}
	}

	g_static_mutex_unlock(&device_mutex);

	if (exists == TRUE)
		return;

	name = inet_index2name(index);

	if (g_str_has_prefix(name, "eth") == TRUE)
		subtype = CONNMAN_ELEMENT_SUBTYPE_ETHERNET;
	else if (g_str_has_prefix(name, "wlan") == TRUE)
		subtype = CONNMAN_ELEMENT_SUBTYPE_WIFI;
	else if (g_str_has_prefix(name, "wmx") == TRUE)
		subtype = CONNMAN_ELEMENT_SUBTYPE_WIMAX;
	else if (g_str_has_prefix(name, "bnep") == TRUE)
		subtype = CONNMAN_ELEMENT_SUBTYPE_BLUETOOTH;
	else
		subtype = CONNMAN_ELEMENT_SUBTYPE_UNKNOWN;

	if (subtype == CONNMAN_ELEMENT_SUBTYPE_UNKNOWN) {
		g_free(name);
		return;
	}

	device = connman_element_create(NULL);
	device->type = CONNMAN_ELEMENT_TYPE_DEVICE;
	device->subtype = subtype;

	device->index = index;
	device->name = name;

	g_static_mutex_lock(&device_mutex);

	connman_element_register(device, NULL);
	device_list = g_slist_append(device_list, device);

	g_static_mutex_unlock(&device_mutex);
}

static void rtnllink_dellink(unsigned short type, int index,
					unsigned flags, unsigned change)
{
	GSList *list;

	DBG("index %d", index);

	g_static_mutex_lock(&device_mutex);

	for (list = device_list; list; list = list->next) {
		struct connman_element *device = list->data;

		if (device->index == index) {
			device_list = g_slist_remove(device_list, device);
			connman_element_unregister(device);
			connman_element_unref(device);
			break;
		}
	}

	g_static_mutex_unlock(&device_mutex);
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

	g_static_mutex_lock(&device_mutex);

	for (list = device_list; list; list = list->next) {
		struct connman_element *device = list->data;

		connman_element_unregister(device);
		connman_element_unref(device);
	}

	g_slist_free(device_list);
	device_list = NULL;

	g_static_mutex_unlock(&device_mutex);
}

CONNMAN_PLUGIN_DEFINE("rtnllink", "RTNL link detection plugin", VERSION,
						rtnllink_init, rtnllink_exit)
