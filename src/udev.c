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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include <libudev.h>

#include <glib.h>

#include "connman.h"

static gboolean rfkill_processing = FALSE;

static GSList *device_list = NULL;

static struct connman_device *find_device(int index)
{
	GSList *list;

	if (index < 0)
		return NULL;

	for (list = device_list; list; list = list->next) {
		struct connman_device *device = list->data;

		if (connman_device_get_index(device) == index)
			return device;
	}

	return NULL;
}

static enum connman_device_type string2devtype(const char *devtype)
{
	if (g_strcmp0(devtype, "wlan") == 0)
		return CONNMAN_DEVICE_TYPE_WIFI;
	else if (g_strcmp0(devtype, "wimax") == 0)
		return CONNMAN_DEVICE_TYPE_WIMAX;
	else if (g_strcmp0(devtype, "wwan") == 0)
		return CONNMAN_DEVICE_TYPE_CELLULAR;

	return CONNMAN_DEVICE_TYPE_UNKNOWN;
}

static enum connman_device_type get_device_type(
		struct udev_device *udev_device, int index)
{
	const char *devtype;

	devtype = udev_device_get_devtype(udev_device);
	if (devtype == NULL)
		return __connman_inet_get_device_type(index);

	return string2devtype(devtype);
}

static void add_net_device(struct udev_device *udev_device)
{
	struct udev_list_entry *entry;
	struct connman_device *device;
	enum connman_device_type devtype;
	const char *value, *systype;
	int index = -1;

	DBG("");

	systype = udev_device_get_sysattr_value(udev_device, "type");
	if (systype == NULL || atoi(systype) != 1)
		return;

	entry = udev_device_get_properties_list_entry(udev_device);
	while (entry) {
		const char *name = udev_list_entry_get_name(entry);

		if (g_str_has_prefix(name, "IFINDEX") == TRUE) {
			const char *value = udev_list_entry_get_value(entry);
			if (value != NULL)
				index = atoi(value);
		}

		entry = udev_list_entry_get_next(entry);
	}

	if (index < 0)
		return;

	devtype = get_device_type(udev_device, index);

	DBG("devtype %d", devtype);

	switch (devtype) {
	case CONNMAN_DEVICE_TYPE_UNKNOWN:
	case CONNMAN_DEVICE_TYPE_VENDOR:
	case CONNMAN_DEVICE_TYPE_WIMAX:
	case CONNMAN_DEVICE_TYPE_BLUETOOTH:
	case CONNMAN_DEVICE_TYPE_CELLULAR:
	case CONNMAN_DEVICE_TYPE_GPS:
		return;
	case CONNMAN_DEVICE_TYPE_ETHERNET:
	case CONNMAN_DEVICE_TYPE_WIFI:
		break;
	}

	device = find_device(index);
	if (device != NULL)
		return;

	device = connman_inet_create_device(index);
	if (device == NULL)
		return;

	value = udev_device_get_sysattr_value(udev_device, "phy80211/index");
	if (value != NULL)
		__connman_device_set_phyindex(device, atoi(value));

	if (connman_device_register(device) < 0) {
		connman_device_unref(device);
		return;
	}

	device_list = g_slist_append(device_list, device);
}

static void remove_net_device(struct udev_device *udev_device)
{
	struct udev_list_entry *entry;
	struct connman_device *device;
	int index = -1;

	DBG("");

	entry = udev_device_get_properties_list_entry(udev_device);
	while (entry) {
		const char *name = udev_list_entry_get_name(entry);

		if (g_str_has_prefix(name, "IFINDEX") == TRUE) {
			const char *value = udev_list_entry_get_value(entry);
			if (value != NULL)
				index = atoi(value);
		}

		entry = udev_list_entry_get_next(entry);
	}

	if (index < 0)
		return;

	device = find_device(index);
	if (device == NULL)
		return;

	device_list = g_slist_remove(device_list, device);

	connman_device_unregister(device);
	connman_device_unref(device);
}

static GSList *rfkill_list = NULL;

struct rfkill_data {
	int phyindex;
	connman_bool_t blocked;
};

connman_bool_t __connman_udev_get_blocked(int phyindex)
{
	GSList *list;

	if (phyindex < 0)
		return FALSE;

	for (list = rfkill_list; list; list = rfkill_list->next) {
		struct rfkill_data *block = list->data;

		if (block->phyindex == phyindex)
			return block->blocked;
	}

	return FALSE;
}

static void update_rfkill_state(int phyindex, connman_bool_t blocked)
{
	GSList *list;
	struct rfkill_data *block;

	DBG("index %d blocked %d", phyindex, blocked);

	for (list = rfkill_list; list; list = rfkill_list->next) {
		block = list->data;

		if (block->phyindex == phyindex) {
			block->blocked = blocked;
			return;
		}
	}

	block = g_try_new0(struct rfkill_data, 1);
	if (block == NULL)
		return;

	block->phyindex = phyindex;
	block->blocked = blocked;

	rfkill_list = g_slist_prepend(rfkill_list, block);
}

static void phyindex_rfkill(int phyindex, connman_bool_t blocked)
{
	GSList *list;

	if (phyindex < 0)
		return;

	update_rfkill_state(phyindex, blocked);

	for (list = device_list; list; list = list->next) {
		struct connman_device *device = list->data;

		if (__connman_device_get_phyindex(device) == phyindex)
			__connman_device_set_blocked(device, blocked);
	}
}

static void change_rfkill_device(struct udev_device *device)
{
	struct udev_device *parent;
	struct udev_list_entry *entry;
	connman_bool_t blocked;
	const char *value, *type = NULL;
	int state = -1;

	if (rfkill_processing == FALSE)
		return;

	entry = udev_device_get_properties_list_entry(device);
	while (entry) {
		const char *name = udev_list_entry_get_name(entry);

		if (g_str_has_prefix(name, "RFKILL_STATE") == TRUE) {
			value = udev_list_entry_get_value(entry);
			if (value != NULL)
				state = atoi(value);
		} else if (g_str_has_prefix(name, "RFKILL_TYPE") == TRUE)
			type = udev_list_entry_get_value(entry);

		entry = udev_list_entry_get_next(entry);
	}

	if (type == NULL || state < 0)
		return;

	if (g_str_equal(type, "wlan") == FALSE)
		return;

	parent = udev_device_get_parent(device);
	if (parent == NULL)
		return;

	value = udev_device_get_sysattr_value(parent, "index");
	if (value == NULL)
		return;

	blocked = (state != 1) ? TRUE : FALSE;

	phyindex_rfkill(atoi(value), blocked);
}

static void add_rfkill_device(struct udev_device *device)
{
	change_rfkill_device(device);
}

static void print_properties(struct udev_device *device, const char *prefix)
{
	struct udev_list_entry *entry;

	entry = udev_device_get_properties_list_entry(device);
	while (entry) {
		const char *name = udev_list_entry_get_name(entry);
		const char *value = udev_list_entry_get_value(entry);

		if (g_str_has_prefix(name, "CONNMAN") == TRUE ||
				g_str_has_prefix(name, "RFKILL") == TRUE ||
				g_str_has_prefix(name, "ID_MODEM") == TRUE ||
				g_str_equal(name, "ID_VENDOR") == TRUE ||
				g_str_equal(name, "ID_MODEL") == TRUE ||
				g_str_equal(name, "INTERFACE") == TRUE ||
				g_str_equal(name, "IFINDEX") == TRUE ||
				g_str_equal(name, "DEVNAME") == TRUE ||
				g_str_equal(name, "DEVPATH") == TRUE)
			DBG("%s%s = %s", prefix, name, value);

		entry = udev_list_entry_get_next(entry);
	}
}

static void print_device(struct udev_device *device, const char *action)
{
	const char *subsystem, *sysname, *driver, *devtype = NULL;
	struct udev_device *parent;

	DBG("=== %s ===", action);
	print_properties(device, "");

	parent = udev_device_get_parent(device);
	if (parent == NULL)
		return;

	subsystem = udev_device_get_subsystem(parent);

	if (subsystem != NULL &&
			g_str_equal(subsystem, "usb-serial") == TRUE) {
		subsystem = "usb";
		devtype = "usb_device";
	}

	parent = udev_device_get_parent_with_subsystem_devtype(device,
							subsystem, devtype);
	print_properties(parent, "    ");

	driver = udev_device_get_driver(device);
	if (driver == NULL) {
		driver = udev_device_get_driver(parent);
		if (driver == NULL)
			return;
	}

	devtype = udev_device_get_devtype(device);

	DBG("devtype %s", devtype);

	sysname = udev_device_get_sysname(device);

	driver = udev_device_get_driver(parent);
}

static void enumerate_devices(struct udev *context)
{
	struct udev_enumerate *enumerate;
	struct udev_list_entry *entry;

	enumerate = udev_enumerate_new(context);
	if (enumerate == NULL)
		return;

	udev_enumerate_add_match_subsystem(enumerate, "net");
	udev_enumerate_add_match_subsystem(enumerate, "rfkill");

	udev_enumerate_scan_devices(enumerate);

	entry = udev_enumerate_get_list_entry(enumerate);
	while (entry) {
		const char *syspath = udev_list_entry_get_name(entry);
		struct udev_device *device;

		device = udev_device_new_from_syspath(context, syspath);
		if (device != NULL) {
			const char *subsystem;

			print_device(device, "coldplug");

			subsystem = udev_device_get_subsystem(device);

			if (g_strcmp0(subsystem, "net") == 0)
				add_net_device(device);
			else if (g_strcmp0(subsystem, "rfkill") == 0)
				add_rfkill_device(device);

			udev_device_unref(device);
		}

		entry = udev_list_entry_get_next(entry);
	}

	udev_enumerate_unref(enumerate);
}

static gboolean udev_event(GIOChannel *channel,
				GIOCondition condition, gpointer user_data)
{
	struct udev_monitor *monitor = user_data;
	struct udev_device *device;
	const char *subsystem, *action;

	device = udev_monitor_receive_device(monitor);
	if (device == NULL)
		return TRUE;

	subsystem = udev_device_get_subsystem(device);
	if (subsystem == NULL)
		goto done;

	action = udev_device_get_action(device);
	if (action == NULL)
		goto done;

	print_device(device, action);

	if (g_str_equal(action, "add") == TRUE) {
		if (g_str_equal(subsystem, "net") == TRUE)
			add_net_device(device);
		else if (g_str_equal(subsystem, "rfkill") == TRUE)
			add_rfkill_device(device);
	} else if (g_str_equal(action, "remove") == TRUE) {
		if (g_str_equal(subsystem, "net") == TRUE)
			remove_net_device(device);
	} else if (g_str_equal(action, "change") == TRUE) {
		if (g_str_equal(subsystem, "rfkill") == TRUE)
			change_rfkill_device(device);
	}

done:
	udev_device_unref(device);

	return TRUE;
}

static struct udev *udev_ctx;
static struct udev_monitor *udev_mon;
static guint udev_watch = 0;

void __connman_udev_enable_rfkill_processing(void)
{
	rfkill_processing = TRUE;

	connman_warn("Enabling udev based RFKILL processing");

	enumerate_devices(udev_ctx);
}

char *__connman_udev_get_devtype(const char *ifname)
{
	struct udev_device *device;
	const char *devtype;

	device = udev_device_new_from_subsystem_sysname(udev_ctx,
							"net", ifname);
	if (device == NULL)
		return NULL;

	devtype = udev_device_get_devtype(device);
	if (devtype == NULL)
		goto done;

done:
	udev_device_unref(device);

	return NULL;
}

void __connman_udev_rfkill(const char *sysname, connman_bool_t blocked)
{
	struct udev_device *device, *parent;
	const char *value;

	device = udev_device_new_from_subsystem_sysname(udev_ctx,
							"rfkill", sysname);
	if (device == NULL)
		return;

	parent = udev_device_get_parent(device);
	if (parent == NULL)
		return;

	value = udev_device_get_sysattr_value(parent, "index");
	if (value == NULL)
		return;

	phyindex_rfkill(atoi(value), blocked);
}

int __connman_udev_init(void)
{
	DBG("");

	udev_ctx = udev_new();
	if (udev_ctx == NULL) {
		connman_error("Failed to create udev context");
		return -1;
	}

	udev_mon = udev_monitor_new_from_netlink(udev_ctx, "udev");
	if (udev_mon == NULL) {
		connman_error("Failed to create udev monitor");
		udev_unref(udev_ctx);
		udev_ctx = NULL;
		return -1;
	}

	udev_monitor_filter_add_match_subsystem_devtype(udev_mon,
							"net", NULL);
	udev_monitor_filter_add_match_subsystem_devtype(udev_mon,
							"rfkill", NULL);

	udev_monitor_filter_update(udev_mon);

	return 0;
}

void __connman_udev_start(void)
{
	GIOChannel *channel;
	int fd;

	DBG("");

	if (udev_monitor_enable_receiving(udev_mon) < 0) {
		connman_error("Failed to enable udev monitor");
		return;
	}

	enumerate_devices(udev_ctx);

	fd = udev_monitor_get_fd(udev_mon);

	channel = g_io_channel_unix_new(fd);
	if (channel == NULL)
		return;

	udev_watch = g_io_add_watch(channel, G_IO_IN, udev_event, udev_mon);

	g_io_channel_unref(channel);
}

void __connman_udev_cleanup(void)
{
	GSList *list;

	DBG("");

	if (udev_watch > 0)
		g_source_remove(udev_watch);

	for (list = device_list; list; list = list->next) {
		struct connman_device *device = list->data;

		connman_device_unregister(device);
		connman_device_unref(device);
	}

	g_slist_free(device_list);
	device_list = NULL;

	for (list = rfkill_list; list; list = list->next) {
		struct rfkill_data *block = list->data;
		g_free(block);
	}

	g_slist_free(rfkill_list);
	rfkill_list = NULL;

	if (udev_ctx == NULL)
		return;

	udev_monitor_filter_remove(udev_mon);

	udev_monitor_unref(udev_mon);
	udev_unref(udev_ctx);
}
