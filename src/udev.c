/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2009  Intel Corporation. All rights reserved.
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

#define LIBUDEV_I_KNOW_THE_API_IS_SUBJECT_TO_CHANGE
#include <libudev.h>

#include <glib.h>

#include "connman.h"

#ifdef NEED_UDEV_MONITOR_FILTER
#if 0
static int udev_monitor_filter_add_match_subsystem_devtype(struct udev_monitor *udev_monitor,
				const char *subsystem, const char *devtype)
{
	return -EINVAL;
}
static int udev_monitor_filter_update(struct udev_monitor *udev_monitor)
{
	return -EINVAL;
}
static int udev_monitor_filter_remove(struct udev_monitor *udev_monitor)
{
	return -EINVAL;
}
#endif
#endif

static GSList *device_list = NULL;

static struct connman_device *find_device(const char *interface)
{
	GSList *list;
	int index;

	if (interface == NULL)
		return NULL;

	index = connman_inet_ifindex(interface);
	if (index < 0)
		return NULL;

	for (list = device_list; list; list = list->next) {
		struct connman_device *device = list->data;

		if (connman_device_get_index(device) == index)
			return device;
	}

	return NULL;
}

static void add_device(struct udev_device *udev_device)
{
	struct connman_device *device;
	struct udev_list_entry *entry;
	const char *type, *interface = NULL;
	int index = -1;

	DBG("");

	type = udev_device_get_sysattr_value(udev_device, "type");
	if (atoi(type) != 1)
		return;

	entry = udev_device_get_properties_list_entry(udev_device);
	while (entry) {
		const char *name = udev_list_entry_get_name(entry);

		if (g_str_has_prefix(name, "IFINDEX") == TRUE) {
			const char *value = udev_list_entry_get_value(entry);
			if (value != NULL)
				index = atoi(value);
		} else if (g_str_has_prefix(name, "INTERFACE") == TRUE)
			interface = udev_list_entry_get_value(entry);

		entry = udev_list_entry_get_next(entry);
	}

	device = find_device(interface);
	if (device != NULL)
		return;

	if (index < 0 || interface == NULL)
		return;

	device = connman_inet_create_device(index);
	if (device == NULL)
		return;

	if (connman_device_register(device) < 0) {
		connman_device_unref(device);
		return;
	}

	device_list = g_slist_append(device_list, device);
}

static void remove_device(struct udev_device *udev_device)
{
	struct connman_device *device;
	struct udev_list_entry *entry;
	const char *interface = NULL;

	DBG("");

	entry = udev_device_get_properties_list_entry(udev_device);
	while (entry) {
		const char *name = udev_list_entry_get_name(entry);

		if (g_str_has_prefix(name, "INTERFACE") == TRUE)
			interface = udev_list_entry_get_value(entry);

		entry = udev_list_entry_get_next(entry);
	}

	device = find_device(interface);
	if (device == NULL)
		return;

	device_list = g_slist_remove(device_list, device);

	connman_device_unregister(device);
	connman_device_unref(device);
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
			connman_debug("%s%s = %s", prefix, name, value);

		entry = udev_list_entry_get_next(entry);
	}
}

static void print_device(struct udev_device *device, const char *action)
{
	const char *subsystem, *sysname, *driver, *devtype = NULL;
	struct udev_device *parent;

	connman_debug("=== %s ===", action);
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

	udev_enumerate_scan_devices(enumerate);

	entry = udev_enumerate_get_list_entry(enumerate);
	while (entry) {
		const char *syspath = udev_list_entry_get_name(entry);
		struct udev_device *device;

		device = udev_device_new_from_syspath(context, syspath);

		print_device(device, "coldplug");

		add_device(device);

		udev_device_unref(device);

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

	if (g_str_equal(subsystem, "net") == FALSE)
		goto done;

	action = udev_device_get_action(device);
	if (action == NULL)
		goto done;

	print_device(device, action);

	if (g_str_equal(action, "add") == TRUE)
		add_device(device);
	else if (g_str_equal(action, "remove") == TRUE)
		remove_device(device);

done:
	udev_device_unref(device);

	return TRUE;
}

static struct udev *udev_ctx;
static struct udev_monitor *udev_mon;
static guint udev_watch = 0;

char *__connman_udev_get_devtype(const char *ifname)
{
	struct udev_device *device;
	const char *devtype;
	char syspath[128];

	snprintf(syspath, sizeof(syspath) - 1, "/sys/class/net/%s", ifname);

	device = udev_device_new_from_syspath(udev_ctx, syspath);
	if (device == NULL)
		return NULL;

	devtype = udev_device_get_devtype(device);
	if (devtype == NULL)
		goto done;

done:
	udev_device_unref(device);

	return NULL;
}

char *__connman_udev_get_mbm_devnode(const char *ifname)
{
	struct udev_device *device, *parent, *control;
	const char *driver, *devpath1, *devpath2;
	char *devnode = NULL;

	device = udev_device_new_from_subsystem_sysname(udev_ctx,
							"net", ifname);
	if (device == NULL)
		return NULL;

	parent = udev_device_get_parent(device);
	if (parent == NULL)
		goto done;

	driver = udev_device_get_driver(parent);
	if (g_strcmp0(driver, "cdc_ether") != 0)
		goto done;

	parent = udev_device_get_parent_with_subsystem_devtype(device,
							"usb", "usb_device");
	if (parent == NULL)
		goto done;

	devpath1 = udev_device_get_devpath(parent);

	control = udev_device_new_from_subsystem_sysname(udev_ctx,
							"usb", "cdc-wdm0");
	if (control == NULL)
		goto done;

	parent = udev_device_get_parent_with_subsystem_devtype(control,
							"usb", "usb_device");
	if (parent == NULL)
		goto done;

	devpath2 = udev_device_get_devpath(parent);

	if (g_strcmp0(devpath1, devpath2) == 0)
		devnode = g_strdup(udev_device_get_devnode(control));

done:
	udev_device_unref(device);

	return devnode;
}

int __connman_udev_init(void)
{
	GIOChannel *channel;
	int fd;

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

	if (udev_monitor_enable_receiving(udev_mon) < 0) {
		connman_error("Failed to enable udev monitor");
		udev_unref(udev_ctx);
		udev_ctx = NULL;
		udev_monitor_unref(udev_mon);
		return -1;
	}

	enumerate_devices(udev_ctx);

	fd = udev_monitor_get_fd(udev_mon);

	channel = g_io_channel_unix_new(fd);
	if (channel == NULL)
		return 0;

	udev_watch = g_io_add_watch(channel, G_IO_IN, udev_event, udev_mon);

	g_io_channel_unref(channel);

	return 0;
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

	if (udev_ctx == NULL)
		return;

	udev_monitor_unref(udev_mon);
	udev_unref(udev_ctx);
}
