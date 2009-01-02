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

#include <sys/types.h>

#define LIBUDEV_I_KNOW_THE_API_IS_SUBJECT_TO_CHANGE
#include <libudev.h>

#include <glib.h>

#include "connman.h"

#ifdef NEED_UDEV_DEVICE_GET_PARENT_WITH_DEVTYPE
static struct udev_device *udev_device_get_parent_with_devtype(struct udev_device *device,
								const char *devtype)
{
	return NULL;
}
#endif

#ifdef NEED_UDEV_ENUMERATE_ADD_MATCH_PROPERTY
static int udev_enumerate_add_match_property(struct udev_enumerate *enumerate,
					const char *property, const char *value)
{
	return 0;
}
#endif

static void print_properties(struct udev_device *device, const char *prefix)
{
	struct udev_list_entry *entry;

	entry = udev_device_get_properties_list_entry(device);
	while (entry) {
		const char *name = udev_list_entry_get_name(entry);
		const char *value = udev_list_entry_get_value(entry);

		if (g_str_has_prefix(name, "CONNMAN") == TRUE ||
				g_str_equal(name, "DEVNAME") == TRUE ||
					g_str_equal(name, "DEVPATH") == TRUE)
			connman_debug("%s%s = %s", prefix, name, value);

		entry = udev_list_entry_get_next(entry);
	}
}

static void print_device(struct udev_device *device, const char *action)
{
	struct udev_device *parent;

	connman_debug("=== %s ===", action);
	print_properties(device, "");

	parent = udev_device_get_parent_with_devtype(device, "usb_device");
	print_properties(parent, "    ");
}

static void enumerate_devices(struct udev *context)
{
	struct udev_enumerate *enumerate;
	struct udev_list_entry *entry;

	enumerate = udev_enumerate_new(context);
	if (enumerate == NULL)
		return;

	udev_enumerate_add_match_property(enumerate, "CONNMAN_TYPE", "?*");

	udev_enumerate_scan_devices(enumerate);

	entry = udev_enumerate_get_list_entry(enumerate);
	while (entry) {
		const char *syspath = udev_list_entry_get_name(entry);
		struct udev_device *device;

		device = udev_device_new_from_syspath(context, syspath);

		print_device(device, "coldplug");

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
	const char *action;

	device = udev_monitor_receive_device(monitor);
	if (device == NULL)
		return TRUE;

	action = udev_device_get_action(device);
	if (action == NULL)
		goto done;

	print_device(device, action);

done:
	udev_device_unref(device);

	return TRUE;
}

static struct udev *udev_ctx;
static struct udev_monitor *udev_mon;
static guint udev_watch = 0;

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

	udev_mon = udev_monitor_new_from_socket(udev_ctx,
						"@/org/moblin/connman/udev");
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
	DBG("");

	if (udev_watch > 0)
		g_source_remove(udev_watch);

	if (udev_ctx == NULL)
		return;

	udev_monitor_unref(udev_mon);
	udev_unref(udev_ctx);
}
