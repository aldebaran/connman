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

#include <stdarg.h>
#include <sys/types.h>

#define LIBUDEV_I_KNOW_THE_API_IS_SUBJECT_TO_CHANGE
#include <libudev.h>

#include <glib.h>

#include "connman.h"

#ifdef NEED_UDEV_MONITOR_RECEIVE_DEVICE
static struct udev_device *udev_monitor_receive_device(struct udev_monitor *monitor);
{
	return udev_monitor_get_device(monitor);
}
#endif

#ifdef NEED_UDEV_DEVICE_GET_ACTION
static const char *udev_device_get_action(struct udev_device *device)
{
	return NULL;
}
#endif

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

	connman_debug("=== %s ===", action);

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
