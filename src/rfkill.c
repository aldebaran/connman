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
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#include "connman.h"

enum rfkill_type {
	RFKILL_TYPE_ALL = 0,
	RFKILL_TYPE_WLAN,
	RFKILL_TYPE_BLUETOOTH,
	RFKILL_TYPE_UWB,
	RFKILL_TYPE_WIMAX,
	RFKILL_TYPE_WWAN,
};

enum rfkill_operation {
	RFKILL_OP_ADD = 0,
	RFKILL_OP_DEL,
	RFKILL_OP_CHANGE,
	RFKILL_OP_CHANGE_ALL,
};

struct rfkill_event {
	uint32_t idx;
	uint8_t  type;
	uint8_t  op;
	uint8_t  soft;
	uint8_t  hard;
};

static gboolean rfkill_event(GIOChannel *chan,
				GIOCondition cond, gpointer data)
{
	unsigned char buf[32];
	struct rfkill_event *event = (void *) buf;
	char sysname[32];
	connman_bool_t blocked;
	gsize len;
	GIOError err;

	if (cond & (G_IO_NVAL | G_IO_HUP | G_IO_ERR))
		return FALSE;

	memset(buf, 0, sizeof(buf));

	err = g_io_channel_read(chan, (gchar *) buf, sizeof(buf), &len);
	if (err) {
		if (err == G_IO_ERROR_AGAIN)
			return TRUE;
		return FALSE;
	}

	if (len != sizeof(struct rfkill_event))
		return TRUE;

	DBG("idx %u type %u op %u soft %u hard %u",
					event->idx, event->type, event->op,
						event->soft, event->hard);

	snprintf(sysname, sizeof(sysname) - 1, "rfkill%d", event->idx);

	blocked = (event->soft || event->hard) ? TRUE : FALSE;

	switch (event->type) {
	case RFKILL_TYPE_ALL:
	case RFKILL_TYPE_WLAN:
		__connman_udev_rfkill(sysname, blocked);
		break;
	default:
		break;
	}

	return TRUE;
}

static GIOChannel *channel = NULL;

int __connman_rfkill_init(void)
{
	int fd;

	DBG("");

	fd = open("/dev/rfkill", O_RDWR);
	if (fd < 0) {
		connman_error("Failed to open RFKILL control device");
		return -EIO;
	}

	channel = g_io_channel_unix_new(fd);
	g_io_channel_set_close_on_unref(channel, TRUE);

	g_io_add_watch(channel, G_IO_IN | G_IO_NVAL | G_IO_HUP | G_IO_ERR,
							rfkill_event, NULL);

	return 0;
}

void __connman_rfkill_cleanup(void)
{
	DBG("");

	if (channel == NULL)
		return;

	g_io_channel_shutdown(channel, TRUE, NULL);
	g_io_channel_unref(channel);

	channel = NULL;
}
