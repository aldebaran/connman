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
	RFKILL_TYPE_GPS,
	RFKILL_TYPE_FM,
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

static enum connman_service_type convert_type(uint8_t type)
{
	switch (type) {
	case RFKILL_TYPE_WLAN:
		return CONNMAN_SERVICE_TYPE_WIFI;
	case RFKILL_TYPE_BLUETOOTH:
		return CONNMAN_SERVICE_TYPE_BLUETOOTH;
	case RFKILL_TYPE_WIMAX:
		return CONNMAN_SERVICE_TYPE_WIMAX;
	case RFKILL_TYPE_WWAN:
		return CONNMAN_SERVICE_TYPE_CELLULAR;
	}

	return CONNMAN_SERVICE_TYPE_UNKNOWN;
}

static GIOStatus rfkill_process(GIOChannel *chan)
{
	GIOStatus status = G_IO_STATUS_NORMAL;
	unsigned char buf[32];
	struct rfkill_event *event = (void *) buf;
	enum connman_service_type type;
	gsize len;

	DBG("");

	memset(buf, 0, sizeof(buf));

	status = g_io_channel_read_chars(chan, (gchar *) buf,
			sizeof(struct rfkill_event), &len, NULL);

	if (status != G_IO_STATUS_NORMAL)
		return status;

	if (len != sizeof(struct rfkill_event))
		return status;

	DBG("idx %u type %u op %u soft %u hard %u", event->idx,
						event->type, event->op,
						event->soft, event->hard);

	switch (event->op) {
	case RFKILL_OP_ADD:
		type = convert_type(event->type);
		__connman_technology_add_rfkill(event->idx, type,
						event->soft, event->hard);
		break;
	case RFKILL_OP_DEL:
		__connman_technology_remove_rfkill(event->idx);
		break;
	case RFKILL_OP_CHANGE:
		__connman_technology_update_rfkill(event->idx, event->soft,
								event->hard);
		break;
	default:
		break;
	}

	return status;
}

static gboolean rfkill_event(GIOChannel *chan,
				GIOCondition cond, gpointer data)
{
	if (cond & (G_IO_NVAL | G_IO_HUP | G_IO_ERR))
		return FALSE;

	if (rfkill_process(chan) == G_IO_STATUS_ERROR)
		return FALSE;

	return TRUE;
}

static GIOChannel *channel = NULL;

int __connman_rfkill_init(void)
{
	GIOFlags flags;
	int fd;

	DBG("");

	fd = open("/dev/rfkill", O_RDWR);
	if (fd < 0) {
		connman_error("Failed to open RFKILL control device");
		return -EIO;
	}

	channel = g_io_channel_unix_new(fd);
	g_io_channel_set_close_on_unref(channel, TRUE);

	flags = g_io_channel_get_flags(channel);
	flags |= G_IO_FLAG_NONBLOCK;
	g_io_channel_set_flags(channel, flags, NULL);

	/* Process current RFKILL events sent on device open */
	while (rfkill_process(channel) == G_IO_STATUS_NORMAL);

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
