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
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <termios.h>

#include <glib.h>

#include <connman/log.h>

#include "modem.h"

struct modem_data {
	char *device;
	GIOChannel *channel;
	guint watch;
	GSList *callbacks;
	GSList *commands;
	char buf[1024];
	int offset;
};

struct modem_callback {
	char *command;
	modem_cb_t function;
	void *user_data;
};

struct modem_cmd {
	char *cmd;
	char *arg;
	modem_cb_t callback;
	void *user_data;
};

static int send_command(struct modem_data *modem, struct modem_cmd *cmd)
{
	char *buf;
	int fd, err;

	if (cmd->arg == NULL) {
		DBG("AT%s", cmd->cmd);
		buf = g_strdup_printf("AT%s\r\n", cmd->cmd);
	} else {
		DBG("AT%s=%s", cmd->cmd, cmd->arg);
		buf = g_strdup_printf("AT%s=%s\r\n", cmd->cmd, cmd->arg);
	}

	fd = g_io_channel_unix_get_fd(modem->channel);
	err = write(fd, buf, strlen(buf));

	fsync(fd);

	g_free(buf);

	return err;
}

static int queue_command(struct modem_data *modem, struct modem_cmd *cmd)
{
	modem->commands = g_slist_append(modem->commands, cmd);

	if (g_slist_length(modem->commands) > 1)
		return 0;

	return send_command(modem, cmd);
}

struct modem_data *modem_create(const char *device)
{
	struct modem_data *modem;

	DBG("device %s", device);

	modem = g_try_new0(struct modem_data, 1);
	if (modem == NULL)
		return NULL;

	modem->device = g_strdup(device);

	DBG("modem %p", modem);

	return modem;
}

void modem_destroy(struct modem_data *modem)
{
	DBG("modem %p", modem);

	if (modem == NULL)
		return;

	g_free(modem->device);
	g_free(modem);
}

static gboolean modem_event(GIOChannel *channel,
				GIOCondition condition, gpointer user_data)
{
	struct modem_data *modem = user_data;
	struct modem_cmd *cmd;
	GSList *list;
	gsize len;
	GIOError err;

	if (condition & (G_IO_NVAL | G_IO_HUP | G_IO_ERR))
		return FALSE;

	err = g_io_channel_read(channel, modem->buf + modem->offset,
				sizeof(modem->buf) - modem->offset, &len);
	if (err) {
		if (err == G_IO_ERROR_AGAIN)
			return TRUE;
		return FALSE;
	}

	DBG("Read %zu bytes (offset %d)", len, modem->offset);

	if (g_str_has_suffix(modem->buf, "\r\n") == TRUE) {
		for (list = modem->callbacks; list; list = list->next) {
			struct modem_callback *callback = list->data;

			if (callback->function == NULL)
				continue;

			if (g_strrstr(modem->buf, callback->command) != NULL)
				callback->function(modem->buf,
							callback->user_data);
		}
	}

	if (g_strrstr(modem->buf, "\r\nERROR\r\n") == NULL &&
				g_strrstr(modem->buf, "\r\nOK\r\n") == NULL) {
		modem->offset += len;
		return TRUE;
	}

	memset(modem->buf, 0, sizeof(modem->buf));
	modem->offset = 0;

	cmd = g_slist_nth_data(modem->commands, 0);
	if (cmd == NULL)
		return TRUE;

	modem->commands = g_slist_remove(modem->commands, cmd);

	DBG("AT%s", cmd->cmd);

	if (cmd->callback)
		cmd->callback(modem->buf, cmd->user_data);

	g_free(cmd->arg);
	g_free(cmd->cmd);
	g_free(cmd);

	cmd = g_slist_nth_data(modem->commands, 0);
	if (cmd == NULL)
		return TRUE;

	send_command(modem, cmd);

	return TRUE;
}

static int open_device(const char *device)
{
	struct termios ti;
	int fd;

	fd = open(device, O_RDWR | O_NOCTTY);
	if (fd < 0)
		return -1;

	tcflush(fd, TCIOFLUSH);

	/* Switch TTY to raw mode */
	memset(&ti, 0, sizeof(ti));
	cfmakeraw(&ti);

	tcsetattr(fd, TCSANOW, &ti);

	return fd;
}

int modem_open(struct modem_data *modem)
{
	int fd, try = 5;

	DBG("modem %p", modem);

	if (modem == NULL)
		return -ENOENT;

	while (try-- > 0) {
		fd = open_device(modem->device);
		if (fd < 0) {
			sleep(1);
			continue;
		}
		try = 0;
	}

	if (fd < 0) {
		connman_error("Can't open %s device", modem->device);
		return -EIO;
	}

	modem->channel = g_io_channel_unix_new(fd);
	g_io_channel_set_close_on_unref(modem->channel, TRUE);

	modem->watch = g_io_add_watch(modem->channel,
				G_IO_IN | G_IO_NVAL | G_IO_HUP | G_IO_ERR,
							modem_event, modem);

	return 0;
}

int modem_close(struct modem_data *modem)
{
	DBG("modem %p", modem);

	if (modem == NULL)
		return -ENOENT;

	g_source_remove(modem->watch);
	modem->watch = 0;

	g_io_channel_unref(modem->channel);
	modem->channel = NULL;

	return 0;
}

int modem_add_callback(struct modem_data *modem, const char *command,
					modem_cb_t function, void *user_data)
{
	struct modem_callback *callback;

	callback = g_try_new0(struct modem_callback, 1);
	if (callback == NULL)
		return -ENOMEM;

	callback->command   = g_strdup(command);
	callback->function  = function;
	callback->user_data = user_data;

	modem->callbacks = g_slist_append(modem->callbacks, callback);

	return 0;
}

static int modem_command_valist(struct modem_data *modem, modem_cb_t callback,
					void *user_data, const char *command,
					const char *format, va_list var_args)
{
	struct modem_cmd *cmd;

	cmd = g_try_new0(struct modem_cmd, 1);
	if (cmd == NULL)
		return -ENOMEM;

	cmd->cmd = g_strdup(command);
	if (format != NULL)
		cmd->arg = g_strdup_vprintf(format, var_args);

	cmd->callback  = callback;
	cmd->user_data = user_data;

	return queue_command(modem, cmd);
}

int modem_command(struct modem_data *modem,
				modem_cb_t callback, void *user_data,
				const char *command, const char *format, ...)
{
	va_list args;
	int err;

	DBG("modem %p", modem);

	if (modem == NULL)
		return -ENOENT;

	va_start(args, format);
	err = modem_command_valist(modem, callback, user_data,
						command, format, args);
	va_end(args);

	return err;
}
