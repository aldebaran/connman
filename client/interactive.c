/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
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
#include <string.h>
#include <errno.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <glib.h>
#include <gdbus.h>

#include "services.h"
#include "technology.h"
#include "data_manager.h"
#include "monitor.h"
#include "interactive.h"

static DBusConnection *interactive_conn;

static gboolean rl_handler(char *input)
{
	char **long_args = NULL;
	int num_args, error;
	num_args = 0;

	if (input == NULL) {
		rl_newline(1, '\n');
		exit(EXIT_FAILURE);
	}

	add_history(input);
	long_args = g_strsplit(input, " ", 0);

	if (long_args == NULL || long_args[0] == NULL) {
		g_strfreev(long_args);
		free(input);
		return FALSE;
	}

	for (num_args = 0; long_args[num_args] != NULL; num_args++);

	error = commands(interactive_conn, long_args, num_args);

	if ((strcmp(long_args[0], "quit") == 0)
					|| (strcmp(long_args[0], "exit") == 0)
					|| (strcmp(long_args[0], "q") == 0)) {
		g_strfreev(long_args);
		exit(EXIT_SUCCESS);
	}
	if (error == -1) {
		fprintf(stderr, "%s is not a valid command, check help.\n",
			long_args[0]);
	}

	g_strfreev(long_args);
	optind = 0;

	return TRUE;
}

static gboolean readmonitor(GIOChannel *channel, GIOCondition condition,
							gpointer user_data){
	if (condition & (G_IO_HUP | G_IO_ERR | G_IO_NVAL)) {
		g_io_channel_unref(channel);
		return FALSE;
	}
	rl_callback_read_char();
	return TRUE;
}

void show_interactive(DBusConnection *connection, GMainLoop *mainloop)
{
	GIOChannel *gchan;
	int events;
	gchan = g_io_channel_unix_new(fileno(stdin));
	events = G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL;
	interactive_conn = connection;

	while (TRUE) {
		g_io_add_watch(gchan, events, readmonitor, NULL);
		rl_callback_handler_install("connmanctl> ", (void *)rl_handler);
		g_main_loop_run(mainloop);

		rl_callback_handler_remove();
		g_io_channel_unref(gchan);
	}
}
