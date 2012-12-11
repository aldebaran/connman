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

#include "client/services.h"
#include "client/technology.h"
#include "client/data_manager.h"
#include "client/monitor.h"
#include "client/interactive.h"

static DBusConnection *interactive_conn;

static char **parse_long(char *input, int *num_args)
{
	int i;
	char **token = NULL;

	for (i = 0; input != NULL; i++) {
		token = realloc(token, (i + 1) * sizeof(char *));
		if (token == NULL)
			return NULL;
		token[i] = strdup(input);
		input = strtok(NULL, " ");
	}
	*num_args = i;

	return token;
}

static gboolean rl_handler(char *input)
{
	char **long_args;
	int num_args, i, error;
	num_args = 0;

	if (input == NULL) {
		rl_newline(1, '\n');
		exit(EXIT_FAILURE);
	}

	add_history(input);
	input = strtok(input, " ");

	if (input == NULL)
		return FALSE;
	long_args = parse_long(input, &num_args);

	if (long_args == NULL) {
		free(input);
		exit(EXIT_FAILURE);
	} else {
		error = commands_no_options(interactive_conn,
						long_args, num_args);
		if (error == -1)
			error = commands_options(interactive_conn, long_args,
						num_args);
		else
			return error;
	}
	if ((strcmp(long_args[0], "quit") == 0)
					|| (strcmp(long_args[0], "exit") == 0)
					|| (strcmp(long_args[0], "q") == 0)) {
		for (i = 0; i < num_args; i++)
			free(long_args[i]);
		free(long_args);
		exit(EXIT_SUCCESS);
	}
	if (error == -1) {
		fprintf(stderr, "%s is not a valid command, check help.\n",
			long_args[0]);
	}

	for (i = 0; i < num_args; i++)
		free(long_args[i]);
	free(long_args);
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
