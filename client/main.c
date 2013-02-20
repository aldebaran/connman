/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
 *
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
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <readline/readline.h>

#include <glib.h>
#include <gdbus.h>

#include "data_manager.h"
#include "services.h"
#include "technology.h"
#include "interactive.h"
#include "monitor.h"

static GMainLoop *main_loop;
DBusConnection *connection;

static gboolean timeout_wait(gpointer data)
{
	static int i;
	i++;
	/* Set to whatever number of retries is wanted/needed */
	if (i == 1) {
		g_main_loop_quit(data);
		return FALSE;
	}
	return TRUE;
}

static void rl_handler(char *input)
{

	if (input == NULL)
		exit(EXIT_FAILURE);
	else
		printf("Use ctrl-d to exit\n");
}

static gboolean readmonitor(GIOChannel *channel, GIOCondition condition,
						gpointer user_data){
	rl_callback_read_char();
	return TRUE;
}

int main(int argc, char *argv[])
{
	DBusError err;
	int events, error;
	GIOChannel *gchan;
	main_loop = g_main_loop_new(NULL, FALSE);

	dbus_error_init(&err);

	connection = g_dbus_setup_bus(DBUS_BUS_SYSTEM, NULL, &err);

	if (dbus_error_is_set(&err)) {
		fprintf(stderr, "Connection Error: %s\n", err.message);
		dbus_error_free(&err);
	}

	if (connection == NULL) {
		fprintf(stderr, "Could not connect to system bus...exiting\n");
		exit(EXIT_FAILURE);
	}

	if (argc < 2)
		show_interactive(connection, main_loop);

	error = commands(connection, argv + 1, argc -1);

	if (error == -1) {
		char *help = "help";

		printf("Usage: connmanctl [[command] [args]]\n");
		commands(connection, &help, 1);
		printf("\nNote: arguments and output are considered "
				"EXPERIMENTAL for now.\n\n");
		return -EINVAL;
	}

	if (error < 0)
		return error;

	gchan = g_io_channel_unix_new(fileno(stdin));
	events = G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL;
	g_io_add_watch(gchan, events, readmonitor, NULL);
	rl_callback_handler_install("", rl_handler);

	if (strcmp(argv[1], "monitor") != 0)
		g_timeout_add_full(G_PRIORITY_DEFAULT, 100, timeout_wait,
							       main_loop, NULL);
	g_main_loop_run(main_loop);
	rl_callback_handler_remove();
	g_io_channel_unref(gchan);
	if (main_loop != NULL)
		g_main_loop_unref(main_loop);
	return 0;
}
