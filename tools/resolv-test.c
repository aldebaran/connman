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
#include <string.h>
#include <signal.h>

#include <gresolv/gresolv.h>

static GMainLoop *main_loop = NULL;

static void resolv_debug(const char *str, void *data)
{
	g_print("%s: %s\n", (const char *) data, str);
}

static void sig_term(int sig)
{
	g_main_loop_quit(main_loop);
}

int main(int argc, char *argv[])
{
	struct sigaction sa;
	GResolv *resolv;
	int index = 0;

	if (argc < 2) {
		printf("missing argument\n");
		return 1;
	}

	resolv = g_resolv_new(index);
	if (resolv == NULL) {
		printf("failed to create resolver\n");
		return 1;
	}

	g_resolv_set_debug(resolv, resolv_debug, "RESOLV");

	main_loop = g_main_loop_new(NULL, FALSE);

	if (argc > 2) {
		int i;

		for (i = 2; i < argc; i++)
			g_resolv_add_nameserver(resolv, argv[i], 53, 0);
	} else
		g_resolv_add_nameserver(resolv, "127.0.0.1", 53, 0);

	g_resolv_lookup_hostname(resolv, argv[1]);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_term;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	g_main_loop_run(main_loop);

	g_resolv_unref(resolv);

	g_main_loop_unref(main_loop);

	return 0;
}
