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

#include <gweb/gweb.h>

static GTimer *timer;

static GMainLoop *main_loop;

static void web_debug(const char *str, void *data)
{
	g_print("%s: %s\n", (const char *) data, str);
}

static void sig_term(int sig)
{
	g_main_loop_quit(main_loop);
}

static gboolean web_result(GWebResult *result, gpointer user_data)
{
	guint16 status;
	gdouble elapsed;

	status = g_web_result_get_status(result);

	elapsed = g_timer_elapsed(timer, NULL);

	g_print("elapse: %f seconds\n", elapsed);

	g_print("status: %03u\n", status);

	g_main_loop_quit(main_loop);

	return FALSE;
}

static gboolean option_debug = FALSE;
static gchar *option_nameserver = NULL;

static GOptionEntry options[] = {
	{ "debug", 'd', 0, G_OPTION_ARG_NONE, &option_debug,
					"Enable debug output" },
	{ "nameserver", 'n', 0, G_OPTION_ARG_STRING, &option_nameserver,
					"Specify nameserver", "ADDRESS" },
	{ NULL },
};

int main(int argc, char *argv[])
{
	GOptionContext *context;
	GError *error = NULL;
	struct sigaction sa;
	GWeb *web;
	int index = 0;

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);

	if (g_option_context_parse(context, &argc, &argv, &error) == FALSE) {
		if (error != NULL) {
			g_printerr("%s\n", error->message);
			g_error_free(error);
		} else
			g_printerr("An unknown error occurred\n");
		return 1;
	}

	g_option_context_free(context);

	if (argc < 2) {
		fprintf(stderr, "Missing argument\n");
		return 1;
	}

	web = g_web_new(index);
	if (web == NULL) {
		fprintf(stderr, "Failed to create web service\n");
		return 1;
	}

	if (option_debug == TRUE)
		g_web_set_debug(web, web_debug, "WEB");

	main_loop = g_main_loop_new(NULL, FALSE);

	if (option_nameserver != NULL) {
		g_web_add_nameserver(web, option_nameserver);
		g_free(option_nameserver);
	}

	g_web_set_user_agent(web, "ConnMan/%s", VERSION);

	timer = g_timer_new();

	if (g_web_request(web, G_WEB_METHOD_GET, argv[1],
					web_result, NULL) == 0) {
		fprintf(stderr, "Failed to start request\n");
		return 1;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_term;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	g_main_loop_run(main_loop);

	g_timer_destroy(timer);

	g_web_unref(web);

	g_main_loop_unref(main_loop);

	return 0;
}
