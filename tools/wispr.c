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
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "gweb/giognutls.h"

static GMainLoop *main_loop;

static void sig_term(int sig)
{
	g_main_loop_quit(main_loop);
}

static int create_connection(const char *address, unsigned short port)
{
	struct sockaddr_in sin;
	int sk;

	sk = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sk < 0)
		return -EIO;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = inet_addr(address);

	if (connect(sk, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
		close(sk);
		return -EIO;
	}

	return sk;
}

static gboolean received_data(GIOChannel *channel, GIOCondition cond,
							gpointer user_data)
{
	gchar buf[2048];
	gsize bytes_read;
	GIOStatus status;

	if (cond & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		g_main_loop_quit(main_loop);
		return FALSE;
	}

	memset(buf, 0, sizeof(buf));

	status = g_io_channel_read_chars(channel, buf, sizeof(buf) - 1,
							&bytes_read, NULL);

	printf("%s\n", buf);

	if (bytes_read == 0) {
		g_main_loop_quit(main_loop);
		return FALSE;
	}

	return TRUE;
}

static gboolean option_debug = FALSE;

static GOptionEntry options[] = {
	{ "debug", 'd', 0, G_OPTION_ARG_NONE, &option_debug,
					"Enable debug output" },
	{ NULL },
};

int main(int argc, char *argv[])
{
	GOptionContext *context;
	GError *error = NULL;
	struct sigaction sa;
	GIOChannel *channel;
	gsize written;
	int sk;

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

	sk = create_connection("140.211.169.100", 443);
	if (sk < 0) {
		fprintf(stderr, "Failed to create connection\n");
		return 1;
	}

	main_loop = g_main_loop_new(NULL, FALSE);

	channel = g_io_channel_gnutls_new(sk);
	if (channel == NULL) {
		fprintf(stderr, "Failed to create GnuTLS IO channel\n");
		return 1;
	}

	g_io_channel_set_close_on_unref(channel, TRUE);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_term;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	g_io_add_watch(channel, G_IO_IN | G_IO_ERR | G_IO_HUP,
						received_data, NULL);

#define MSG "GET / HTTP/1.0\r\n\r\n"

	g_io_channel_write_chars(channel, MSG, strlen(MSG), &written, NULL);

	g_main_loop_run(main_loop);

	g_main_loop_unref(main_loop);

	g_io_channel_unref(channel);

	return 0;
}
