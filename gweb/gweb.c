/*
 *
 *  Web service library with GLib integration
 *
 *  Copyright (C) 2009-2010  Intel Corporation. All rights reserved.
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
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "gweb.h"

struct web_session {
	GWeb *web;

	char *address;
	char *host;
	uint16_t port;
	unsigned long flags;

	GIOChannel *transport_channel;
	guint transport_watch;
};

struct _GWeb {
	gint ref_count;

	guint next_query_id;

	int index;
	GList *session_list;

	GWebDebugFunc debug_func;
	gpointer debug_data;
};

static inline void debug(GWeb *web, const char *format, ...)
{
	char str[256];
	va_list ap;

	if (web->debug_func == NULL)
		return;

	va_start(ap, format);

	if (vsnprintf(str, sizeof(str), format, ap) > 0)
		web->debug_func(str, web->debug_data);

	va_end(ap);
}

static void free_session(struct web_session *session)
{
	if (session == NULL)
		return;

	if (session->transport_watch > 0)
		g_source_remove(session->transport_watch);

	if (session->transport_channel != NULL)
		g_io_channel_unref(session->transport_channel);

	g_free(session->host);
	g_free(session->address);
	g_free(session);
}

static void flush_sessions(GWeb *web)
{
	GList *list;

	for (list = g_list_first(web->session_list);
					list; list = g_list_next(list))
		free_session(list->data);

	g_list_free(web->session_list);
	web->session_list = NULL;
}

GWeb *g_web_new(int index)
{
	GWeb *web;

	if (index < 0)
		return NULL;

	web = g_try_new0(GWeb, 1);
	if (web == NULL)
		return NULL;

	web->ref_count = 1;

	web->next_query_id = 1;

	web->index = index;
	web->session_list = NULL;

	return web;
}

GWeb *g_web_ref(GWeb *web)
{
	if (web == NULL)
		return NULL;

	g_atomic_int_inc(&web->ref_count);

	return web;
}

void g_web_unref(GWeb *web)
{
	if (web == NULL)
		return;

	if (g_atomic_int_dec_and_test(&web->ref_count) == FALSE)
		return;

	flush_sessions(web);

	g_free(web);
}

void g_web_set_debug(GWeb *web, GWebDebugFunc func, gpointer user_data)
{
	if (web == NULL)
		return;

	web->debug_func = func;
	web->debug_data = user_data;
}

static gboolean received_data(GIOChannel *channel, GIOCondition cond,
							gpointer user_data)
{
	struct web_session *session = user_data;
	unsigned char buf[4096];
	int sk, len;

	if (cond & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		session->transport_watch = 0;
		return FALSE;
	}

	sk = g_io_channel_unix_get_fd(session->transport_channel);

	memset(buf, 0, sizeof(buf));
	len = recv(sk, buf, sizeof(buf) - 1, 0);

	printf("%s", buf);

	return TRUE;
}

static int connect_session_transport(struct web_session *session)
{
	struct sockaddr_in sin;
	int sk;

	sk = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sk < 0)
		return -EIO;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(session->port);
	sin.sin_addr.s_addr = inet_addr(session->address);

	if (connect(sk, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
		close(sk);
		return -EIO;
	}

	session->transport_channel = g_io_channel_unix_new(sk);
	if (session->transport_channel == NULL) {
		close(sk);
		return -ENOMEM;
	}

	g_io_channel_set_close_on_unref(session->transport_channel, TRUE);

	session->transport_watch = g_io_add_watch(session->transport_channel,
							G_IO_IN, received_data,
								session);

	return 0;
}

static void start_request(struct web_session *session, const char *request)
{
	GString *buf;
	char *str;
	ssize_t len;
	int sk;

	debug(session->web, "request %s from %s", request, session->host);

	sk = g_io_channel_unix_get_fd(session->transport_channel);

	buf = g_string_new(NULL);
	g_string_append_printf(buf, "GET %s HTTP/1.1\r\n", request);
	g_string_append_printf(buf, "Host: %s\r\n", session->host);
	g_string_append_printf(buf, "User-Agent: ConnMan/%s\r\n", VERSION);
	g_string_append(buf, "Accept: */*\r\n");
	g_string_append(buf, "\r\n");
	str = g_string_free(buf, FALSE);

	len = send(sk, str, strlen(str), 0);

	printf("%s", str);

	g_free(str);
}

static char *parse_url(struct web_session *session, const char *url)
{
	char *scheme, *host, *port, *path, *request;

	scheme = g_strdup(url);
	if (scheme == NULL)
		return NULL;

	host = strstr(scheme, "://");
	if (host != NULL) {
		*host = '\0';
		host += 3;

		if (strcasecmp(scheme, "https") == 0)
			session->port = 443;
		else if (strcasecmp(scheme, "http") == 0)
			session->port = 80;
		else {
			g_free(scheme);
			return NULL;
		}
	} else {
		host = scheme;
		session->port = 80;
	}

	path = strchr(host, '/');
	if (path != NULL)
		*(path++) = '\0';

	request = g_strdup_printf("/%s", path ? path : "");

	port = strrchr(host, ':');
	if (port != NULL) {
		char *end;
		int tmp = strtol(port + 1, &end, 10);

		if (*end == '\0') {
			*port = '\0';
			session->port = tmp;
		}
	}

	session->host = g_strdup(host);

	g_free(scheme);

	return request;
}

guint g_web_request(GWeb *web, GWebMethod method, const char *url,
				GWebResultFunc func, gpointer user_data)
{
	struct web_session *session;
	char *request;

	if (web == NULL || url == NULL)
		return 0;

	debug(web, "request %s", url);

	session = g_try_new0(struct web_session, 1);
	if (session == NULL)
		return 0;

	request = parse_url(session, url);
	if (request == NULL) {
		g_free(session);
		return 0;
	}

	if (inet_aton(session->host, NULL) == 0) {
		g_free(session);
		return 0;
	}

	session->address = g_strdup(session->host);

	debug(web, "host %s:%u", session->host, session->port);

	if (connect_session_transport(session) < 0) {
		g_free(request);
		free_session(session);
		return FALSE;
	}

	session->web = web;

	web->session_list = g_list_append(web->session_list, session);

	debug(web, "creating session %s:%u", session->address, session->port);

	start_request(session, request);

	g_free(request);

	return web->next_query_id++;
}
