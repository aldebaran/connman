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

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <glib.h>
#include <glib/gprintf.h>

#define PORT 80
#define PROXY_PORT 911
#define PAGE "/"
#define HOST "connman.net"
#define USER_APP "connman"

#define CONNECT_TIMEOUT	120
#define MAX_COUNTER	80

enum get_page_status {
	GET_PAGE_SUCCESS	= 0,
	GET_PAGE_TIMEOUT	= 1,
	GET_PAGE_FAILED		= 2,
	GET_PAGE_REDIRECTED	= 3,
};

struct server_data {
	char host[MAX_COUNTER];
	char page[MAX_COUNTER];
	char proxy[MAX_COUNTER];
	GIOChannel *channel;
	guint watch;
	guint timeout;
	int connection_ready;
	int sock;
	int proxy_port;
	int (*get_page) (struct server_data *data, char *page, int len,
						enum get_page_status status);
};

static GMainLoop *main_loop = NULL;

static int create_socket()
{
	int sk;

	sk = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sk < 0) {
		perror("Error: Can not create TCP socket");
		exit(1);
	}

	return sk;
}

static char *get_ip_from_host(char *host)
{
	int ip_len = 15;
	char *ip;
	struct hostent *host_ent;

	ip = g_try_malloc0(ip_len + 1);
	if ((host_ent = gethostbyname(host)) == NULL) {
		perror("Error: Can not get IP");
		exit(1);
	}

	if (inet_ntop(AF_INET, (void *) host_ent->h_addr_list[0],
							ip, ip_len) == NULL) {
		perror("Error: Can not resolve host");
		exit(1);
	}

	return ip;
}

static char *build_get_query(char *host, char *page)
{
	char *query;
	char *host_page = page;
	char *tpl = "GET /%s HTTP/1.0\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n";

	if(host_page[0] == '/')
		host_page = host_page + 1;

	query = g_try_malloc0(strlen(host) + strlen(host_page) +
					strlen(USER_APP) + strlen(tpl) - 5);
	sprintf(query, tpl, host_page, host, USER_APP);

	return query;
}

static gboolean connect_timeout(gpointer user_data)
{
	struct server_data *data = user_data;

	data->timeout = 0;

	if (data->get_page)
		data->get_page(data, NULL, 0, GET_PAGE_TIMEOUT);

	return FALSE;
}

static void remove_timeout(struct server_data *data)
{
	if (data->timeout > 0) {
		g_source_remove(data->timeout);
		data->timeout = 0;
	}
}

static gboolean tcp_event(GIOChannel *channel, GIOCondition condition,
							gpointer user_data)
{
	char buf[BUFSIZ+1];
	int len;
	int sk;
	struct server_data *data = user_data;

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		remove_timeout(data);
		data->watch = 0;
		if (data->get_page)
			data->get_page(data, NULL, 0, GET_PAGE_FAILED);

		return FALSE;
	}

	sk = g_io_channel_unix_get_fd(channel);
	len = recv(sk, buf, BUFSIZ, 0);

	if (len > 0) {
		remove_timeout(data);
		if (data->get_page)
			data->get_page(data, buf, len, GET_PAGE_SUCCESS);
	}

	return TRUE;
}

static gboolean socket_event(GIOChannel *channel, GIOCondition condition,
				gpointer user_data)
{
	struct server_data *data = user_data;
	char *query;
	int sk;
	unsigned int send_counter = 0;
	int ret;

	if (condition & G_IO_OUT && data->connection_ready == 0) {
		data->connection_ready = 1;
		sk = g_io_channel_unix_get_fd(channel);

		query = build_get_query(data->host, data->page);
		fprintf(stderr, "query is:\n%s\n", query);

		while (send_counter < strlen(query)) {
			ret = send(sk, query+send_counter,
					strlen(query) - send_counter, 0);
			if(ret == -1) {
				perror("Error sending query");
				remove_timeout(data);
				if (data->get_page)
					data->get_page(data, NULL, 0,
							GET_PAGE_FAILED);
				g_free(query);
				return FALSE;
			}
			send_counter += ret;
		}
		g_free(query);
	} else if (condition & G_IO_IN)
		tcp_event(channel, condition, user_data);

	return TRUE;
}

static void remove_connection(struct server_data *data)
{
	remove_timeout(data);
	g_source_remove(data->watch);
	g_io_channel_shutdown(data->channel, TRUE, NULL);
	
	if (data->sock >= 0)
		close(data->sock);

	g_free(data);
}

static int get_html(struct server_data *data, int ms_time)
{
	struct sockaddr_in *remote_host;
	int ret;
	char *ip;

	data->connection_ready = 0;
	data->sock = create_socket();
	if (strlen(data->proxy) > 0)
		ip = get_ip_from_host(data->proxy);
	else
		ip = get_ip_from_host(data->host);

	fprintf(stderr, "IP from host %s is %s\n", data->host, ip); 

	remote_host = g_try_new0(struct sockaddr_in, 1);
	remote_host->sin_family = AF_INET;
	ret = inet_pton(AF_INET, ip, (void *) (&(remote_host->sin_addr.s_addr)));
	if (ret < 0) {
		perror("Error Calling inet_pton");
		goto error;
	} else if (ret == 0) {
		fprintf(stderr, "Error: wrong IP address:%s\n", ip);
		goto error;
	}
	if (strlen(data->proxy) > 0)
		remote_host->sin_port = htons(data->proxy_port);
	else
		remote_host->sin_port = htons(PORT);

	data->channel = g_io_channel_unix_new(data->sock);
	g_io_channel_set_flags(data->channel, G_IO_FLAG_NONBLOCK, NULL);
	g_io_channel_set_close_on_unref(data->channel, TRUE);
	data->watch = g_io_add_watch(data->channel, G_IO_OUT | G_IO_IN,
							socket_event, data);
	data->timeout = g_timeout_add_seconds(ms_time, connect_timeout, data);

	ret = connect(data->sock, (struct sockaddr *)remote_host,
						sizeof(struct sockaddr));
	if (ret < 0 && errno != EINPROGRESS) {
		perror("Could not connect");
		remove_timeout(data);
		goto error;
	}

	g_free(remote_host);
	g_free(ip);
	return 0;

error:
	g_free(remote_host);
	g_free(ip);

	if (data->get_page)
		data->get_page(data, NULL, 0, GET_PAGE_FAILED);

	return ret;
}

static int get_status(struct server_data *data, char *page, int len)
{
	gchar **lines;
	gchar *str;
	int i;
	int ret = GET_PAGE_REDIRECTED;

	lines = g_strsplit(page, "\n", 13);

	str = g_strrstr(lines[0], "200 OK");
	if (str != NULL) {
		for (i = 0; lines[i] != NULL && i < 12; i++) {
			str = g_strstr_len(lines[i], 12, "Set-Cookie");
			if (str != NULL)
				ret = GET_PAGE_SUCCESS;
		}
	}
	g_strfreev(lines);

	return ret;
}

static int get_page_cb(struct server_data *data, char *page, int len,
		enum get_page_status status)
{
	int ret = status;

	if (page)
		ret = get_status(data, page, len);

	switch (ret) {
	case GET_PAGE_SUCCESS:
		fprintf(stderr, "%s\n", "Page was fetched");
		break;
	case GET_PAGE_REDIRECTED:
		fprintf(stderr, "%s\n", "Page was redirected");
		break;
	case GET_PAGE_FAILED:
		fprintf(stderr, "%s\n", "error can not get the page");
		break;
	case GET_PAGE_TIMEOUT:
		fprintf(stderr, "%s\n", "Page was timeout");
		break;
	}
	g_main_loop_quit(main_loop);

	return ret;
}

int main(int argc, char **argv)
{
	char *host = HOST;
	char *page = PAGE;
	char *proxy;
	struct server_data *data;

	if (argc > 1)
		host = argv[1];

	if (argc > 2)
		page = argv[2];

	data = g_try_new0(struct server_data, 1);
	if (data == NULL)
		exit(1);

	memset(data, 0, sizeof(struct server_data));
	strcpy(data->host, host);
	strcpy(data->page, page);
	data->get_page = get_page_cb;
	data->timeout = 0;

	main_loop = g_main_loop_new(NULL, FALSE);

	proxy = getenv("http_proxy");
	if (proxy) {
		char *delim;

		if (strncmp(proxy, "http://", 7) == 0)
			strcpy(data->proxy, proxy + 7);
		else
			strcpy(data->proxy, proxy);

		delim = strchr(data->proxy, ':');
		if (delim) {
			int len;

			len = delim - data->proxy;
			data->proxy[len] = '\0';

			data->proxy_port = atoi(delim + 1);
		} else
			data->proxy_port = PROXY_PORT;
	}
	get_html(data, CONNECT_TIMEOUT);

	g_main_loop_run(main_loop);

	remove_connection(data);

	return 0;
}
