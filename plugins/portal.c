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

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/location.h>
#include <connman/proxy.h>
#include <connman/log.h>

#define STATUS_URL  "http://www.connman.net/online/status.html"

#define HOST "www.connman.net"
#define PORT 80
#define PAGE "/online/status.html"

#define CONNMAN_NET_IP "62.75.245.128"
#define CONNMAN_MAX_IP_LENGTH	15
#define CONNECT_TIMEOUT		120
#define MAX_COUNTER		80

#define MAX_HEADER_LINES	13
#define PROXY_HEADER_LENGTH	7

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
	int (*get_page) (struct connman_location *location, char *page, int len,
						enum get_page_status status);
};

static int create_socket()
{
	int sk;

	sk = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sk < 0)
		connman_error("Can not create TCP socket");

	return sk;
}

static char *get_ip_from_host(char *host)
{
	int ip_len = CONNMAN_MAX_IP_LENGTH;
	char *ip;
	struct hostent *host_ent;

	DBG("Get ip for %s", host);
	ip = g_try_malloc0(ip_len + 1);
	if (ip == NULL)
		return NULL;

	host_ent = gethostbyname(host);
	if (host_ent == NULL) {
		connman_error("Can not get IP");
		goto failed;
	}

	if (inet_ntop(AF_INET, (void *) host_ent->h_addr_list[0],
							ip, ip_len) == NULL) {
		connman_error("Can not resolve host");
		goto failed;
	}

	return ip;
failed:
	g_free(ip);

	return NULL;
}

static char *build_get_query(char *host, char *page)
{
	char *query;

	query = g_strdup_printf("GET %s HTTP/1.0\r\nHost: %s\r\n"
				"User-Agent: ConnMan/%s\r\n\r\n",
				page, host, VERSION);

	return query;
}

static gboolean connect_timeout(gpointer user_data)
{
	struct connman_location *location = user_data;
	struct server_data *data = connman_location_get_data(location);

	if (data == NULL)
		return FALSE;

	data->timeout = 0;

	if (data->get_page)
		data->get_page(location, NULL, 0, GET_PAGE_TIMEOUT);

	return FALSE;
}

static void remove_timeout(struct server_data *data)
{
	if (data && data->timeout > 0) {
		g_source_remove(data->timeout);
		data->timeout = 0;
	}
}

static gboolean tcp_event(GIOChannel *channel, GIOCondition condition,
							gpointer user_data)
{
	struct connman_location *location = user_data;
	struct server_data *data = connman_location_get_data(location);
	enum get_page_status status;
	char buf[BUFSIZ+1];
	int len;
	int sk;

	if (data == NULL)
		return FALSE;

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		connman_error("TCP event error %d", condition);
		len = 0;
		status = GET_PAGE_FAILED;
		goto done;
	}

	sk = g_io_channel_unix_get_fd(channel);
	len = recv(sk, buf, BUFSIZ, 0);

	if (len > 0)
		status = GET_PAGE_SUCCESS;
	else
		status = GET_PAGE_FAILED;

done:
	remove_timeout(data);
	data->watch = 0;
	if (data->get_page)
		data->get_page(location, buf, len, status);

	return FALSE;
}

static gboolean socket_event(GIOChannel *channel, GIOCondition condition,
				gpointer user_data)
{
	struct connman_location *location = user_data;
	struct server_data *data = connman_location_get_data(location);
	char *query;
	int sk;
	unsigned int send_counter = 0;
	int ret;

	if (data == NULL)
		return FALSE;

	if (condition & G_IO_OUT && data->connection_ready == 0) {
		data->connection_ready = 1;
		sk = g_io_channel_unix_get_fd(channel);

		query = build_get_query(data->host, data->page);
		DBG("query is:\n%s\n", query);

		while (send_counter < strlen(query)) {
			ret = send(sk, query+send_counter,
					strlen(query) - send_counter, 0);
			if (ret == -1) {
				DBG("Error sending query");
				remove_timeout(data);
				if (data->get_page)
					data->get_page(location, NULL, 0,
							GET_PAGE_FAILED);
				g_free(query);
				return FALSE;
			}
			send_counter += ret;
		}
		g_free(query);
	} else if (condition & G_IO_IN)
		return tcp_event(channel, condition, user_data);

	return TRUE;
}

static void remove_connection(struct connman_location *location)
{
	struct server_data *data = connman_location_get_data(location);

	data = connman_location_get_data(location);
	if (data == NULL)
		return;

	remove_timeout(data);
	if (data->watch)
		g_source_remove(data->watch);

	if (data->channel != NULL)
		g_io_channel_shutdown(data->channel, TRUE, NULL);

	if (data->sock >= 0)
		close(data->sock);

	g_free(data);
	connman_location_set_data(location, NULL);
}

static int get_html(struct connman_location *location, int ms_time)
{
	struct server_data *data;
	struct sockaddr_in *remote_host = NULL;
	int ret;
	char *ip = NULL;

	DBG("");

	data = connman_location_get_data(location);
	data->connection_ready = 0;
	data->sock = create_socket();
	if (data->sock < 0)
		goto error;

	DBG("proxy %s port %d", data->proxy, data->proxy_port);

	if (strlen(data->proxy) > 0)
		ip = get_ip_from_host(data->proxy);
	else {
		ip = g_try_malloc0(16);
		if (ip != NULL)
			strcpy(ip, CONNMAN_NET_IP);
	}

	if (ip == NULL)
		goto error;

	DBG("IP from host %s is %s", data->host, ip);

	remote_host = g_try_new0(struct sockaddr_in, 1);
	remote_host->sin_family = AF_INET;
	ret = inet_pton(AF_INET, ip,
			(void *) (&(remote_host->sin_addr.s_addr)));
	if (ret < 0) {
		connman_error("Error Calling inet_pton");
		goto error;
	} else if (ret == 0) {
		connman_error("Wrong IP address %s", ip);
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
							socket_event, location);
	data->timeout = g_timeout_add_seconds(ms_time, connect_timeout,
								location);

	ret = connect(data->sock, (struct sockaddr *)remote_host,
						sizeof(struct sockaddr));
	if (ret < 0 && errno != EINPROGRESS) {
		connman_error("Could not connect");
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
		data->get_page(location, NULL, 0, GET_PAGE_FAILED);

	return ret;
}

static int get_status(struct server_data *data, char *page, int len)
{
	gchar **lines;
	gchar *str;
	int i;

	/*
	 * Right now we are only looking at HTTP response header to figure
	 * out if AP redirected our HTTP request. In the future we are going
	 * to parse the HTTP body and look for certain fixed context.
	 * To figure out if we are redirected we look for some HTTP header line,
	 * if these header was found then we have our page otherwise we
	 * have a redirection page.
	 */
	lines = g_strsplit(page, "\n", MAX_HEADER_LINES);

	str = g_strrstr(lines[0], "200 OK");
	if (str != NULL) {
		for (i = 0; lines[i] != NULL && i < 12; i++) {
			DBG("%s", lines[i]);
			str = g_strstr_len(lines[i], 12, "X-ConnMan");
			if (str != NULL) {
				g_strfreev(lines);
				DBG("success");
				return GET_PAGE_SUCCESS;
			}
		}
	}
	g_strfreev(lines);

	DBG("redirection");

	return GET_PAGE_REDIRECTED;
}

static int get_page_cb(struct connman_location *location, char *page, int len,
		enum get_page_status status)
{
	int ret;
	struct server_data *data = connman_location_get_data(location);

	remove_connection(location);

	if (page && len > 0)
		ret = get_status(data, page, len);
	else
		ret = status;

	DBG("status %d", status);

	switch (ret) {
	case GET_PAGE_SUCCESS:
		connman_location_report_result(location,
					CONNMAN_LOCATION_RESULT_ONLINE);
		DBG("Page fetched");
		break;
	case GET_PAGE_REDIRECTED:
		connman_location_report_result(location,
					CONNMAN_LOCATION_RESULT_PORTAL);
		DBG("Page redirected");
		break;
	case GET_PAGE_FAILED:
		connman_location_report_result(location,
					CONNMAN_LOCATION_RESULT_UNKNOWN);
		DBG("Could not get the page");
		break;
	case GET_PAGE_TIMEOUT:
		connman_location_report_result(location,
					CONNMAN_LOCATION_RESULT_UNKNOWN);
		DBG("Page timeout");
		break;
	}

	return ret;
}

static void proxy_callback(const char *proxy, void *user_data)
{
	struct connman_location *location = user_data;

	DBG("proxy %s", proxy);

	if (proxy == NULL)
		proxy = getenv("http_proxy");

	if (proxy != NULL) {
		struct server_data *data = connman_location_get_data(location);
		char *delim;

		if (strncmp(proxy, "http://", PROXY_HEADER_LENGTH) == 0)
			strcpy(data->proxy, proxy + PROXY_HEADER_LENGTH);
		else
			strcpy(data->proxy, proxy);

		delim = strchr(data->proxy, ':');
		if (delim) {
			int len;

			len = delim - data->proxy;
			data->proxy[len] = '\0';

			data->proxy_port = atoi(delim + 1);
		} else
			data->proxy_port = PORT;
	}

	get_html(location, CONNECT_TIMEOUT);
}

static int location_detect(struct connman_location *location)
{
	struct server_data *data;
	enum connman_service_type service_type;
	const char *interface;

	service_type = connman_location_get_type(location);

	DBG("service type %d", service_type);

	switch (service_type) {
	case CONNMAN_SERVICE_TYPE_ETHERNET:
	case CONNMAN_SERVICE_TYPE_WIFI:
	case CONNMAN_SERVICE_TYPE_WIMAX:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		break;
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_VPN:
		return -EOPNOTSUPP;
	}

	interface = connman_location_get_interface(location);
	if (interface == NULL)
		return -EINVAL;

	data = g_try_new0(struct server_data, 1);
	if (data == NULL)
		return -ENOMEM;

	strcpy(data->host, HOST);
	strcpy(data->page, PAGE);
	data->get_page = get_page_cb;
	data->timeout = 0;

	connman_location_set_data(location, data);

	connman_proxy_lookup(interface, STATUS_URL,
					proxy_callback, location);

	return 0;
}

static int location_finish(struct connman_location *location)
{

	remove_connection(location);
	return 0;
}

static struct connman_location_driver location = {
	.name		= "wifi and ethernet location",
	.type		= CONNMAN_SERVICE_TYPE_WIFI,
	.priority	= CONNMAN_LOCATION_PRIORITY_HIGH,
	.detect		= location_detect,
	.finish		= location_finish,
};

static int portal_init(void)
{
	return connman_location_driver_register(&location);
}

static void portal_exit(void)
{
	connman_location_driver_unregister(&location);
}

CONNMAN_PLUGIN_DEFINE(portal, "Portal detection plugin", VERSION,
		CONNMAN_PLUGIN_PRIORITY_DEFAULT, portal_init, portal_exit)
