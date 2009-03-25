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

#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/resolver.h>
#include <connman/log.h>

#include <glib.h>

struct server_data {
	char *interface;
	char *server;
	GIOChannel *channel;
	guint watch;
};

struct request_data {
	struct sockaddr_in sin;
	socklen_t len;
	guint16 id;
};

static GSList *server_list = NULL;
static GSList *request_list = NULL;

static GIOChannel *listener_channel = NULL;
static guint listener_watch = 0;

static struct request_data *find_request(guint16 id)
{
	GSList *list;

	for (list = request_list; list; list = list->next) {
		struct request_data *data = list->data;

		if (data->id == id)
			return data;
	}

	return NULL;
}

static struct server_data *find_server(const char *interface,
							const char *server)
{
	GSList *list;

	DBG("interface %s server %s", interface, server);

	for (list = server_list; list; list = list->next) {
		struct server_data *data = list->data;

		if (data->interface == NULL || data->server == NULL)
			continue;

		if (g_str_equal(data->interface, interface) == TRUE &&
				g_str_equal(data->server, server) == TRUE)
			return data;
	}

	return NULL;
}

static gboolean server_event(GIOChannel *channel, GIOCondition condition,
							gpointer user_data)
{
	struct server_data *data = user_data;
	struct request_data *req;
	unsigned char buf[768];
	int sk, err, len;

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		connman_error("Error with server channel");
		data->watch = 0;
		return FALSE;
	}

	sk = g_io_channel_unix_get_fd(channel);

	len = recv(sk, buf, sizeof(buf), 0);
	if (len < 2)
		return TRUE;

	DBG("Received %d bytes (id 0x%04x)", len, buf[0] | buf[1] << 8);

	req = find_request(buf[0] | buf[1] << 8);
	if (req == NULL)
		return TRUE;

	request_list = g_slist_remove(request_list, req);

	sk = g_io_channel_unix_get_fd(listener_channel);

	err = sendto(sk, buf, len, 0, (struct sockaddr *) &req->sin, req->len);

	g_free(req);

	return TRUE;
}

static struct server_data *create_server(const char *interface,
							const char *server)
{
	struct server_data *data;
	struct sockaddr_in sin;
	int sk;

	DBG("interface %s server %s", interface, server);

	sk = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sk < 0) {
		connman_error("Failed to create server %s socket", server);
		return NULL;
	}

	if (setsockopt(sk, SOL_SOCKET, SO_BINDTODEVICE,
				interface, strlen(interface) + 1) < 0) {
		connman_error("Failed to bind server %s to interface %s",
							server, interface);
		close(sk);
		return NULL;
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(53);
	sin.sin_addr.s_addr = inet_addr(server);

	if (connect(sk, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
		connman_error("Failed to connect server %s", server);
		close(sk);
		return NULL;
	}

	data = g_try_new0(struct server_data, 1);
	if (data == NULL) {
		connman_error("Failed to allocate server %s data", server);
		close(sk);
		return NULL;
	}

	data->channel = g_io_channel_unix_new(sk);
	if (data->channel == NULL) {
		connman_error("Failed to create server %s channel", server);
		close(sk);
		g_free(data);
		return NULL;
	}

	g_io_channel_set_close_on_unref(data->channel, TRUE);

	data->watch = g_io_add_watch(data->channel, G_IO_IN,
							server_event, data);

	data->interface = g_strdup(interface);
	data->server = g_strdup(server);

	return data;
}

static void destroy_server(struct server_data *data)
{
	DBG("interface %s server %s", data->interface, data->server);

	if (data->watch > 0)
		g_source_remove(data->watch);

	g_io_channel_unref(data->channel);

	g_free(data->interface);
	g_free(data->server);
	g_free(data);
}

static int dnsproxy_append(const char *interface, const char *domain,
							const char *server)
{
	struct server_data *data;

	DBG("interface %s server %s", interface, server);

	if (g_str_equal(server, "127.0.0.1") == TRUE)
		return -ENODEV;

	data = create_server(interface, server);
	if (data == NULL)
		return -EIO;

	server_list = g_slist_append(server_list, data);

	return 0;
}

static int dnsproxy_remove(const char *interface, const char *domain,
							const char *server)
{
	struct server_data *data;

	DBG("interface %s server %s", interface, server);

	if (g_str_equal(server, "127.0.0.1") == TRUE)
		return -ENODEV;

	data = find_server(interface, server);
	if (data == NULL)
		return 0;

	server_list = g_slist_remove(server_list, data);

	destroy_server(data);

	return 0;
}

static struct connman_resolver dnsproxy_resolver = {
	.name		= "dnsproxy",
	.priority	= CONNMAN_RESOLVER_PRIORITY_HIGH,
	.append		= dnsproxy_append,
	.remove		= dnsproxy_remove,
};

#if __BYTE_ORDER == __LITTLE_ENDIAN
struct domain_hdr {
	uint16_t id;
	uint8_t rd:1;
	uint8_t tc:1;
	uint8_t aa:1;
	uint8_t opcode:4;
	uint8_t qr:1;
	uint8_t rcode:4;
	uint8_t z:3;
	uint8_t ra:1;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} __attribute__ ((packed));
#elif __BYTE_ORDER == __BIG_ENDIAN
struct domain_hdr {
	uint16_t id;
	uint8_t qr:1;
	uint8_t opcode:4;
	uint8_t aa:1;
	uint8_t tc:1;
	uint8_t rd:1;
	uint8_t ra:1;
	uint8_t z:3;
	uint8_t rcode:4;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} __attribute__ ((packed));
#else
#error "Unknown byte order"
#endif

static void parse_request(unsigned char *buf, int len)
{
	struct domain_hdr *hdr = (void *) buf;
	uint16_t qdcount = ntohs(hdr->qdcount);
	unsigned char *ptr;
	char name[512];
	unsigned int remain, used = 0;

	if (len < 12)
		return;

	DBG("id 0x%04x qr %d opcode %d qdcount %d",
				hdr->id, hdr->qr, hdr->opcode, qdcount);

	if (hdr->qr != 0 || qdcount != 1)
		return;

	memset(name, 0, sizeof(name));

	ptr = buf + 12;
	remain = len - 12;

	while (remain > 0) {
		uint8_t len = *ptr;

		if (len == 0x00)
			break;

		if (used + len + 1 > sizeof(name))
			return;

		strncat(name, (char *) (ptr + 1), len);
		strcat(name, ".");

		used += len + 1;

		ptr += len + 1;
		remain -= len + 1;
	}

	DBG("domain name %s", name);
}

static gboolean listener_event(GIOChannel *channel, GIOCondition condition,
							gpointer user_data)
{
	GSList *list;
	unsigned char buf[768];
	struct request_data *req;
	struct sockaddr_in sin;
	socklen_t size = sizeof(sin);
	int sk, err, len;

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		connman_error("Error with listener channel");
		listener_watch = 0;
		return FALSE;
	}

	sk = g_io_channel_unix_get_fd(channel);

	memset(&sin, 0, sizeof(sin));
	len = recvfrom(sk, buf, sizeof(buf), 0,
					(struct sockaddr *) &sin, &size);
	if (len < 2)
		return TRUE;

	DBG("Received %d bytes (id 0x%04x)", len, buf[0] | buf[1] << 8);

	parse_request(buf, len);

	if (g_slist_length(server_list) == 0)
		return TRUE;

	req = find_request(buf[0] | (buf[1] << 8));
	if (req == NULL) {
		req = g_try_new0(struct request_data, 1);
		if (req == NULL)
			return TRUE;

		memcpy(&req->sin, &sin, sizeof(sin));
		req->len = size;
		req->id = buf[0] | (buf[1] << 8);

		request_list = g_slist_append(request_list, req);
	} else {
		memcpy(&req->sin, &sin, sizeof(sin));
		req->len = size;
	}

	for (list = server_list; list; list = list->next) {
		struct server_data *data = list->data;

		sk = g_io_channel_unix_get_fd(data->channel);

		err = send(sk, buf, len, 0);
	}

	return TRUE;
}

static int create_listener(void)
{
	const char *ifname = "lo";
	struct sockaddr_in sin;
	int sk;

	DBG("");

	sk = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sk < 0) {
		connman_error("Failed to create listener socket");
		return -EIO;
	}

	//setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	//setsockopt(sk, SOL_IP, IP_PKTINFO, &opt, sizeof(opt));

	if (setsockopt(sk, SOL_SOCKET, SO_BINDTODEVICE,
					ifname, strlen(ifname) + 1) < 0) {
		connman_error("Failed to bind listener interface");
		close(sk);
		return -EIO;
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(53);
	sin.sin_addr.s_addr = inet_addr("127.0.0.1");
	//sin.sin_addr.s_addr = INADDR_ANY;

	if (bind(sk, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
		connman_error("Failed to bind listener socket");
		close(sk);
		return -EIO;
	}

	listener_channel = g_io_channel_unix_new(sk);
	if (listener_channel == NULL) {
		connman_error("Failed to create listener channel");
		close(sk);
		return -EIO;
	}

	g_io_channel_set_close_on_unref(listener_channel, TRUE);

	listener_watch = g_io_add_watch(listener_channel, G_IO_IN,
							listener_event, NULL);

	connman_resolver_append("lo", NULL, "127.0.0.1");

	return 0;
}

static void destroy_listener(void)
{
	GSList *list;

	DBG("");

	connman_resolver_remove_all("lo");

	if (listener_watch > 0)
		g_source_remove(listener_watch);

	for (list = request_list; list; list = list->next) {
		struct request_data *data = list->data;

		DBG("Dropping request (id 0x%04x)", data->id);

		g_free(data);
		list->data = NULL;
	}

	g_slist_free(request_list);
	request_list = NULL;

	g_io_channel_unref(listener_channel);
}

static int dnsproxy_init(void)
{
	int err;

	err = create_listener();
	if (err < 0)
		return err;

	err = connman_resolver_register(&dnsproxy_resolver);
	if (err < 0)
		destroy_listener();

	return err;
}

static void dnsproxy_exit(void)
{
	destroy_listener();

	connman_resolver_unregister(&dnsproxy_resolver);
}

CONNMAN_PLUGIN_DEFINE(dnsproxy, "DNS proxy resolver plugin", VERSION,
		 CONNMAN_PLUGIN_PRIORITY_DEFAULT, dnsproxy_init, dnsproxy_exit)
