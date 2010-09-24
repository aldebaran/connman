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
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/resolver.h>
#include <connman/notifier.h>
#include <connman/ondemand.h>
#include <connman/log.h>

#include <glib.h>

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

struct server_data {
	char *interface;
	char *domain;
	char *server;
	int protocol;
	GIOChannel *channel;
	guint watch;
	guint timeout;
	gboolean enabled;
	gboolean connected;
};

struct request_data {
	struct sockaddr_in sin;
	int client_sk;
	socklen_t len;
	guint16 srcid;
	guint16 dstid;
	guint16 altid;
	guint timeout;
	guint watch;
	guint numserv;
	guint numresp;
	gpointer request;
	gsize request_len;
	gpointer name;
	gpointer resp;
	gsize resplen;
};

static GSList *server_list = NULL;
static GSList *request_list = NULL;
static GSList *request_pending_list = NULL;
static guint16 request_id = 0x0000;

static GIOChannel *udp_listener_channel = NULL;
static guint udp_listener_watch = 0;
static GIOChannel *tcp_listener_channel = NULL;
static guint tcp_listener_watch = 0;

static struct request_data *find_request(guint16 id)
{
	GSList *list;

	for (list = request_list; list; list = list->next) {
		struct request_data *req = list->data;

		if (req->dstid == id || req->altid == id)
			return req;
	}

	return NULL;
}

static struct server_data *find_server(const char *interface,
					const char *domain, const char *server,
						int protocol)
{
	GSList *list;

	DBG("interface %s server %s", interface, server);

	for (list = server_list; list; list = list->next) {
		struct server_data *data = list->data;

		if (data->interface == NULL || data->server == NULL)
			continue;

		if (g_str_equal(data->interface, interface) == TRUE &&
				g_str_equal(data->server, server) == TRUE &&
				data->protocol == protocol) {
			if (domain == NULL) {
				if (data->domain == NULL)
					return data;
				continue;
			}

			if (g_str_equal(data->domain, domain) == TRUE)
				return data;
		}
	}

	return NULL;
}

static gboolean request_timeout(gpointer user_data)
{
	struct request_data *req = user_data;

	DBG("id 0x%04x", req->srcid);

	request_list = g_slist_remove(request_list, req);

	if (req->resplen > 0 && req->resp != NULL) {
		int sk, err;

		sk = g_io_channel_unix_get_fd(udp_listener_channel);

		err = sendto(sk, req->resp, req->resplen, 0,
				(struct sockaddr *) &req->sin, req->len);
	}

	g_free(req->resp);
	g_free(req);

	return FALSE;
}

static int append_query(unsigned char *buf, unsigned int size,
				const char *query, const char *domain)
{
	unsigned char *ptr = buf;
	char *offset;

	DBG("query %s domain %s", query, domain);

	offset = (char *) query;
	while (offset != NULL) {
		char *tmp;

		tmp = strchr(offset, '.');
		if (tmp == NULL) {
			if (strlen(offset) == 0)
				break;
			*ptr = strlen(offset);
			memcpy(ptr + 1, offset, strlen(offset));
			ptr += strlen(offset) + 1;
			break;
		}

		*ptr = tmp - offset;
		memcpy(ptr + 1, offset, tmp - offset);
		ptr += tmp - offset + 1;

		offset = tmp + 1;
	}

	offset = (char *) domain;
	while (offset != NULL) {
		char *tmp;

		tmp = strchr(offset, '.');
		if (tmp == NULL) {
			if (strlen(offset) == 0)
				break;
			*ptr = strlen(offset);
			memcpy(ptr + 1, offset, strlen(offset));
			ptr += strlen(offset) + 1;
			break;
		}

		*ptr = tmp - offset;
		memcpy(ptr + 1, offset, tmp - offset);
		ptr += tmp - offset + 1;

		offset = tmp + 1;
	}

	*ptr++ = 0x00;

	return ptr - buf;
}

static int ns_resolv(struct server_data *server, struct request_data *req,
				gpointer request, gpointer name)
{
	int sk, err;

	sk = g_io_channel_unix_get_fd(server->channel);

	err = send(sk, request, req->request_len, 0);

	req->numserv++;

	if (server->domain != NULL && server->protocol == IPPROTO_UDP) {
		unsigned char alt[1024];
		struct domain_hdr *hdr = (void *) &alt;
		int altlen, domlen;

		domlen = strlen(server->domain) + 1;
		if (domlen < 5)
			return -EINVAL;

		alt[0] = req->altid & 0xff;
		alt[1] = req->altid >> 8;

		memcpy(alt + 2, request + 2, 10);
		hdr->qdcount = htons(1);

		altlen = append_query(alt + 12, sizeof(alt) - 12,
					name, server->domain);
		if (altlen < 0)
			return -EINVAL;

		altlen += 12;

		memcpy(alt + altlen, request + altlen - domlen,
				req->request_len - altlen + domlen);

		err = send(sk, alt, req->request_len + domlen + 1, 0);

		req->numserv++;
	}

	return 0;
}

static int forward_dns_reply(unsigned char *reply, int reply_len, int protocol)
{
	struct domain_hdr *hdr;
	struct request_data *req;
	unsigned char offset;
	int dns_id, sk, err;

	switch (protocol) {
	case IPPROTO_UDP:
		offset = 0;
		break;

	case IPPROTO_TCP:
		offset = 2;
		break;

	default:
		return -EINVAL;
	}

	hdr = (void *)(reply + offset);
	dns_id = reply[offset] | reply[offset + 1] << 8;

	DBG("Received %d bytes (id 0x%04x)", reply_len, dns_id);

	req = find_request(dns_id);
	if (req == NULL)
		return -EINVAL;

	DBG("id 0x%04x rcode %d", hdr->id, hdr->rcode);

	reply[offset] = req->srcid & 0xff;
	reply[offset + 1] = req->srcid >> 8;

	req->numresp++;

	if (hdr->rcode == 0 || req->resp == NULL) {
		g_free(req->resp);
		req->resplen = 0;

		req->resp = g_try_malloc(reply_len);
		if (req->resp == NULL)
			return -ENOMEM;

		memcpy(req->resp, reply, reply_len);
		req->resplen = reply_len;
	}

	if (hdr->rcode > 0 && req->numresp < req->numserv)
		return -EINVAL;

	if (req->timeout > 0)
		g_source_remove(req->timeout);

	request_list = g_slist_remove(request_list, req);

	if (protocol == IPPROTO_UDP) {
		sk = g_io_channel_unix_get_fd(udp_listener_channel);
		err = sendto(sk, req->resp, req->resplen, 0,
				(struct sockaddr *) &req->sin, req->len);
	} else {
		sk = req->client_sk;
		err = send(sk, req->resp, req->resplen, 0);
		close(sk);
	}

	g_free(req->resp);
	g_free(req);

	return err;
}


static void destroy_server(struct server_data *server)
{
	DBG("interface %s server %s", server->interface, server->server);

	if (server->watch > 0)
		g_source_remove(server->watch);

	if (server->timeout > 0)
		g_source_remove(server->timeout);

	g_io_channel_unref(server->channel);

	connman_info("Removing DNS server %s", server->server);

	g_free(server->server);
	g_free(server->domain);
	g_free(server->interface);
	g_free(server);
}

static gboolean udp_server_event(GIOChannel *channel, GIOCondition condition,
							gpointer user_data)
{
	struct server_data *data = user_data;
	unsigned char buf[4096];
	int sk, err, len;

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		connman_error("Error with server channel");
		data->watch = 0;
		return FALSE;
	}

	sk = g_io_channel_unix_get_fd(channel);

	len = recv(sk, buf, sizeof(buf), 0);
	if (len < 12)
		return TRUE;

	err = forward_dns_reply(buf, len, IPPROTO_UDP);

	return TRUE;
}

static gboolean tcp_server_event(GIOChannel *channel, GIOCondition condition,
							gpointer user_data)
{
	int sk;
	struct server_data *server = user_data;

	sk = g_io_channel_unix_get_fd(channel);
	if (sk == 0)
		return FALSE;

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		DBG("TCP server channel closed");

		server_list = g_slist_remove(server_list, server);
		destroy_server(server);

		return FALSE;
	}

	if ((condition & G_IO_OUT) && !server->connected) {
		GSList *list;

		server->connected = TRUE;
		server_list = g_slist_append(server_list, server);

		if (server->timeout > 0) {
			g_source_remove(server->timeout);
			server->timeout = 0;
		}

		for (list = request_list; list; list = list->next) {
			struct request_data *req = list->data;

			if (!req->client_sk)
				continue;

			DBG("Sending req %s over TCP", (char *)req->name);

			if (req->timeout > 0)
				g_source_remove(req->timeout);

			req->timeout = g_timeout_add_seconds(30,
						request_timeout, req);
			ns_resolv(server, req, req->request, req->name);
		}

	} else if (condition & G_IO_IN) {
		int len, bytes_recv, total_bytes_recv;
		unsigned char reply_len_buf[2];
		uint16_t reply_len;
		unsigned char *reply;

		len = recv(sk, reply_len_buf, 2, 0);
		if (len < 2)
			return TRUE;

		reply_len = reply_len_buf[1] | reply_len_buf[0] << 8;

		DBG("TCP reply %d bytes", reply_len);

		reply = g_try_malloc(reply_len + 2);
		if (reply == NULL)
			return TRUE;

		reply[0] = reply_len_buf[0];
		reply[1] = reply_len_buf[1];

		total_bytes_recv = bytes_recv = 0;
		while (total_bytes_recv < reply_len) {
			bytes_recv = recv(sk, reply + 2, reply_len, 0);
			if (bytes_recv < 0)
				return TRUE;

			total_bytes_recv += bytes_recv;
		}

		forward_dns_reply(reply, reply_len + 2, IPPROTO_TCP);

		g_free(reply);
	}

	return TRUE;
}

static gboolean tcp_idle_timeout(gpointer user_data)
{
	struct server_data *server = user_data;

	DBG("");

	if (server == NULL)
		return FALSE;

	destroy_server(server);

	return FALSE;
}

static struct server_data *create_server(const char *interface,
					const char *domain, const char *server,
					int protocol)
{
	struct server_data *data;
	struct sockaddr_in sin;
	int sk, type, ret;

	DBG("interface %s server %s", interface, server);

	switch (protocol) {
	case IPPROTO_UDP:
		type = SOCK_DGRAM;
		break;

	case IPPROTO_TCP:
		type = SOCK_STREAM;
		break;

	default:
		return NULL;
	}

	data = find_server(interface, domain, server, protocol);
	if (data)
		return data;

	sk = socket(AF_INET, type, protocol);
	if (sk < 0) {
		connman_error("Failed to create server %s socket", server);
		return NULL;
	}

	if (interface != NULL) {
		if (setsockopt(sk, SOL_SOCKET, SO_BINDTODEVICE,
				interface, strlen(interface) + 1) < 0) {
			connman_error("Failed to bind server %s "
						"to interface %s",
							server, interface);
			close(sk);
			return NULL;
		}
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

	if (protocol == IPPROTO_TCP) {
		g_io_channel_set_flags(data->channel, G_IO_FLAG_NONBLOCK, NULL);
		data->watch = g_io_add_watch(data->channel,
			G_IO_OUT | G_IO_IN | G_IO_HUP | G_IO_NVAL | G_IO_ERR,
						tcp_server_event, data);
		data->timeout = g_timeout_add_seconds(30, tcp_idle_timeout,
								data);
	} else
		data->watch = g_io_add_watch(data->channel, G_IO_IN,
						udp_server_event, data);

	data->interface = g_strdup(interface);
	data->domain = g_strdup(domain);
	data->server = g_strdup(server);
	data->protocol = protocol;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(53);
	sin.sin_addr.s_addr = inet_addr(server);

	ret = connect(sk, (struct sockaddr *) &sin, sizeof(sin));
	if (ret < 0) {
		if ((protocol == IPPROTO_TCP && errno != EINPROGRESS) ||
				protocol == IPPROTO_UDP) {
			connman_error("Failed to connect to server %s", server);
			close(sk);
			g_free(data);
			return NULL;
		}
	}

	if (protocol == IPPROTO_UDP) {
		/* Enable new servers by default */
		data->enabled = TRUE;
		connman_info("Adding DNS server %s", data->server);

		server_list = g_slist_append(server_list, data);

		return data;
	}

	return NULL;
}

static gboolean resolv(struct request_data *req,
				gpointer request, gpointer name)
{
	GSList *list;

	for (list = server_list; list; list = list->next) {
		struct server_data *data = list->data;

		DBG("server %s domain %s enabled %d",
				data->server, data->domain, data->enabled);

		if (data->enabled == FALSE)
			continue;

		if (ns_resolv(data, req, request, name) < 0)
			continue;
	}

	return TRUE;
}

static int dnsproxy_append(const char *interface, const char *domain,
							const char *server)
{
	struct server_data *data;

	DBG("interface %s server %s", interface, server);

	if (g_str_equal(server, "127.0.0.1") == TRUE)
		return -ENODEV;

	data = create_server(interface, domain, server, IPPROTO_UDP);
	if (data == NULL)
		return -EIO;

	return 0;
}

static void remove_server(const char *interface, const char *domain,
			const char *server, int protocol)
{
	struct server_data *data;

	data = find_server(interface, domain, server, protocol);
	if (data == NULL)
		return;

	server_list = g_slist_remove(server_list, data);

	destroy_server(data);
}

static int dnsproxy_remove(const char *interface, const char *domain,
							const char *server)
{
	DBG("interface %s server %s", interface, server);

	if (g_str_equal(server, "127.0.0.1") == TRUE)
		return -ENODEV;

	remove_server(interface, domain, server, IPPROTO_UDP);
	remove_server(interface, domain, server, IPPROTO_TCP);

	return 0;
}

static void dnsproxy_flush(void)
{
	GSList *list;

	list = request_pending_list;
	while (list) {
		struct request_data *req = list->data;

		list = list->next;

		request_pending_list =
				g_slist_remove(request_pending_list, req);
		resolv(req, req->request, req->name);
		g_free(req->request);
		g_free(req->name);
	}
}

static struct connman_resolver dnsproxy_resolver = {
	.name		= "dnsproxy",
	.priority	= CONNMAN_RESOLVER_PRIORITY_HIGH,
	.append		= dnsproxy_append,
	.remove		= dnsproxy_remove,
	.flush		= dnsproxy_flush,
};

static void dnsproxy_offline_mode(connman_bool_t enabled)
{
	GSList *list;

	DBG("enabled %d", enabled);

	for (list = server_list; list; list = list->next) {
		struct server_data *data = list->data;

		if (enabled == FALSE) {
			connman_info("Enabling DNS server %s", data->server);
			data->enabled = TRUE;
		} else {
			connman_info("Disabling DNS server %s", data->server);
			data->enabled = FALSE;
		}
	}
}

static void dnsproxy_default_changed(struct connman_service *service)
{
	GSList *list;
	char *interface;

	DBG("service %p", service);

	if (service == NULL) {
		/* When no services are active, then disable DNS proxying */
		dnsproxy_offline_mode(TRUE);
		return;
	}

	interface = connman_service_get_interface(service);
	if (interface == NULL)
		return;

	for (list = server_list; list; list = list->next) {
		struct server_data *data = list->data;

		if (g_strcmp0(data->interface, interface) == 0) {
			connman_info("Enabling DNS server %s", data->server);
			data->enabled = TRUE;
		} else {
			connman_info("Disabling DNS server %s", data->server);
			data->enabled = FALSE;
		}
	}

	g_free(interface);
}

static struct connman_notifier dnsproxy_notifier = {
	.name			= "dnsproxy",
	.default_changed	= dnsproxy_default_changed,
	.offline_mode		= dnsproxy_offline_mode,
};

static unsigned char opt_edns0_type[2] = { 0x00, 0x29 };

static int parse_request(unsigned char *buf, int len,
					char *name, unsigned int size)
{
	struct domain_hdr *hdr = (void *) buf;
	uint16_t qdcount = ntohs(hdr->qdcount);
	uint16_t arcount = ntohs(hdr->arcount);
	unsigned char *ptr;
	char *last_label = NULL;
	unsigned int remain, used = 0;

	if (len < 12)
		return -EINVAL;

	DBG("id 0x%04x qr %d opcode %d qdcount %d arcount %d",
					hdr->id, hdr->qr, hdr->opcode,
							qdcount, arcount);

	if (hdr->qr != 0 || qdcount != 1)
		return -EINVAL;

	memset(name, 0, size);

	ptr = buf + sizeof(struct domain_hdr);
	remain = len - sizeof(struct domain_hdr);

	while (remain > 0) {
		uint8_t len = *ptr;

		if (len == 0x00) {
			last_label = (char *) (ptr + 1);
			break;
		}

		if (used + len + 1 > size)
			return -ENOBUFS;

		strncat(name, (char *) (ptr + 1), len);
		strcat(name, ".");

		used += len + 1;

		ptr += len + 1;
		remain -= len + 1;
	}

	if (last_label && arcount && remain >= 9 && last_label[4] == 0 &&
				!memcmp(last_label + 5, opt_edns0_type, 2)) {
		uint16_t edns0_bufsize;

		edns0_bufsize = last_label[7] << 8 | last_label[8];

		DBG("EDNS0 buffer size %u", edns0_bufsize);

		/* This is an evil hack until full TCP support has been
		 * implemented.
		 *
		 * Somtimes the EDNS0 request gets send with a too-small
		 * buffer size. Since glibc doesn't seem to crash when it
		 * gets a response biffer then it requested, just bump
		 * the buffer size up to 4KiB.
		 */
		if (edns0_bufsize < 0x1000) {
			last_label[7] = 0x10;
			last_label[8] = 0x00;
		}
	}

	DBG("query %s", name);

	return 0;
}

static void send_response(int sk, unsigned char *buf, int len,
				const struct sockaddr *to, socklen_t tolen)
{
	struct domain_hdr *hdr = (void *) buf;
	int err;

	if (len < 12)
		return;

	DBG("id 0x%04x qr %d opcode %d", hdr->id, hdr->qr, hdr->opcode);

	hdr->qr = 1;
	hdr->rcode = 2;

	hdr->ancount = 0;
	hdr->nscount = 0;
	hdr->arcount = 0;

	err = sendto(sk, buf, len, 0, to, tolen);
}

static gboolean tcp_listener_event(GIOChannel *channel, GIOCondition condition,
							gpointer user_data)
{
	unsigned char buf[768];
	char query[512];
	struct request_data *req;
	struct server_data *server;
	int sk, client_sk, len, err;
	struct sockaddr client_addr;
	socklen_t client_addr_len;
	GSList *list;

	DBG("condition 0x%x", condition);

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		if (tcp_listener_watch > 0)
			g_source_remove(tcp_listener_watch);
		tcp_listener_watch = 0;

		connman_error("Error with TCP listener channel");

		return FALSE;
	}

	sk = g_io_channel_unix_get_fd(channel);

	client_addr_len = sizeof(struct sockaddr);
	client_sk = accept(sk, &client_addr, &client_addr_len);
	if (client_sk < 0) {
		connman_error("Accept failure on TCP listener");
		tcp_listener_watch = 0;
		return FALSE;
	}

	len = recv(client_sk, buf, sizeof(buf), 0);
	if (len < 2)
		return TRUE;

	DBG("Received %d bytes (id 0x%04x)", len, buf[0] | buf[1] << 8);

	err = parse_request(buf + 2, len - 2, query, sizeof(query));
	if (err < 0 || (g_slist_length(server_list) == 0 &&
				connman_ondemand_connected())) {
		send_response(client_sk, buf, len, NULL, 0);
		return TRUE;
	}

	req = g_try_new0(struct request_data, 1);
	if (req == NULL)
		return TRUE;

	memcpy(&req->sin, (struct sockaddr_in *)&client_addr, sizeof(req->sin));
	req->client_sk = client_sk;
	req->len = client_addr_len;

	request_id += 2;
	if (request_id == 0x0000 || request_id == 0xffff)
		request_id += 2;

	req->srcid = buf[2] | (buf[3] << 8);
	req->dstid = request_id;
	req->altid = request_id + 1;
	req->request_len = len;

	buf[2] = req->dstid & 0xff;
	buf[3] = req->dstid >> 8;

	req->numserv = 0;
	request_list = g_slist_append(request_list, req);

	for (list = server_list; list; list = list->next) {
		struct server_data *data = list->data;

		if (data->protocol != IPPROTO_UDP || data->enabled == FALSE)
			continue;

		server = create_server(data->interface, data->domain,
					data->server, IPPROTO_TCP);

		/*
		 * If server is NULL, we're not connected yet.
		 * Copy the relevant buffers and continue with
		 * the next nameserver.
		 * The request will actually be sent once we're
		 * properly connected over TCP to this nameserver.
		 */
		if (server == NULL) {
			req->request = g_try_malloc0(req->request_len);
			if (req->request == NULL)
				return TRUE;

			memcpy(req->request, buf, req->request_len);

			req->name = g_try_malloc0(sizeof(query));
			if (req->name == NULL) {
				g_free(req->request);
				return TRUE;
			}
			memcpy(req->name, query, sizeof(query));

			continue;
		}

		if (req->timeout > 0)
			g_source_remove(req->timeout);

		req->timeout = g_timeout_add_seconds(30, request_timeout, req);
		ns_resolv(server, req, buf, query);
	}

	return TRUE;
}

static gboolean udp_listener_event(GIOChannel *channel, GIOCondition condition,
							gpointer user_data)
{
	unsigned char buf[768];
	char query[512];
	struct request_data *req;
	struct sockaddr_in sin;
	socklen_t size = sizeof(sin);
	int sk, err, len;

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		connman_error("Error with UDP listener channel");
		udp_listener_watch = 0;
		return FALSE;
	}

	sk = g_io_channel_unix_get_fd(channel);

	memset(&sin, 0, sizeof(sin));
	len = recvfrom(sk, buf, sizeof(buf), 0,
					(struct sockaddr *) &sin, &size);
	if (len < 2)
		return TRUE;

	DBG("Received %d bytes (id 0x%04x)", len, buf[0] | buf[1] << 8);

	err = parse_request(buf, len, query, sizeof(query));
	if (err < 0 || (g_slist_length(server_list) == 0 &&
				connman_ondemand_connected())) {
		send_response(sk, buf, len, (struct sockaddr *) &sin, size);
		return TRUE;
	}

	req = g_try_new0(struct request_data, 1);
	if (req == NULL)
		return TRUE;

	memcpy(&req->sin, &sin, sizeof(sin));
	req->client_sk = 0;
	req->len = size;

	request_id += 2;
	if (request_id == 0x0000 || request_id == 0xffff)
		request_id += 2;

	req->srcid = buf[0] | (buf[1] << 8);
	req->dstid = request_id;
	req->altid = request_id + 1;
	req->request_len = len;

	buf[0] = req->dstid & 0xff;
	buf[1] = req->dstid >> 8;

	if (!connman_ondemand_connected()) {
		DBG("Starting on demand connection");
		/*
		 * We're not connected, let's queue the request and start
		 * an on-demand connection.
		 */
		req->request = g_try_malloc0(req->request_len);
		if (req->request == NULL)
			return TRUE;

		memcpy(req->request, buf, req->request_len);

		req->name = g_try_malloc0(sizeof(query));
		if (req->name == NULL) {
			g_free(req->request);
			return TRUE;
		}
		memcpy(req->name, query, sizeof(query));

		request_pending_list = g_slist_append(request_pending_list,
									req);

		connman_ondemand_start("", 300);

		return TRUE;
	}


	req->numserv = 0;
	req->timeout = g_timeout_add_seconds(5, request_timeout, req);
	request_list = g_slist_append(request_list, req);

	return resolv(req, buf, query);
}

static int create_dns_listener(int protocol)
{
	GIOChannel *channel;
	const char *ifname = "lo", *proto;
	struct sockaddr_in sin;
	int sk, type;

	DBG("");

	switch (protocol) {
	case IPPROTO_UDP:
		proto = "UDP";
		type = SOCK_DGRAM;
		break;

	case IPPROTO_TCP:
		proto = "TCP";
		type = SOCK_STREAM;
		break;

	default:
		return -EINVAL;
	}

	sk = socket(AF_INET, type, protocol);
	if (sk < 0) {
		connman_error("Failed to create %s listener socket", proto);
		return -EIO;
	}

	if (setsockopt(sk, SOL_SOCKET, SO_BINDTODEVICE,
					ifname, strlen(ifname) + 1) < 0) {
		connman_error("Failed to bind %s listener interface", proto);
		close(sk);
		return -EIO;
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(53);
	sin.sin_addr.s_addr = inet_addr("127.0.0.1");
	sin.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(sk, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
		connman_error("Failed to bind %s listener socket", proto);
		close(sk);
		return -EIO;
	}

	if (protocol == IPPROTO_TCP && listen(sk, 10) < 0) {
		connman_error("Failed to listen on TCP socket");
		close(sk);
		return -EIO;
	}

	channel = g_io_channel_unix_new(sk);
	if (channel == NULL) {
		connman_error("Failed to create %s listener channel", proto);
		close(sk);
		return -EIO;
	}

	g_io_channel_set_close_on_unref(channel, TRUE);

	if (protocol == IPPROTO_TCP) {
		tcp_listener_channel = channel;
		tcp_listener_watch = g_io_add_watch(channel,
					G_IO_IN, tcp_listener_event, NULL);
	} else {
		udp_listener_channel = channel;
		udp_listener_watch = g_io_add_watch(channel,
					G_IO_IN, udp_listener_event, NULL);
	}

	return 0;
}

static void destroy_udp_listener(void)
{
	DBG("");

	if (udp_listener_watch > 0)
		g_source_remove(udp_listener_watch);

	g_io_channel_unref(udp_listener_channel);
}

static void destroy_tcp_listener(void)
{
	DBG("");

	if (tcp_listener_watch > 0)
		g_source_remove(tcp_listener_watch);

	g_io_channel_unref(tcp_listener_channel);
}

static int create_listener(void)
{
	int err;

	err = create_dns_listener(IPPROTO_UDP);
	if (err < 0)
		return err;

	err = create_dns_listener(IPPROTO_TCP);
	if (err < 0) {
		destroy_udp_listener();
		return err;
	}

	connman_resolver_append("lo", NULL, "127.0.0.1");

	return 0;
}

static void destroy_listener(void)
{
	GSList *list;

	connman_resolver_remove_all("lo");

	for (list = request_pending_list; list; list = list->next) {
		struct request_data *req = list->data;

		DBG("Dropping pending request (id 0x%04x -> 0x%04x)",
						req->srcid, req->dstid);

		g_free(req->resp);
		g_free(req->request);
		g_free(req->name);
		g_free(req);
		list->data = NULL;
	}

	g_slist_free(request_pending_list);
	request_pending_list = NULL;

	for (list = request_list; list; list = list->next) {
		struct request_data *req = list->data;

		DBG("Dropping request (id 0x%04x -> 0x%04x)",
						req->srcid, req->dstid);

		g_free(req->resp);
		g_free(req->request);
		g_free(req->name);
		g_free(req);
		list->data = NULL;
	}

	g_slist_free(request_list);
	request_list = NULL;

	destroy_tcp_listener();
	destroy_udp_listener();
}

static int dnsproxy_init(void)
{
	int err;

	err = create_listener();
	if (err < 0)
		return err;

	err = connman_resolver_register(&dnsproxy_resolver);
	if (err < 0)
		goto destroy;

	err = connman_notifier_register(&dnsproxy_notifier);
	if (err < 0)
		goto unregister;

	return 0;

unregister:
	connman_resolver_unregister(&dnsproxy_resolver);

destroy:
	destroy_listener();

	return err;
}

static void dnsproxy_exit(void)
{
	connman_notifier_unregister(&dnsproxy_notifier);

	connman_resolver_unregister(&dnsproxy_resolver);

	destroy_listener();
}

CONNMAN_PLUGIN_DEFINE(dnsproxy, "DNS proxy resolver plugin", VERSION,
		 CONNMAN_PLUGIN_PRIORITY_DEFAULT, dnsproxy_init, dnsproxy_exit)
