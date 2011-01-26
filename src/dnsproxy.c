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
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <glib.h>

#include "connman.h"

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

struct partial_reply {
	uint16_t len;
	uint16_t received;
	unsigned char buf[];
};

struct server_data {
	char *interface;
	GList *domains;
	char *server;
	int protocol;
	GIOChannel *channel;
	guint watch;
	guint timeout;
	gboolean enabled;
	gboolean connected;
	struct partial_reply *incoming_reply;
};

struct request_data {
	union {
		struct sockaddr_in6 __sin6; /* Only for the length */
		struct sockaddr sa;
	};
	socklen_t sa_len;
	int client_sk;
	int protocol;
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

static connman_bool_t dnsproxy_enabled = TRUE;
static GSList *server_list = NULL;
static GSList *request_list = NULL;
static GSList *request_pending_list = NULL;
static guint16 request_id = 0x0000;

static GIOChannel *udp_listener_channel = NULL;
static guint udp_listener_watch = 0;
static GIOChannel *tcp_listener_channel = NULL;
static guint tcp_listener_watch = 0;

static int protocol_offset(int protocol)
{
	switch (protocol) {
	case IPPROTO_UDP:
		return 0;

	case IPPROTO_TCP:
		return 2;

	default:
		return -EINVAL;
	}

}

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
					const char *server,
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
				data->protocol == protocol)
			return data;
	}

	return NULL;
}


static void send_response(int sk, unsigned char *buf, int len,
				const struct sockaddr *to, socklen_t tolen,
				int protocol)
{
	struct domain_hdr *hdr;
	int err, offset = protocol_offset(protocol);

	DBG("");

	if (offset < 0)
		return;

	if (len < 12)
		return;

	hdr = (void *) (buf + offset);

	DBG("id 0x%04x qr %d opcode %d", hdr->id, hdr->qr, hdr->opcode);

	hdr->qr = 1;
	hdr->rcode = 2;

	hdr->ancount = 0;
	hdr->nscount = 0;
	hdr->arcount = 0;

	err = sendto(sk, buf, len, 0, to, tolen);
}

static gboolean request_timeout(gpointer user_data)
{
	struct request_data *req = user_data;

	DBG("id 0x%04x", req->srcid);

	if (req == NULL)
		return FALSE;

	request_list = g_slist_remove(request_list, req);
	req->numserv--;

	if (req->resplen > 0 && req->resp != NULL) {
		int sk, err;

		sk = g_io_channel_unix_get_fd(udp_listener_channel);

		err = sendto(sk, req->resp, req->resplen, 0,
			     &req->sa, req->sa_len);
	} else if (req->request && req->numserv == 0) {
		struct domain_hdr *hdr;

		if (req->protocol == IPPROTO_TCP) {
			hdr = (void *) (req->request + 2);
			hdr->id = req->srcid;
			send_response(req->client_sk, req->request,
					req->request_len, NULL, 0, IPPROTO_TCP);

		} else if (req->protocol == IPPROTO_UDP) {
			int sk;

			hdr = (void *) (req->request);
			hdr->id = req->srcid;
			sk = g_io_channel_unix_get_fd(udp_listener_channel);
			send_response(sk, req->request, req->request_len,
				      &req->sa, req->sa_len, IPPROTO_UDP);
		}
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
	GList *list;
	int sk, err;

	sk = g_io_channel_unix_get_fd(server->channel);

	err = send(sk, request, req->request_len, 0);

	req->numserv++;

	for (list = server->domains; list; list = list->next) {
		char *domain;
		unsigned char alt[1024];
		struct domain_hdr *hdr = (void *) &alt;
		int altlen, domlen, offset;

		domain = list->data;

		if (domain == NULL)
			continue;

		offset = protocol_offset(server->protocol);
		if (offset < 0)
			return offset;

		domlen = strlen(domain) + 1;
		if (domlen < 5)
			return -EINVAL;

		alt[offset] = req->altid & 0xff;
		alt[offset + 1] = req->altid >> 8;

		memcpy(alt + offset + 2, request + offset + 2, 10);
		hdr->qdcount = htons(1);

		altlen = append_query(alt + offset + 12, sizeof(alt) - 12,
					name, domain);
		if (altlen < 0)
			return -EINVAL;

		altlen += 12;

		memcpy(alt + offset + altlen,
			request + offset + altlen - domlen,
				req->request_len - altlen + domlen);

		if (server->protocol == IPPROTO_TCP) {
			int req_len = req->request_len + domlen - 1;

			alt[0] = (req_len >> 8) & 0xff;
			alt[1] = req_len & 0xff;
		}

		err = send(sk, alt, req->request_len + domlen + 1, 0);

		req->numserv++;
	}

	return 0;
}

static int forward_dns_reply(unsigned char *reply, int reply_len, int protocol)
{
	struct domain_hdr *hdr;
	struct request_data *req;
	int dns_id, sk, err, offset = protocol_offset(protocol);

	if (offset < 0)
		return offset;

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
			     &req->sa, req->sa_len);
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
	GList *list;

	DBG("interface %s server %s", server->interface, server->server);

	server_list = g_slist_remove(server_list, server);

	if (server->watch > 0)
		g_source_remove(server->watch);

	if (server->timeout > 0)
		g_source_remove(server->timeout);

	g_io_channel_unref(server->channel);

	if (server->protocol == IPPROTO_UDP)
		connman_info("Removing DNS server %s", server->server);

	g_free(server->incoming_reply);
	g_free(server->server);
	for (list = server->domains; list; list = list->next) {
		char *domain = list->data;

		server->domains = g_list_remove(server->domains, domain);
		g_free(domain);
	}
	g_free(server->interface);
	g_free(server);
}

static gboolean udp_server_event(GIOChannel *channel, GIOCondition condition,
							gpointer user_data)
{
	unsigned char buf[4096];
	int sk, err, len;

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		struct server_data *data = user_data;

		connman_error("Error with UDP server %s", data->server);
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
		GSList *list;
hangup:
		DBG("TCP server channel closed");

		/*
		 * Discard any partial response which is buffered; better
		 * to get a proper response from a working server.
		 */
		g_free(server->incoming_reply);
		server->incoming_reply = NULL;

		for (list = request_list; list; list = list->next) {
			struct request_data *req = list->data;
			struct domain_hdr *hdr;

			if (req->protocol == IPPROTO_UDP)
				continue;

			if (req->request == NULL)
				continue;

			/*
			 * If we're not waiting for any further response
			 * from another name server, then we send an error
			 * response to the client.
			 */
			if (req->numserv && --(req->numserv))
				continue;

			hdr = (void *) (req->request + 2);
			hdr->id = req->srcid;
			send_response(req->client_sk, req->request,
					req->request_len, NULL, 0, IPPROTO_TCP);

			request_list = g_slist_remove(request_list, req);
		}

		destroy_server(server);

		return FALSE;
	}

	if ((condition & G_IO_OUT) && !server->connected) {
		GSList *list;
		GList *domains;
		struct server_data *udp_server;

		udp_server = find_server(server->interface, server->server,
								IPPROTO_UDP);
		if (udp_server != NULL) {
			for (domains = udp_server->domains; domains;
						domains = domains->next) {
				char *dom = domains->data;

				DBG("Adding domain %s to %s",
						dom, server->server);

				server->domains = g_list_append(server->domains,
								g_strdup(dom));
			}
		}

		server->connected = TRUE;
		server_list = g_slist_append(server_list, server);

		if (server->timeout > 0) {
			g_source_remove(server->timeout);
			server->timeout = 0;
		}

		for (list = request_list; list; list = list->next) {
			struct request_data *req = list->data;

			if (req->protocol == IPPROTO_UDP)
				continue;

			DBG("Sending req %s over TCP", (char *)req->name);

			if (req->timeout > 0)
				g_source_remove(req->timeout);

			req->timeout = g_timeout_add_seconds(30,
						request_timeout, req);
			ns_resolv(server, req, req->request, req->name);
		}

	} else if (condition & G_IO_IN) {
		struct partial_reply *reply = server->incoming_reply;
		int bytes_recv;

		if (!reply) {
			unsigned char reply_len_buf[2];
			uint16_t reply_len;

			bytes_recv = recv(sk, reply_len_buf, 2, MSG_PEEK);
			if (!bytes_recv) {
				goto hangup;
			} else if (bytes_recv < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					return TRUE;

				connman_error("DNS proxy error %s",
						strerror(errno));
				goto hangup;
			} else if (bytes_recv < 2)
				return TRUE;

			reply_len = reply_len_buf[1] | reply_len_buf[0] << 8;
			reply_len += 2;

			DBG("TCP reply %d bytes", reply_len);

			reply = g_try_malloc(sizeof(*reply) + reply_len + 2);
			if (!reply)
				return TRUE;

			reply->len = reply_len;
			reply->received = 0;

			server->incoming_reply = reply;
		}

		while (reply->received < reply->len) {
			bytes_recv = recv(sk, reply->buf + reply->received,
					reply->len - reply->received, 0);
			if (!bytes_recv) {
				connman_error("DNS proxy TCP disconnect");
				break;
			} else if (bytes_recv < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					return TRUE;

				connman_error("DNS proxy error %s",
						strerror(errno));
				break;
			}
			reply->received += bytes_recv;
		}

		forward_dns_reply(reply->buf, reply->received, IPPROTO_TCP);

		g_free(reply);
		server->incoming_reply = NULL;

		destroy_server(server);

		return FALSE;
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
	struct addrinfo hints, *rp;
	struct server_data *data;
	int sk, ret;

	DBG("interface %s server %s", interface, server);

	memset(&hints, 0, sizeof(hints));

	switch (protocol) {
	case IPPROTO_UDP:
		hints.ai_socktype = SOCK_DGRAM;
		break;

	case IPPROTO_TCP:
		hints.ai_socktype = SOCK_STREAM;
		break;

	default:
		return NULL;
	}
	hints.ai_family = AF_UNSPEC;
	hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV | AI_NUMERICHOST;

	ret = getaddrinfo(server, "53", &hints, &rp);
	if (ret) {
		connman_error("Failed to parse server %s address: %s\n",
			      server, gai_strerror(ret));
		return NULL;
	}
	/* Do not blindly copy this code elsewhere; it doesn't loop over the
	   results using ->ai_next as it should. That's OK in *this* case
	   because it was a numeric lookup; we *know* there's only one. */

	sk = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
	if (sk < 0) {
		connman_error("Failed to create server %s socket", server);
		freeaddrinfo(rp);
		return NULL;
	}

	if (interface != NULL) {
		if (setsockopt(sk, SOL_SOCKET, SO_BINDTODEVICE,
				interface, strlen(interface) + 1) < 0) {
			connman_error("Failed to bind server %s "
						"to interface %s",
							server, interface);
			freeaddrinfo(rp);
			close(sk);
			return NULL;
		}
	}

	data = g_try_new0(struct server_data, 1);
	if (data == NULL) {
		connman_error("Failed to allocate server %s data", server);
		freeaddrinfo(rp);
		close(sk);
		return NULL;
	}

	data->channel = g_io_channel_unix_new(sk);
	if (data->channel == NULL) {
		connman_error("Failed to create server %s channel", server);
		freeaddrinfo(rp);
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
		data->watch = g_io_add_watch(data->channel,
			G_IO_IN | G_IO_NVAL | G_IO_ERR | G_IO_HUP,
						udp_server_event, data);

	data->interface = g_strdup(interface);
	if (domain)
		data->domains = g_list_append(data->domains, g_strdup(domain));
	data->server = g_strdup(server);
	data->protocol = protocol;

	ret = connect(sk, rp->ai_addr, rp->ai_addrlen);
	freeaddrinfo(rp);
	if (ret < 0) {
		if ((protocol == IPPROTO_TCP && errno != EINPROGRESS) ||
				protocol == IPPROTO_UDP) {
			GList *list;

			connman_error("Failed to connect to server %s", server);
			if (data->watch > 0)
				g_source_remove(data->watch);
			if (data->timeout > 0)
				g_source_remove(data->timeout);

			g_io_channel_unref(data->channel);
			close(sk);

			g_free(data->server);
			g_free(data->interface);
			for (list = data->domains; list; list = list->next) {
				char *domain = list->data;

				data->domains = g_list_remove(data->domains,
									domain);
				g_free(domain);
			}
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

		DBG("server %s enabled %d", data->server, data->enabled);

		if (data->enabled == FALSE)
			continue;

		if (data->watch == 0 && data->protocol == IPPROTO_UDP)
			data->watch = g_io_add_watch(data->channel,
				G_IO_IN | G_IO_NVAL | G_IO_ERR | G_IO_HUP,
						udp_server_event, data);

		if (ns_resolv(data, req, request, name) < 0)
			continue;
	}

	return TRUE;
}

static void append_domain(const char *interface, const char *domain)
{
	GSList *list;

	DBG("interface %s domain %s", interface, domain);

	for (list = server_list; list; list = list->next) {
		struct server_data *data = list->data;
		GList *dom_list;
		char *dom;
		gboolean dom_found = FALSE;

		if (data->interface == NULL)
			continue;

		if (g_str_equal(data->interface, interface) == FALSE)
			continue;

		for (dom_list = data->domains; dom_list;
				dom_list = dom_list->next) {
			dom = dom_list->data;

			if (g_str_equal(dom, domain)) {
				dom_found = TRUE;
				break;
			}
		}

		if (dom_found == FALSE) {
			data->domains =
				g_list_append(data->domains, g_strdup(domain));
		}
	}
}

int __connman_dnsproxy_append(const char *interface, const char *domain,
							const char *server)
{
	struct server_data *data;

	DBG("interface %s server %s", interface, server);

	if (server == NULL && domain == NULL)
		return -EINVAL;

	if (server == NULL) {
		append_domain(interface, domain);

		return 0;
	}

	if (g_str_equal(server, "127.0.0.1") == TRUE)
		return -ENODEV;

	data = find_server(interface, server, IPPROTO_UDP);
	if (data != NULL) {
		append_domain(interface, domain);
		return 0;
	}

	data = create_server(interface, domain, server, IPPROTO_UDP);
	if (data == NULL)
		return -EIO;

	return 0;
}

static void remove_server(const char *interface, const char *domain,
			const char *server, int protocol)
{
	struct server_data *data;

	data = find_server(interface, server, protocol);
	if (data == NULL)
		return;

	destroy_server(data);
}

int __connman_dnsproxy_remove(const char *interface, const char *domain,
							const char *server)
{
	DBG("interface %s server %s", interface, server);

	if (server == NULL)
		return -EINVAL;

	if (g_str_equal(server, "127.0.0.1") == TRUE)
		return -ENODEV;

	remove_server(interface, domain, server, IPPROTO_UDP);
	remove_server(interface, domain, server, IPPROTO_TCP);

	return 0;
}

void __connman_dnsproxy_flush(void)
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

static gboolean tcp_listener_event(GIOChannel *channel, GIOCondition condition,
							gpointer user_data)
{
	unsigned char buf[768];
	char query[512];
	struct request_data *req;
	struct server_data *server;
	int sk, client_sk, len, err;
	struct sockaddr_in6 client_addr;
	socklen_t client_addr_len = sizeof(client_addr);
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

	client_sk = accept(sk, (void *)&client_addr, &client_addr_len);
	if (client_sk < 0) {
		connman_error("Accept failure on TCP listener");
		tcp_listener_watch = 0;
		return FALSE;
	}

	len = recv(client_sk, buf, sizeof(buf), 0);
	if (len < 2)
		return TRUE;

	DBG("Received %d bytes (id 0x%04x)", len, buf[2] | buf[3] << 8);

	err = parse_request(buf + 2, len - 2, query, sizeof(query));
	if (err < 0 || (g_slist_length(server_list) == 0)) {
		send_response(client_sk, buf, len, NULL, 0, IPPROTO_TCP);
		return TRUE;
	}

	req = g_try_new0(struct request_data, 1);
	if (req == NULL)
		return TRUE;

	memcpy(&req->sa, &client_addr, client_addr_len);
	req->sa_len = client_addr_len;
	req->client_sk = client_sk;
	req->protocol = IPPROTO_TCP;

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
		GList *domains;

		if (data->protocol != IPPROTO_UDP || data->enabled == FALSE)
			continue;

		server = create_server(data->interface, NULL,
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

		for (domains = data->domains; domains;
				domains = domains->next) {
			char *dom = domains->data;

			DBG("Adding domain %s to %s", dom, server->server);

			server->domains = g_list_append(server->domains,
						g_strdup(dom));
		}

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
	struct sockaddr_in6 client_addr;
	socklen_t client_addr_len = sizeof(client_addr);
	int sk, err, len;

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		connman_error("Error with UDP listener channel");
		udp_listener_watch = 0;
		return FALSE;
	}

	sk = g_io_channel_unix_get_fd(channel);

	memset(&client_addr, 0, client_addr_len);
	len = recvfrom(sk, buf, sizeof(buf), 0, (void *)&client_addr,
		       &client_addr_len);
	if (len < 2)
		return TRUE;

	DBG("Received %d bytes (id 0x%04x)", len, buf[0] | buf[1] << 8);

	err = parse_request(buf, len, query, sizeof(query));
	if (err < 0 || (g_slist_length(server_list) == 0)) {
		send_response(sk, buf, len, (void *)&client_addr,
			      client_addr_len, IPPROTO_UDP);
		return TRUE;
	}

	req = g_try_new0(struct request_data, 1);
	if (req == NULL)
		return TRUE;

	memcpy(&req->sa, &client_addr, client_addr_len);
	req->sa_len = client_addr_len;
	req->client_sk = 0;
	req->protocol = IPPROTO_UDP;

	request_id += 2;
	if (request_id == 0x0000 || request_id == 0xffff)
		request_id += 2;

	req->srcid = buf[0] | (buf[1] << 8);
	req->dstid = request_id;
	req->altid = request_id + 1;
	req->request_len = len;

	buf[0] = req->dstid & 0xff;
	buf[1] = req->dstid >> 8;

	req->numserv = 0;
	req->timeout = g_timeout_add_seconds(5, request_timeout, req);
	request_list = g_slist_append(request_list, req);

	return resolv(req, buf, query);
}

static int create_dns_listener(int protocol)
{
	GIOChannel *channel;
	const char *ifname = "lo", *proto;
	union {
		struct sockaddr sa;
		struct sockaddr_in6 sin6;
		struct sockaddr_in sin;
	} s;
	socklen_t slen;
	int sk, type, v6only = 0;
	int family = AF_INET6;

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

	sk = socket(family, type, protocol);
	if (sk < 0 && family == AF_INET6 && errno == EAFNOSUPPORT) {
		connman_error("No IPv6 support; DNS proxy listening only on Legacy IP");
		family = AF_INET;
		sk = socket(family, type, protocol);
	}
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
	/* Ensure it accepts Legacy IP connections too */
	if (family == AF_INET6 &&
			setsockopt(sk, SOL_IPV6, IPV6_V6ONLY,
					&v6only, sizeof(v6only)) < 0) {
		connman_error("Failed to clear V6ONLY on %s listener socket",
			      proto);
		close(sk);
		return -EIO;
	}

	if (family == AF_INET) {
		memset(&s.sin, 0, sizeof(s.sin));
		s.sin.sin_family = AF_INET;
		s.sin.sin_port = htons(53);
		s.sin.sin_addr.s_addr = htonl(INADDR_ANY);
		slen = sizeof(s.sin);
	} else {
		memset(&s.sin6, 0, sizeof(s.sin6));
		s.sin6.sin6_family = AF_INET6;
		s.sin6.sin6_port = htons(53);
		s.sin6.sin6_addr = in6addr_any;
		slen = sizeof(s.sin6);
	}

	if (bind(sk, &s.sa, slen) < 0) {
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

	__connman_resolvfile_append("lo", NULL, "127.0.0.1");

	return 0;
}

static void destroy_listener(void)
{
	GSList *list;

	__connman_resolvfile_remove("lo", NULL, "127.0.0.1");

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

int __connman_dnsproxy_init(connman_bool_t dnsproxy)
{
	int err;

	DBG("dnsproxy %d", dnsproxy);

	dnsproxy_enabled = dnsproxy;
	if (dnsproxy_enabled == FALSE)
		return 0;

	err = create_listener();
	if (err < 0)
		return err;

	err = connman_notifier_register(&dnsproxy_notifier);
	if (err < 0)
		goto destroy;

	return 0;

destroy:
	destroy_listener();

	return err;
}

void __connman_dnsproxy_cleanup(void)
{
	DBG("");

	if (dnsproxy_enabled == FALSE)
		return;

	connman_notifier_unregister(&dnsproxy_notifier);

	destroy_listener();
}
