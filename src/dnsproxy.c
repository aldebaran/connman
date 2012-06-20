/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2012  Intel Corporation. All rights reserved.
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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <resolv.h>
#include <gweb/gresolv.h>

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
	struct listener_data *ifdata;
	gboolean append_domain;
};

struct listener_data {
	char *ifname;
	GIOChannel *udp_listener_channel;
	guint udp_listener_watch;
	GIOChannel *tcp_listener_channel;
	guint tcp_listener_watch;
};

struct cache_data {
	time_t inserted;
	time_t valid_until;
	time_t cache_until;
	int timeout;
	uint16_t type;
	uint16_t answers;
	unsigned int data_len;
	unsigned char *data; /* contains DNS header + body */
};

struct cache_entry {
	char *key;
	int want_refresh;
	int hits;
	struct cache_data *ipv4;
	struct cache_data *ipv6;
};

struct domain_question {
	uint16_t type;
	uint16_t class;
} __attribute__ ((packed));

struct domain_rr {
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t rdlen;
} __attribute__ ((packed));

/*
 * We limit how long the cached DNS entry stays in the cache.
 * By default the TTL (time-to-live) of the DNS response is used
 * when setting the cache entry life time. The value is in seconds.
 */
#define MAX_CACHE_TTL (60 * 30)
/*
 * Also limit the other end, cache at least for 30 seconds.
 */
#define MIN_CACHE_TTL (30)

/*
 * We limit the cache size to some sane value so that cached data does
 * not occupy too much memory. Each cached entry occupies on average
 * about 100 bytes memory (depending on DNS name length).
 * Example: caching www.connman.net uses 97 bytes memory.
 * The value is the max amount of cached DNS responses (count).
 */
#define MAX_CACHE_SIZE 256

static int cache_size;
static GHashTable *cache;
static int cache_refcount;
static GSList *server_list = NULL;
static GSList *request_list = NULL;
static GHashTable *listener_table = NULL;
static time_t next_refresh;

static guint16 get_id()
{
	return random();
}

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

/*
 * There is a power and efficiency benefit to have entries
 * in our cache expire at the same time. To this extend,
 * we round down the cache valid time to common boundaries.
 */
static time_t round_down_ttl(time_t end_time, int ttl)
{
	if (ttl < 15)
		return end_time;

	/* Less than 5 minutes, round to 10 second boundary */
	if (ttl < 300) {
		end_time = end_time / 10;
		end_time = end_time * 10;
	} else { /* 5 or more minutes, round to 30 seconds */
		end_time = end_time / 30;
		end_time = end_time * 30;
	}
	return end_time;
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

		if (interface == NULL && data->interface == NULL &&
				g_str_equal(data->server, server) == TRUE &&
				data->protocol == protocol)
			return data;

		if (interface == NULL ||
				data->interface == NULL || data->server == NULL)
			continue;

		if (g_str_equal(data->interface, interface) == TRUE &&
				g_str_equal(data->server, server) == TRUE &&
				data->protocol == protocol)
			return data;
	}

	return NULL;
}

/* we can keep using the same resolve's */
static GResolv *ipv4_resolve;
static GResolv *ipv6_resolve;

static void dummy_resolve_func(GResolvResultStatus status,
					char **results, gpointer user_data)
{
}

/*
 * Refresh a DNS entry, but also age the hit count a bit */
static void refresh_dns_entry(struct cache_entry *entry, char *name)
{
	int age = 1;

	if (ipv4_resolve == NULL) {
		ipv4_resolve = g_resolv_new(0);
		g_resolv_set_address_family(ipv4_resolve, AF_INET);
		g_resolv_add_nameserver(ipv4_resolve, "127.0.0.1", 53, 0);
	}

	if (ipv6_resolve == NULL) {
		ipv6_resolve = g_resolv_new(0);
		g_resolv_set_address_family(ipv6_resolve, AF_INET6);
		g_resolv_add_nameserver(ipv6_resolve, "127.0.0.1", 53, 0);
	}

	if (entry->ipv4 == NULL) {
		DBG("Refresing A record for %s", name);
		g_resolv_lookup_hostname(ipv4_resolve, name,
					dummy_resolve_func, NULL);
		age = 4;
	}

	if (entry->ipv6 == NULL) {
		DBG("Refresing AAAA record for %s", name);
		g_resolv_lookup_hostname(ipv6_resolve, name,
					dummy_resolve_func, NULL);
		age = 4;
	}

	entry->hits -= age;
	if (entry->hits < 0)
		entry->hits = 0;
}

static int dns_name_length(unsigned char *buf)
{
	if ((buf[0] & NS_CMPRSFLGS) == NS_CMPRSFLGS) /* compressed name */
		return 2;
	return strlen((char *)buf);
}

static void update_cached_ttl(unsigned char *buf, int len, int new_ttl)
{
	unsigned char *c;
	uint32_t *i;
	uint16_t *w;
	int l;

	/* skip the header */
	c = buf + 12;
	len -= 12;

	/* skip the query, which is a name and 2 16 bit words */
	l = dns_name_length(c);
	c += l;
	len -= l;
	c += 4;
	len -= 4;

	/* now we get the answer records */

	while (len > 0) {
		/* first a name */
		l = dns_name_length(c);
		c += l;
		len -= l;
		if (len < 0)
			break;
		/* then type + class, 2 bytes each */
		c += 4;
		len -= 4;
		if (len < 0)
			break;

		/* now the 4 byte TTL field */
		i = (uint32_t *)c;
		*i = htonl(new_ttl);
		c += 4;
		len -= 4;
		if (len < 0)
			break;

		/* now the 2 byte rdlen field */
		w = (uint16_t *)c;
		c += ntohs(*w) + 2;
		len -= ntohs(*w) + 2;
	}
}

static void send_cached_response(int sk, unsigned char *buf, int len,
				const struct sockaddr *to, socklen_t tolen,
				int protocol, int id, uint16_t answers, int ttl)
{
	struct domain_hdr *hdr;
	unsigned char *ptr = buf;
	int err, offset, dns_len, adj_len = len - 2;

	/*
	 * The cached packet contains always the TCP offset (two bytes)
	 * so skip them for UDP.
	 */
	switch (protocol) {
	case IPPROTO_UDP:
		ptr += 2;
		len -= 2;
		dns_len = len;
		offset = 0;
		break;
	case IPPROTO_TCP:
		offset = 2;
		dns_len = ptr[0] * 256 + ptr[1];
		break;
	default:
		return;
	}

	if (len < 12)
		return;

	hdr = (void *) (ptr + offset);

	hdr->id = id;
	hdr->qr = 1;
	hdr->rcode = 0;
	hdr->ancount = htons(answers);
	hdr->nscount = 0;
	hdr->arcount = 0;

	/* if this is a negative reply, we are authorative */
	if (answers == 0)
		hdr->aa = 1;
	else
		update_cached_ttl((unsigned char *)hdr, adj_len, ttl);

	DBG("sk %d id 0x%04x answers %d ptr %p length %d dns %d",
		sk, hdr->id, answers, ptr, len, dns_len);

	err = sendto(sk, ptr, len, MSG_NOSIGNAL, to, tolen);
	if (err < 0) {
		connman_error("Cannot send cached DNS response: %s",
				strerror(errno));
		return;
	}

	if (err != len || (dns_len != (len - 2) && protocol == IPPROTO_TCP) ||
				(dns_len != len && protocol == IPPROTO_UDP))
		DBG("Packet length mismatch, sent %d wanted %d dns %d",
			err, len, dns_len);
}

static void send_response(int sk, unsigned char *buf, int len,
				const struct sockaddr *to, socklen_t tolen,
				int protocol)
{
	struct domain_hdr *hdr;
	int err, offset = protocol_offset(protocol);

	DBG("sk %d", sk);

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

	err = sendto(sk, buf, len, MSG_NOSIGNAL, to, tolen);
	if (err < 0) {
		connman_error("Failed to send DNS response to %d: %s",
				sk, strerror(errno));
		return;
	}
}

static gboolean request_timeout(gpointer user_data)
{
	struct request_data *req = user_data;
	struct listener_data *ifdata;

	DBG("id 0x%04x", req->srcid);

	if (req == NULL)
		return FALSE;

	ifdata = req->ifdata;

	request_list = g_slist_remove(request_list, req);
	req->numserv--;

	if (req->resplen > 0 && req->resp != NULL) {
		int sk, err;

		sk = g_io_channel_unix_get_fd(ifdata->udp_listener_channel);

		err = sendto(sk, req->resp, req->resplen, MSG_NOSIGNAL,
						&req->sa, req->sa_len);
		if (err < 0)
			return FALSE;
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
			sk = g_io_channel_unix_get_fd(
						ifdata->udp_listener_channel);
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
	int len;

	DBG("query %s domain %s", query, domain);

	while (query != NULL) {
		const char *tmp;

		tmp = strchr(query, '.');
		if (tmp == NULL) {
			len = strlen(query);
			if (len == 0)
				break;
			*ptr = len;
			memcpy(ptr + 1, query, len);
			ptr += len + 1;
			break;
		}

		*ptr = tmp - query;
		memcpy(ptr + 1, query, tmp - query);
		ptr += tmp - query + 1;

		query = tmp + 1;
	}

	while (domain != NULL) {
		const char *tmp;

		tmp = strchr(domain, '.');
		if (tmp == NULL) {
			len = strlen(domain);
			if (len == 0)
				break;
			*ptr = len;
			memcpy(ptr + 1, domain, len);
			ptr += len + 1;
			break;
		}

		*ptr = tmp - domain;
		memcpy(ptr + 1, domain, tmp - domain);
		ptr += tmp - domain + 1;

		domain = tmp + 1;
	}

	*ptr++ = 0x00;

	return ptr - buf;
}

static gboolean cache_check_is_valid(struct cache_data *data,
				time_t current_time)
{
	if (data == NULL)
		return FALSE;

	if (data->cache_until < current_time)
		return FALSE;

	return TRUE;
}

/*
 * remove stale cached entries so that they can be refreshed
 */
static void cache_enforce_validity(struct cache_entry *entry)
{
	time_t current_time = time(NULL);

	if (cache_check_is_valid(entry->ipv4, current_time) == FALSE
							&& entry->ipv4) {
		DBG("cache timeout \"%s\" type A", entry->key);
		g_free(entry->ipv4->data);
		g_free(entry->ipv4);
		entry->ipv4 = NULL;

	}

	if (cache_check_is_valid(entry->ipv6, current_time) == FALSE
							&& entry->ipv6) {
		DBG("cache timeout \"%s\" type AAAA", entry->key);
		g_free(entry->ipv6->data);
		g_free(entry->ipv6);
		entry->ipv6 = NULL;
	}
}

static uint16_t cache_check_validity(char *question, uint16_t type,
				struct cache_entry *entry)
{
	time_t current_time = time(NULL);
	int want_refresh = 0;

	/*
	 * if we have a popular entry, we want a refresh instead of
	 * total destruction of the entry.
	 */
	if (entry->hits > 2)
		want_refresh = 1;

	cache_enforce_validity(entry);

	switch (type) {
	case 1:		/* IPv4 */
		if (cache_check_is_valid(entry->ipv4, current_time) == FALSE) {
			DBG("cache %s \"%s\" type A", entry->ipv4 ?
					"timeout" : "entry missing", question);

			if (want_refresh)
				entry->want_refresh = 1;

			/*
			 * We do not remove cache entry if there is still
			 * valid IPv6 entry found in the cache.
			 */
			if (cache_check_is_valid(entry->ipv6, current_time)
					== FALSE && want_refresh == FALSE) {
				g_hash_table_remove(cache, question);
				type = 0;
			}
		}
		break;

	case 28:	/* IPv6 */
		if (cache_check_is_valid(entry->ipv6, current_time) == FALSE) {
			DBG("cache %s \"%s\" type AAAA", entry->ipv6 ?
					"timeout" : "entry missing", question);

			if (want_refresh)
				entry->want_refresh = 1;

			if (cache_check_is_valid(entry->ipv4, current_time)
					== FALSE && want_refresh == FALSE) {
				g_hash_table_remove(cache, question);
				type = 0;
			}
		}
		break;
	}

	return type;
}

static struct cache_entry *cache_check(gpointer request, int *qtype, int proto)
{
	char *question;
	struct cache_entry *entry;
	struct domain_question *q;
	uint16_t type;
	int offset, proto_offset;

	if (request == NULL)
		return NULL;

	proto_offset = protocol_offset(proto);
	if (proto_offset < 0)
		return NULL;

	question = request + proto_offset + 12;

	offset = strlen(question) + 1;
	q = (void *) (question + offset);
	type = ntohs(q->type);

	/* We only cache either A (1) or AAAA (28) requests */
	if (type != 1 && type != 28)
		return NULL;

	entry = g_hash_table_lookup(cache, question);
	if (entry == NULL)
		return NULL;

	type = cache_check_validity(question, type, entry);
	if (type == 0)
		return NULL;

	*qtype = type;
	return entry;
}

/*
 * Get a label/name from DNS resource record. The function decompresses the
 * label if necessary. The function does not convert the name to presentation
 * form. This means that the result string will contain label lengths instead
 * of dots between labels. We intentionally do not want to convert to dotted
 * format so that we can cache the wire format string directly.
 */
static int get_name(int counter,
		unsigned char *pkt, unsigned char *start, unsigned char *max,
		unsigned char *output, int output_max, int *output_len,
		unsigned char **end, char *name, int *name_len)
{
	unsigned char *p;

	/* Limit recursion to 10 (this means up to 10 labels in domain name) */
	if (counter > 10)
		return -EINVAL;

	p = start;
	while (*p) {
		if ((*p & NS_CMPRSFLGS) == NS_CMPRSFLGS) {
			uint16_t offset = (*p & 0x3F) * 256 + *(p + 1);

			if (offset >= max - pkt)
				return -ENOBUFS;

			if (*end == NULL)
				*end = p + 2;

			return get_name(counter + 1, pkt, pkt + offset, max,
					output, output_max, output_len, end,
					name, name_len);
		} else {
			unsigned label_len = *p;

			if (pkt + label_len > max)
				return -ENOBUFS;

			if (*output_len > output_max)
				return -ENOBUFS;

			/*
			 * We need the original name in order to check
			 * if this answer is the correct one.
			 */
			name[(*name_len)++] = label_len;
			memcpy(name + *name_len, p + 1,	label_len + 1);
			*name_len += label_len;

			/* We compress the result */
			output[0] = NS_CMPRSFLGS;
			output[1] = 0x0C;
			*output_len = 2;

			p += label_len + 1;

			if (*end == NULL)
				*end = p;

			if (p >= max)
				return -ENOBUFS;
		}
	}

	return 0;
}

static int parse_rr(unsigned char *buf, unsigned char *start,
			unsigned char *max,
			unsigned char *response, unsigned int *response_size,
			uint16_t *type, uint16_t *class, int *ttl, int *rdlen,
			unsigned char **end,
			char *name)
{
	struct domain_rr *rr;
	int err, offset;
	int name_len = 0, output_len = 0, max_rsp = *response_size;

	err = get_name(0, buf, start, max, response, max_rsp,
		&output_len, end, name, &name_len);
	if (err < 0)
		return err;

	offset = output_len;

	if ((unsigned int) offset > *response_size)
		return -ENOBUFS;

	rr = (void *) (*end);

	if (rr == NULL)
		return -EINVAL;

	*type = ntohs(rr->type);
	*class = ntohs(rr->class);
	*ttl = ntohl(rr->ttl);
	*rdlen = ntohs(rr->rdlen);

	if (*ttl < 0)
		return -EINVAL;

	memcpy(response + offset, *end, sizeof(struct domain_rr));

	offset += sizeof(struct domain_rr);
	*end += sizeof(struct domain_rr);

	if ((unsigned int) (offset + *rdlen) > *response_size)
		return -ENOBUFS;

	memcpy(response + offset, *end, *rdlen);

	*end += *rdlen;

	*response_size = offset + *rdlen;

	return 0;
}

static gboolean check_alias(GSList *aliases, char *name)
{
	GSList *list;

	if (aliases != NULL) {
		for (list = aliases; list; list = list->next) {
			int len = strlen((char *)list->data);
			if (strncmp((char *)list->data, name, len) == 0)
				return TRUE;
		}
	}

	return FALSE;
}

static int parse_response(unsigned char *buf, int buflen,
			char *question, int qlen,
			uint16_t *type, uint16_t *class, int *ttl,
			unsigned char *response, unsigned int *response_len,
			uint16_t *answers)
{
	struct domain_hdr *hdr = (void *) buf;
	struct domain_question *q;
	unsigned char *ptr;
	uint16_t qdcount = ntohs(hdr->qdcount);
	uint16_t ancount = ntohs(hdr->ancount);
	int err, i;
	uint16_t qtype, qclass;
	unsigned char *next = NULL;
	unsigned int maxlen = *response_len;
	GSList *aliases = NULL, *list;
	char name[NS_MAXDNAME + 1];

	if (buflen < 12)
		return -EINVAL;

	DBG("qr %d qdcount %d", hdr->qr, qdcount);

	/* We currently only cache responses where question count is 1 */
	if (hdr->qr != 1 || qdcount != 1)
		return -EINVAL;

	ptr = buf + sizeof(struct domain_hdr);

	strncpy(question, (char *) ptr, qlen);
	qlen = strlen(question);
	ptr += qlen + 1; /* skip \0 */

	q = (void *) ptr;
	qtype = ntohs(q->type);

	/* We cache only A and AAAA records */
	if (qtype != 1 && qtype != 28)
		return -ENOMSG;

	qclass = ntohs(q->class);

	ptr += 2 + 2; /* ptr points now to answers */

	err = -ENOMSG;
	*response_len = 0;
	*answers = 0;

	/*
	 * We have a bunch of answers (like A, AAAA, CNAME etc) to
	 * A or AAAA question. We traverse the answers and parse the
	 * resource records. Only A and AAAA records are cached, all
	 * the other records in answers are skipped.
	 */
	for (i = 0; i < ancount; i++) {
		/*
		 * Get one address at a time to this buffer.
		 * The max size of the answer is
		 *   2 (pointer) + 2 (type) + 2 (class) +
		 *   4 (ttl) + 2 (rdlen) + addr (16 or 4) = 28
		 * for A or AAAA record.
		 * For CNAME the size can be bigger.
		 */
		unsigned char rsp[NS_MAXCDNAME];
		unsigned int rsp_len = sizeof(rsp) - 1;
		int ret, rdlen;

		memset(rsp, 0, sizeof(rsp));

		ret = parse_rr(buf, ptr, buf + buflen, rsp, &rsp_len,
			type, class, ttl, &rdlen, &next, name);
		if (ret != 0) {
			err = ret;
			goto out;
		}

		/*
		 * Now rsp contains compressed or uncompressed resource
		 * record. Next we check if this record answers the question.
		 * The name var contains the uncompressed label.
		 * One tricky bit is the CNAME records as they alias
		 * the name we might be interested in.
		 */

		/*
		 * Go to next answer if the class is not the one we are
		 * looking for.
		 */
		if (*class != qclass) {
			ptr = next;
			next = NULL;
			continue;
		}

		/*
		 * Try to resolve aliases also, type is CNAME(5).
		 * This is important as otherwise the aliased names would not
		 * be cached at all as the cache would not contain the aliased
		 * question.
		 *
		 * If any CNAME is found in DNS packet, then we cache the alias
		 * IP address instead of the question (as the server
		 * said that question has only an alias).
		 * This means in practice that if e.g., ipv6.google.com is
		 * queried, DNS server returns CNAME of that name which is
		 * ipv6.l.google.com. We then cache the address of the CNAME
		 * but return the question name to client. So the alias
		 * status of the name is not saved in cache and thus not
		 * returned to the client. We do not return DNS packets from
		 * cache to client saying that ipv6.google.com is an alias to
		 * ipv6.l.google.com but we return instead a DNS packet that
		 * says ipv6.google.com has address xxx which is in fact the
		 * address of ipv6.l.google.com. For caching purposes this
		 * should not cause any issues.
		 */
		if (*type == 5 && strncmp(question, name, qlen) == 0) {
			/*
			 * So now the alias answered the question. This is
			 * not very useful from caching point of view as
			 * the following A or AAAA records will not match the
			 * question. We need to find the real A/AAAA record
			 * of the alias and cache that.
			 */
			unsigned char *end = NULL;
			int name_len = 0, output_len;

			memset(rsp, 0, sizeof(rsp));
			rsp_len = sizeof(rsp) - 1;

			/*
			 * Alias is in rdata part of the message,
			 * and next-rdlen points to it. So we need to get
			 * the real name of the alias.
			 */
			ret = get_name(0, buf, next - rdlen, buf + buflen,
					rsp, rsp_len, &output_len, &end,
					name, &name_len);
			if (ret != 0) {
				/* just ignore the error at this point */
				ptr = next;
				next = NULL;
				continue;
			}

			/*
			 * We should now have the alias of the entry we might
			 * want to cache. Just remember it for a while.
			 * We check the alias list when we have parsed the
			 * A or AAAA record.
			 */
			aliases = g_slist_prepend(aliases, g_strdup(name));

			ptr = next;
			next = NULL;
			continue;
		}

		if (*type == qtype) {
			/*
			 * We found correct type (A or AAAA)
			 */
			if (check_alias(aliases, name) == TRUE ||
				(aliases == NULL && strncmp(question, name,
							qlen) == 0)) {
				/*
				 * We found an alias or the name of the rr
				 * matches the question. If so, we append
				 * the compressed label to the cache.
				 * The end result is a response buffer that
				 * will contain one or more cached and
				 * compressed resource records.
				 */
				if (*response_len + rsp_len > maxlen) {
					err = -ENOBUFS;
					goto out;
				}
				memcpy(response + *response_len, rsp, rsp_len);
				*response_len += rsp_len;
				(*answers)++;
				err = 0;
			}
		}

		ptr = next;
		next = NULL;
	}

out:
	for (list = aliases; list; list = list->next)
		g_free(list->data);
	g_slist_free(aliases);

	return err;
}

struct cache_timeout {
	time_t current_time;
	int max_timeout;
	int try_harder;
};

static gboolean cache_check_entry(gpointer key, gpointer value,
					gpointer user_data)
{
	struct cache_timeout *data = user_data;
	struct cache_entry *entry = value;
	int max_timeout;

	/* Scale the number of hits by half as part of cache aging */

	entry->hits /= 2;

	/*
	 * If either IPv4 or IPv6 cached entry has expired, we
	 * remove both from the cache.
	 */

	if (entry->ipv4 != NULL && entry->ipv4->timeout > 0) {
		max_timeout = entry->ipv4->cache_until;
		if (max_timeout > data->max_timeout)
			data->max_timeout = max_timeout;

		if (entry->ipv4->cache_until < data->current_time)
			return TRUE;
	}

	if (entry->ipv6 != NULL && entry->ipv6->timeout > 0) {
		max_timeout = entry->ipv6->cache_until;
		if (max_timeout > data->max_timeout)
			data->max_timeout = max_timeout;

		if (entry->ipv6->cache_until < data->current_time)
			return TRUE;
	}

	/*
	 * if we're asked to try harder, also remove entries that have
	 * few hits
	 */
	if (data->try_harder && entry->hits < 4)
		return TRUE;

	return FALSE;
}

static void cache_cleanup(void)
{
	static int max_timeout;
	struct cache_timeout data;
	int count = 0;

	data.current_time = time(NULL);
	data.max_timeout = 0;
	data.try_harder = 0;

	/*
	 * In the first pass, we only remove entries that have timed out.
	 * We use a cache of the first time to expire to do this only
	 * when it makes sense.
	 */
	if (max_timeout <= data.current_time) {
		count = g_hash_table_foreach_remove(cache, cache_check_entry,
						&data);
	}
	DBG("removed %d in the first pass", count);

	/*
	 * In the second pass, if the first pass turned up blank,
	 * we also expire entries with a low hit count,
	 * while aging the hit count at the same time.
	 */
	data.try_harder = 1;
	if (count == 0)
		count = g_hash_table_foreach_remove(cache, cache_check_entry,
						&data);

	if (count == 0)
		/*
		 * If we could not remove anything, then remember
		 * what is the max timeout and do nothing if we
		 * have not yet reached it. This will prevent
		 * constant traversal of the cache if it is full.
		 */
		max_timeout = data.max_timeout;
	else
		max_timeout = 0;
}

static gboolean cache_invalidate_entry(gpointer key, gpointer value,
					gpointer user_data)
{
	struct cache_entry *entry = value;

	/* first, delete any expired elements */
	cache_enforce_validity(entry);

	/* if anything is not expired, mark the entry for refresh */
	if (entry->hits > 0 && (entry->ipv4 || entry->ipv6))
		entry->want_refresh = 1;

	/* delete the cached data */
	if (entry->ipv4) {
		g_free(entry->ipv4->data);
		g_free(entry->ipv4);
		entry->ipv4 = NULL;
	}

	if (entry->ipv6) {
		g_free(entry->ipv6->data);
		g_free(entry->ipv6);
		entry->ipv6 = NULL;
	}

	/* keep the entry if we want it refreshed, delete it otherwise */
	if (entry->want_refresh)
		return FALSE;
	else
		return TRUE;
}

/*
 * cache_invalidate is called from places where the DNS landscape
 * has changed, say because connections are added or we entered a VPN.
 * The logic is to wipe all cache data, but mark all non-expired
 * parts of the cache for refresh rather than deleting the whole cache.
 */
static void cache_invalidate(void)
{
	DBG("Invalidating the DNS cache %p", cache);

	if (cache == NULL)
		return;

	g_hash_table_foreach_remove(cache, cache_invalidate_entry, NULL);
}

static void cache_refresh_entry(struct cache_entry *entry)
{

	cache_enforce_validity(entry);

	if (entry->hits > 2 && entry->ipv4 == NULL)
		entry->want_refresh = 1;
	if (entry->hits > 2 && entry->ipv6 == NULL)
		entry->want_refresh = 1;

	if (entry->want_refresh) {
		char *c;
		char dns_name[NS_MAXDNAME + 1];
		entry->want_refresh = 0;

		/* turn a DNS name into a hostname with dots */
		strncpy(dns_name, entry->key, NS_MAXDNAME);
		c = dns_name;
		while (c && *c) {
			int jump;
			jump = *c;
			*c = '.';
			c += jump + 1;
		}
		DBG("Refreshing %s\n", dns_name);
		/* then refresh the hostname */
		refresh_dns_entry(entry, &dns_name[1]);
	}
}

static void cache_refresh_iterator(gpointer key, gpointer value,
					gpointer user_data)
{
	struct cache_entry *entry = value;

	cache_refresh_entry(entry);
}

static void cache_refresh(void)
{
	if (cache == NULL)
		return;

	g_hash_table_foreach(cache, cache_refresh_iterator, NULL);
}

static int reply_query_type(unsigned char *msg, int len)
{
	unsigned char *c;
	uint16_t *w;
	int l;
	int type;

	/* skip the header */
	c = msg + sizeof(struct domain_hdr);
	len -= sizeof(struct domain_hdr);

	if (len < 0)
		return 0;

	/* now the query, which is a name and 2 16 bit words */
	l = dns_name_length(c) + 1;
	c += l;
	w = (uint16_t *) c;
	type = ntohs(*w);

	return type;
}

static int cache_update(struct server_data *srv, unsigned char *msg,
			unsigned int msg_len)
{
	int offset = protocol_offset(srv->protocol);
	int err, qlen, ttl = 0;
	uint16_t answers = 0, type = 0, class = 0;
	struct domain_hdr *hdr = (void *)(msg + offset);
	struct domain_question *q;
	struct cache_entry *entry;
	struct cache_data *data;
	char question[NS_MAXDNAME + 1];
	unsigned char response[NS_MAXDNAME + 1];
	unsigned char *ptr;
	unsigned int rsplen;
	gboolean new_entry = TRUE;
	time_t current_time;

	if (cache_size >= MAX_CACHE_SIZE) {
		cache_cleanup();
		if (cache_size >= MAX_CACHE_SIZE)
			return 0;
	}

	current_time = time(NULL);

	/* don't do a cache refresh more than twice a minute */
	if (next_refresh < current_time) {
		cache_refresh();
		next_refresh = current_time + 30;
	}

	if (offset < 0)
		return 0;

	DBG("offset %d hdr %p msg %p rcode %d", offset, hdr, msg, hdr->rcode);

	/* Continue only if response code is 0 (=ok) */
	if (hdr->rcode != 0)
		return 0;

	rsplen = sizeof(response) - 1;
	question[sizeof(question) - 1] = '\0';

	err = parse_response(msg + offset, msg_len - offset,
				question, sizeof(question) - 1,
				&type, &class, &ttl,
				response, &rsplen, &answers);

	/*
	 * special case: if we do a ipv6 lookup and get no result
	 * for a record that's already in our ipv4 cache.. we want
	 * to cache the negative response.
	 */
	if ((err == -ENOMSG || err == -ENOBUFS) &&
			reply_query_type(msg + offset,
					msg_len - offset) == 28) {
		entry = g_hash_table_lookup(cache, question);
		if (entry && entry->ipv4 && entry->ipv6 == NULL) {
			int cache_offset = 0;

			data = g_try_new(struct cache_data, 1);
			if (data == NULL)
				return -ENOMEM;
			data->inserted = entry->ipv4->inserted;
			data->type = type;
			data->answers = hdr->ancount;
			data->timeout = entry->ipv4->timeout;
			if (srv->protocol == IPPROTO_UDP)
				cache_offset = 2;
			data->data_len = msg_len + cache_offset;
			data->data = ptr = g_malloc(data->data_len);
			ptr[0] = (data->data_len - 2) / 256;
			ptr[1] = (data->data_len - 2) - ptr[0] * 256;
			if (srv->protocol == IPPROTO_UDP)
				ptr += 2;
			data->valid_until = entry->ipv4->valid_until;
			data->cache_until = entry->ipv4->cache_until;
			memcpy(ptr, msg, msg_len);
			entry->ipv6 = data;
			/*
			 * we will get a "hit" when we serve the response
			 * out of the cache
			 */
			entry->hits--;
			if (entry->hits < 0)
				entry->hits = 0;
			return 0;
		}
	}

	if (err < 0 || ttl == 0)
		return 0;

	qlen = strlen(question);

	/*
	 * If the cache contains already data, check if the
	 * type of the cached data is the same and do not add
	 * to cache if data is already there.
	 * This is needed so that we can cache both A and AAAA
	 * records for the same name.
	 */
	entry = g_hash_table_lookup(cache, question);
	if (entry == NULL) {
		entry = g_try_new(struct cache_entry, 1);
		if (entry == NULL)
			return -ENOMEM;

		data = g_try_new(struct cache_data, 1);
		if (data == NULL) {
			g_free(entry);
			return -ENOMEM;
		}

		entry->key = g_strdup(question);
		entry->ipv4 = entry->ipv6 = NULL;
		entry->want_refresh = 0;
		entry->hits = 0;

		if (type == 1)
			entry->ipv4 = data;
		else
			entry->ipv6 = data;
	} else {
		if (type == 1 && entry->ipv4 != NULL)
			return 0;

		if (type == 28 && entry->ipv6 != NULL)
			return 0;

		data = g_try_new(struct cache_data, 1);
		if (data == NULL)
			return -ENOMEM;

		if (type == 1)
			entry->ipv4 = data;
		else
			entry->ipv6 = data;

		/*
		 * compensate for the hit we'll get for serving
		 * the response out of the cache
		 */
		entry->hits--;
		if (entry->hits < 0)
			entry->hits = 0;

		new_entry = FALSE;
	}

	if (ttl < MIN_CACHE_TTL)
		ttl = MIN_CACHE_TTL;

	data->inserted = current_time;
	data->type = type;
	data->answers = answers;
	data->timeout = ttl;
	/*
	 * The "2" in start of the length is the TCP offset. We allocate it
	 * here even for UDP packet because it simplifies the sending
	 * of cached packet.
	 */
	data->data_len = 2 + 12 + qlen + 1 + 2 + 2 + rsplen;
	data->data = ptr = g_malloc(data->data_len);
	data->valid_until = current_time + ttl;

	/*
	 * Restrict the cached DNS record TTL to some sane value
	 * in order to prevent data staying in the cache too long.
	 */
	if (ttl > MAX_CACHE_TTL)
		ttl = MAX_CACHE_TTL;

	data->cache_until = round_down_ttl(current_time + ttl, ttl);

	if (data->data == NULL) {
		g_free(entry->key);
		g_free(data);
		g_free(entry);
		return -ENOMEM;
	}

	/*
	 * We cache the two extra bytes at the start of the message
	 * in a TCP packet. When sending UDP packet, we skip the first
	 * two bytes. This way we do not need to know the format
	 * (UDP/TCP) of the cached message.
	 */
	ptr[0] = (data->data_len - 2) / 256;
	ptr[1] = (data->data_len - 2) - ptr[0] * 256;
	if (srv->protocol == IPPROTO_UDP)
		ptr += 2;

	memcpy(ptr, msg, offset + 12);
	memcpy(ptr + offset + 12, question, qlen + 1); /* copy also the \0 */

	q = (void *) (ptr + offset + 12 + qlen + 1);
	q->type = htons(type);
	q->class = htons(class);
	memcpy(ptr + offset + 12 + qlen + 1 + sizeof(struct domain_question),
		response, rsplen);

	if (new_entry == TRUE) {
		g_hash_table_replace(cache, entry->key, entry);
		cache_size++;
	}

	DBG("cache %d %squestion \"%s\" type %d ttl %d size %zd packet %u "
								"dns len %u",
		cache_size, new_entry ? "new " : "old ",
		question, type, ttl,
		sizeof(*entry) + sizeof(*data) + data->data_len + qlen,
		data->data_len,
		srv->protocol == IPPROTO_TCP ?
			(unsigned int)(data->data[0] * 256 + data->data[1]) :
			data->data_len);

	return 0;
}

static int ns_resolv(struct server_data *server, struct request_data *req,
				gpointer request, gpointer name)
{
	GList *list;
	int sk, err, type = 0;
	char *dot, *lookup = (char *) name;
	struct cache_entry *entry;

	entry = cache_check(request, &type, req->protocol);
	if (entry != NULL) {
		int ttl_left = 0;
		struct cache_data *data;

		DBG("cache hit %s type %s", lookup, type == 1 ? "A" : "AAAA");
		if (type == 1)
			data = entry->ipv4;
		else
			data = entry->ipv6;

		if (data) {
			ttl_left = data->valid_until - time(NULL);
			entry->hits++;
		}

		if (data != NULL && req->protocol == IPPROTO_TCP) {
			send_cached_response(req->client_sk, data->data,
					data->data_len, NULL, 0, IPPROTO_TCP,
					req->srcid, data->answers, ttl_left);
			return 1;
		}

		if (data != NULL && req->protocol == IPPROTO_UDP) {
			int sk;
			sk = g_io_channel_unix_get_fd(
					req->ifdata->udp_listener_channel);

			send_cached_response(sk, data->data,
				data->data_len, &req->sa, req->sa_len,
				IPPROTO_UDP, req->srcid, data->answers,
				ttl_left);
			return 1;
		}
	}

	sk = g_io_channel_unix_get_fd(server->channel);

	err = send(sk, request, req->request_len, MSG_NOSIGNAL);
	if (err < 0)
		return -EIO;

	req->numserv++;

	/* If we have more than one dot, we don't add domains */
	dot = strchr(lookup, '.');
	if (dot != NULL && dot != lookup + strlen(lookup) - 1)
		return 0;

	if (server->domains != NULL && server->domains->data != NULL)
		req->append_domain = TRUE;

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
				req->request_len - altlen - offset + domlen);

		if (server->protocol == IPPROTO_TCP) {
			int req_len = req->request_len + domlen - 2;

			alt[0] = (req_len >> 8) & 0xff;
			alt[1] = req_len & 0xff;
		}

		err = send(sk, alt, req->request_len + domlen, MSG_NOSIGNAL);
		if (err < 0)
			return -EIO;

		req->numserv++;
	}

	return 0;
}

static void destroy_request_data(struct request_data *req)
{
	if (req->timeout > 0)
		g_source_remove(req->timeout);

	g_free(req->resp);
	g_free(req->request);
	g_free(req->name);
	g_free(req);
}

static int forward_dns_reply(unsigned char *reply, int reply_len, int protocol,
				struct server_data *data)
{
	struct domain_hdr *hdr;
	struct request_data *req;
	int dns_id, sk, err, offset = protocol_offset(protocol);
	struct listener_data *ifdata;

	if (offset < 0)
		return offset;

	hdr = (void *)(reply + offset);
	dns_id = reply[offset] | reply[offset + 1] << 8;

	DBG("Received %d bytes (id 0x%04x)", reply_len, dns_id);

	req = find_request(dns_id);
	if (req == NULL)
		return -EINVAL;

	DBG("id 0x%04x rcode %d", hdr->id, hdr->rcode);

	ifdata = req->ifdata;

	reply[offset] = req->srcid & 0xff;
	reply[offset + 1] = req->srcid >> 8;

	req->numresp++;

	if (hdr->rcode == 0 || req->resp == NULL) {

		/*
		 * If the domain name was append
		 * remove it before forwarding the reply.
		 */
		if (req->append_domain == TRUE) {
			unsigned char *ptr;
			uint8_t host_len;
			unsigned int domain_len;

			/*
			 * ptr points to the first char of the hostname.
			 * ->hostname.domain.net
			 */
			ptr = reply + offset + sizeof(struct domain_hdr);
			host_len = *ptr;
			domain_len = strlen((const char *)ptr + host_len + 1);

			/*
			 * Remove the domain name and replace it by the end
			 * of reply. Check if the domain is really there
			 * before trying to copy the data. The domain_len can
			 * be 0 because if the original query did not contain
			 * a domain name, then we are sending two packets,
			 * first without the domain name and the second packet
			 * with domain name. The append_domain is set to true
			 * even if we sent the first packet without domain
			 * name. In this case we end up in this branch.
			 */
			if (domain_len > 0) {
				/*
				 * Note that we must use memmove() here,
				 * because the memory areas can overlap.
				 */
				memmove(ptr + host_len + 1,
					ptr + host_len + domain_len + 1,
					reply_len - (ptr - reply + domain_len));

				reply_len = reply_len - domain_len;
			}
		}

		g_free(req->resp);
		req->resplen = 0;

		req->resp = g_try_malloc(reply_len);
		if (req->resp == NULL)
			return -ENOMEM;

		memcpy(req->resp, reply, reply_len);
		req->resplen = reply_len;

		cache_update(data, reply, reply_len);
	}

	if (hdr->rcode > 0 && req->numresp < req->numserv)
		return -EINVAL;

	request_list = g_slist_remove(request_list, req);

	if (protocol == IPPROTO_UDP) {
		sk = g_io_channel_unix_get_fd(ifdata->udp_listener_channel);
		err = sendto(sk, req->resp, req->resplen, 0,
			     &req->sa, req->sa_len);
	} else {
		sk = req->client_sk;
		err = send(sk, req->resp, req->resplen, MSG_NOSIGNAL);
		close(sk);
	}

	if (err < 0)
		DBG("Cannot send msg, sk %d proto %d errno %d/%s", sk,
			protocol, errno, strerror(errno));
	else
		DBG("proto %d sent %d bytes to %d", protocol, err, sk);

	destroy_request_data(req);

	return err;
}

static void cache_element_destroy(gpointer value)
{
	struct cache_entry *entry = value;

	if (entry == NULL)
		return;

	if (entry->ipv4 != NULL) {
		g_free(entry->ipv4->data);
		g_free(entry->ipv4);
	}

	if (entry->ipv6 != NULL) {
		g_free(entry->ipv6->data);
		g_free(entry->ipv6);
	}

	g_free(entry->key);
	g_free(entry);

	if (--cache_size < 0)
		cache_size = 0;
}

static gboolean try_remove_cache(gpointer user_data)
{
	if (__sync_fetch_and_sub(&cache_refcount, 1) == 1) {
		DBG("No cache users, removing it.");

		g_hash_table_destroy(cache);
		cache = NULL;
	}

	return FALSE;
}

static void destroy_server(struct server_data *server)
{
	GList *list;

	DBG("interface %s server %s sock %d", server->interface, server->server,
		g_io_channel_unix_get_fd(server->channel));

	server_list = g_slist_remove(server_list, server);

	if (server->watch > 0)
		g_source_remove(server->watch);

	if (server->timeout > 0)
		g_source_remove(server->timeout);

	g_io_channel_unref(server->channel);

	if (server->protocol == IPPROTO_UDP)
		DBG("Removing DNS server %s", server->server);

	g_free(server->incoming_reply);
	g_free(server->server);
	for (list = server->domains; list; list = list->next) {
		char *domain = list->data;

		server->domains = g_list_remove(server->domains, domain);
		g_free(domain);
	}
	g_free(server->interface);

	/*
	 * We do not remove cache right away but delay it few seconds.
	 * The idea is that when IPv6 DNS server is added via RDNSS, it has a
	 * lifetime. When the lifetime expires we decrease the refcount so it
	 * is possible that the cache is then removed. Because a new DNS server
	 * is usually created almost immediately we would then loose the cache
	 * without any good reason. The small delay allows the new RDNSS to
	 * create a new DNS server instance and the refcount does not go to 0.
	 */
	g_timeout_add_seconds(3, try_remove_cache, NULL);

	g_free(server);
}

static gboolean udp_server_event(GIOChannel *channel, GIOCondition condition,
							gpointer user_data)
{
	unsigned char buf[4096];
	int sk, err, len;
	struct server_data *data = user_data;

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		connman_error("Error with UDP server %s", data->server);
		data->watch = 0;
		return FALSE;
	}

	sk = g_io_channel_unix_get_fd(channel);

	len = recv(sk, buf, sizeof(buf), 0);
	if (len < 12)
		return TRUE;

	err = forward_dns_reply(buf, len, IPPROTO_UDP, data);
	if (err < 0)
		return TRUE;

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
		DBG("TCP server channel closed, sk %d", sk);

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
		int no_request_sent = TRUE;
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

		for (list = request_list; list; ) {
			struct request_data *req = list->data;
			int status;

			if (req->protocol == IPPROTO_UDP) {
				list = list->next;
				continue;
			}

			DBG("Sending req %s over TCP", (char *)req->name);

			status = ns_resolv(server, req,
						req->request, req->name);
			if (status > 0) {
				/*
				 * A cached result was sent,
				 * so the request can be released
				 */
				list = list->next;
				request_list = g_slist_remove(request_list, req);
				destroy_request_data(req);
				continue;
			}

			if (status < 0) {
				list = list->next;
				continue;
			}

			no_request_sent = FALSE;

			if (req->timeout > 0)
				g_source_remove(req->timeout);

			req->timeout = g_timeout_add_seconds(30,
						request_timeout, req);
			list = list->next;
		}

		if (no_request_sent == TRUE) {
			destroy_server(server);
			return FALSE;
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

			DBG("TCP reply %d bytes from %d", reply_len, sk);

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

		forward_dns_reply(reply->buf, reply->received, IPPROTO_TCP,
					server);

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

	DBG("sk %d", sk);

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

	if (__sync_fetch_and_add(&cache_refcount, 1) == 0)
		cache = g_hash_table_new_full(g_str_hash,
					g_str_equal,
					NULL,
					cache_element_destroy);

	if (protocol == IPPROTO_UDP) {
		/* Enable new servers by default */
		data->enabled = TRUE;
		DBG("Adding DNS server %s", data->server);

		server_list = g_slist_append(server_list, data);
	}

	return data;
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

		if (ns_resolv(data, req, request, name) > 0)
			return TRUE;
	}

	return FALSE;
}

static void append_domain(const char *interface, const char *domain)
{
	GSList *list;

	DBG("interface %s domain %s", interface, domain);

	if (domain == NULL)
		return;

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

	list = request_list;
	while (list) {
		struct request_data *req = list->data;

		list = list->next;

		if (resolv(req, req->request, req->name) == TRUE) {
			/*
			 * A cached result was sent,
			 * so the request can be released
			 */
			request_list =
				g_slist_remove(request_list, req);
			destroy_request_data(req);
			continue;
		}

		if (req->timeout > 0)
			g_source_remove(req->timeout);
		req->timeout = g_timeout_add_seconds(5, request_timeout, req);
	}
}

static void dnsproxy_offline_mode(connman_bool_t enabled)
{
	GSList *list;

	DBG("enabled %d", enabled);

	for (list = server_list; list; list = list->next) {
		struct server_data *data = list->data;

		if (enabled == FALSE) {
			DBG("Enabling DNS server %s", data->server);
			data->enabled = TRUE;
			cache_invalidate();
			cache_refresh();
		} else {
			DBG("Disabling DNS server %s", data->server);
			data->enabled = FALSE;
			cache_invalidate();
		}
	}
}

static void dnsproxy_default_changed(struct connman_service *service)
{
	GSList *list;
	char *interface;

	DBG("service %p", service);

	/* DNS has changed, invalidate the cache */
	cache_invalidate();

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
			DBG("Enabling DNS server %s", data->server);
			data->enabled = TRUE;
		} else {
			DBG("Disabling DNS server %s", data->server);
			data->enabled = FALSE;
		}
	}

	g_free(interface);
	cache_refresh();
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

	name[0] = '\0';

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
	int sk, client_sk, len, err;
	struct sockaddr_in6 client_addr;
	socklen_t client_addr_len = sizeof(client_addr);
	GSList *list;
	struct listener_data *ifdata = user_data;
	int waiting_for_connect = FALSE, qtype = 0;
	struct cache_entry *entry;

	DBG("condition 0x%x", condition);

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		if (ifdata->tcp_listener_watch > 0)
			g_source_remove(ifdata->tcp_listener_watch);
		ifdata->tcp_listener_watch = 0;

		connman_error("Error with TCP listener channel");

		return FALSE;
	}

	sk = g_io_channel_unix_get_fd(channel);

	client_sk = accept(sk, (void *)&client_addr, &client_addr_len);
	if (client_sk < 0) {
		connman_error("Accept failure on TCP listener");
		ifdata->tcp_listener_watch = 0;
		return FALSE;
	}

	len = recv(client_sk, buf, sizeof(buf), 0);
	if (len < 2)
		return TRUE;

	DBG("Received %d bytes (id 0x%04x) from %d", len,
		buf[2] | buf[3] << 8, client_sk);

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

	req->srcid = buf[2] | (buf[3] << 8);
	req->dstid = get_id();
	req->altid = get_id();
	req->request_len = len;

	buf[2] = req->dstid & 0xff;
	buf[3] = req->dstid >> 8;

	req->numserv = 0;
	req->ifdata = (struct listener_data *) ifdata;
	req->append_domain = FALSE;

	/*
	 * Check if the answer is found in the cache before
	 * creating sockets to the server.
	 */
	entry = cache_check(buf, &qtype, IPPROTO_TCP);
	if (entry != NULL) {
		int ttl_left = 0;
		struct cache_data *data;

		DBG("cache hit %s type %s", query, qtype == 1 ? "A" : "AAAA");
		if (qtype == 1)
			data = entry->ipv4;
		else
			data = entry->ipv6;

		if (data != NULL) {
			ttl_left = data->valid_until - time(NULL);
			entry->hits++;

			send_cached_response(client_sk, data->data,
					data->data_len, NULL, 0, IPPROTO_TCP,
					req->srcid, data->answers, ttl_left);

			g_free(req);
			return TRUE;
		} else
			DBG("data missing, ignoring cache for this query");
	}

	for (list = server_list; list; list = list->next) {
		struct server_data *data = list->data;

		if (data->protocol != IPPROTO_UDP || data->enabled == FALSE)
			continue;

		if(create_server(data->interface, NULL,
					data->server, IPPROTO_TCP) == NULL)
			continue;

		waiting_for_connect = TRUE;
	}

	if (waiting_for_connect == FALSE) {
		/* No server is waiting for connect */
		send_response(client_sk, buf, len, NULL, 0, IPPROTO_TCP);
		g_free(req);
		return TRUE;
	}

	/*
	 * The server is not connected yet.
	 * Copy the relevant buffers.
	 * The request will actually be sent once we're
	 * properly connected over TCP to the nameserver.
	 */
	req->request = g_try_malloc0(req->request_len);
	if (req->request == NULL) {
		send_response(client_sk, buf, len, NULL, 0, IPPROTO_TCP);
		g_free(req);
		return TRUE;
	}
	memcpy(req->request, buf, req->request_len);

	req->name = g_try_malloc0(sizeof(query));
	if (req->name == NULL) {
		send_response(client_sk, buf, len, NULL, 0, IPPROTO_TCP);
		g_free(req->request);
		g_free(req);
		return TRUE;
	}
	memcpy(req->name, query, sizeof(query));

	req->timeout = g_timeout_add_seconds(30, request_timeout, req);

	request_list = g_slist_append(request_list, req);

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
	struct listener_data *ifdata = user_data;

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		connman_error("Error with UDP listener channel");
		ifdata->udp_listener_watch = 0;
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

	req->srcid = buf[0] | (buf[1] << 8);
	req->dstid = get_id();
	req->altid = get_id();
	req->request_len = len;

	buf[0] = req->dstid & 0xff;
	buf[1] = req->dstid >> 8;

	req->numserv = 0;
	req->ifdata = (struct listener_data *) ifdata;
	req->append_domain = FALSE;

	if (resolv(req, buf, query) == TRUE) {
		/* a cached result was sent, so the request can be released */
	        g_free(req);
		return TRUE;
	}

	req->timeout = g_timeout_add_seconds(5, request_timeout, req);
	request_list = g_slist_append(request_list, req);

	return TRUE;
}

static int create_dns_listener(int protocol, struct listener_data *ifdata)
{
	GIOChannel *channel;
	const char *proto;
	union {
		struct sockaddr sa;
		struct sockaddr_in6 sin6;
		struct sockaddr_in sin;
	} s;
	socklen_t slen;
	int sk, type, v6only = 0;
	int family = AF_INET6;


	DBG("interface %s", ifdata->ifname);

	switch (protocol) {
	case IPPROTO_UDP:
		proto = "UDP";
		type = SOCK_DGRAM | SOCK_CLOEXEC;
		break;

	case IPPROTO_TCP:
		proto = "TCP";
		type = SOCK_STREAM | SOCK_CLOEXEC;
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
					ifdata->ifname,
					strlen(ifdata->ifname) + 1) < 0) {
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
		ifdata->tcp_listener_channel = channel;
		ifdata->tcp_listener_watch = g_io_add_watch(channel,
				G_IO_IN, tcp_listener_event, (gpointer) ifdata);
	} else {
		ifdata->udp_listener_channel = channel;
		ifdata->udp_listener_watch = g_io_add_watch(channel,
				G_IO_IN, udp_listener_event, (gpointer) ifdata);
	}

	return 0;
}

static void destroy_udp_listener(struct listener_data *ifdata)
{
	DBG("interface %s", ifdata->ifname);

	if (ifdata->udp_listener_watch > 0)
		g_source_remove(ifdata->udp_listener_watch);

	g_io_channel_unref(ifdata->udp_listener_channel);
}

static void destroy_tcp_listener(struct listener_data *ifdata)
{
	DBG("interface %s", ifdata->ifname);

	if (ifdata->tcp_listener_watch > 0)
		g_source_remove(ifdata->tcp_listener_watch);

	g_io_channel_unref(ifdata->tcp_listener_channel);
}

static int create_listener(struct listener_data *ifdata)
{
	int err;

	err = create_dns_listener(IPPROTO_UDP, ifdata);
	if (err < 0)
		return err;

	err = create_dns_listener(IPPROTO_TCP, ifdata);
	if (err < 0) {
		destroy_udp_listener(ifdata);
		return err;
	}

	if (g_strcmp0(ifdata->ifname, "lo") == 0)
		__connman_resolvfile_append("lo", NULL, "127.0.0.1");

	return 0;
}

static void destroy_listener(struct listener_data *ifdata)
{
	GSList *list;

	if (g_strcmp0(ifdata->ifname, "lo") == 0)
		__connman_resolvfile_remove("lo", NULL, "127.0.0.1");

	for (list = request_list; list; list = list->next) {
		struct request_data *req = list->data;

		DBG("Dropping request (id 0x%04x -> 0x%04x)",
						req->srcid, req->dstid);
		destroy_request_data(req);
		list->data = NULL;
	}

	g_slist_free(request_list);
	request_list = NULL;

	destroy_tcp_listener(ifdata);
	destroy_udp_listener(ifdata);
}

int __connman_dnsproxy_add_listener(const char *interface)
{
	struct listener_data *ifdata;
	int err;

	DBG("interface %s", interface);

	if (g_hash_table_lookup(listener_table, interface) != NULL)
		return 0;

	ifdata = g_try_new0(struct listener_data, 1);
	if (ifdata == NULL)
		return -ENOMEM;

	ifdata->ifname = g_strdup(interface);
	ifdata->udp_listener_channel = NULL;
	ifdata->udp_listener_watch = 0;
	ifdata->tcp_listener_channel = NULL;
	ifdata->tcp_listener_watch = 0;

	err = create_listener(ifdata);
	if (err < 0) {
		connman_error("Couldn't create listener for %s err %d",
				interface, err);
		g_free(ifdata->ifname);
		g_free(ifdata);
		return err;
	}
	g_hash_table_insert(listener_table, ifdata->ifname, ifdata);
	return 0;
}

void __connman_dnsproxy_remove_listener(const char *interface)
{
	struct listener_data *ifdata;

	DBG("interface %s", interface);

	ifdata = g_hash_table_lookup(listener_table, interface);
	if (ifdata == NULL)
		return;

	destroy_listener(ifdata);

	g_hash_table_remove(listener_table, interface);
}

static void remove_listener(gpointer key, gpointer value, gpointer user_data)
{
	const char *interface = key;
	struct listener_data *ifdata = value;

	DBG("interface %s", interface);

	destroy_listener(ifdata);
}

int __connman_dnsproxy_init(void)
{
	int err;

	DBG("");

	srandom(time(NULL));

	listener_table = g_hash_table_new_full(g_str_hash, g_str_equal,
							g_free, g_free);
	err = __connman_dnsproxy_add_listener("lo");
	if (err < 0)
		return err;

	err = connman_notifier_register(&dnsproxy_notifier);
	if (err < 0)
		goto destroy;

	return 0;

destroy:
	__connman_dnsproxy_remove_listener("lo");
	g_hash_table_destroy(listener_table);

	return err;
}

void __connman_dnsproxy_cleanup(void)
{
	DBG("");

	connman_notifier_unregister(&dnsproxy_notifier);

	g_hash_table_foreach(listener_table, remove_listener, NULL);

	g_hash_table_destroy(listener_table);
}
