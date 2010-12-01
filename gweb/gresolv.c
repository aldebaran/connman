/*
 *
 *  Resolver library with GLib integration
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

#include <errno.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <resolv.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>

#include "gresolv.h"

struct resolv_query {
	GResolv *resolv;

	guint id;
	guint timeout;

	uint16_t msgid;

	GResolvResultFunc result_func;
	gpointer result_data;
};

struct resolv_nameserver {
	GResolv *resolv;

	char *address;
	uint16_t port;
	unsigned long flags;

	GIOChannel *udp_channel;
	guint udp_watch;
};

struct _GResolv {
	gint ref_count;

	guint next_query_id;
	GQueue *query_queue;

	int index;
	GList *nameserver_list;

	struct __res_state res;

	GResolvDebugFunc debug_func;
	gpointer debug_data;
};

static inline void debug(GResolv *resolv, const char *format, ...)
{
	char str[256];
	va_list ap;

	if (resolv->debug_func == NULL)
		return;

	va_start(ap, format);

	if (vsnprintf(str, sizeof(str), format, ap) > 0)
		resolv->debug_func(str, resolv->debug_data);

	va_end(ap);
}

static void destroy_query(struct resolv_query *query)
{
	if (query->timeout > 0)
		g_source_remove(query->timeout);

	g_free(query);
}

static gboolean query_timeout(gpointer user_data)
{
	struct resolv_query *query = user_data;
	GResolv *resolv = query->resolv;

	query->timeout = 0;

	if (query->result_func != NULL)
		query->result_func(G_RESOLV_RESULT_STATUS_NO_RESPONSE,
						NULL, query->result_data);

	destroy_query(query);
	g_queue_remove(resolv->query_queue, query);

	return FALSE;
}

static void free_nameserver(struct resolv_nameserver *nameserver)
{
	if (nameserver == NULL)
		return;

	if (nameserver->udp_watch > 0)
		g_source_remove(nameserver->udp_watch);

	if (nameserver->udp_channel != NULL)
		g_io_channel_unref(nameserver->udp_channel);

	g_free(nameserver->address);
	g_free(nameserver);
}

static void flush_nameservers(GResolv *resolv)
{
	GList *list;

	for (list = g_list_first(resolv->nameserver_list);
					list; list = g_list_next(list))
		free_nameserver(list->data);

	g_list_free(resolv->nameserver_list);
	resolv->nameserver_list = NULL;
}

static int send_query(GResolv *resolv, const unsigned char *buf, int len)
{
	GList *list;

	if (resolv->nameserver_list == NULL)
		return -ENOENT;

	for (list = g_list_first(resolv->nameserver_list);
					list; list = g_list_next(list)) {
		struct resolv_nameserver *nameserver = list->data;
		int sk, sent;

		if (nameserver->udp_channel == NULL)
			continue;

		sk = g_io_channel_unix_get_fd(nameserver->udp_channel);

		sent = send(sk, buf, len, 0);
	}

	return 0;
}

static gint compare_query_id(gconstpointer a, gconstpointer b)
{
	const struct resolv_query *query = a;
	guint id = GPOINTER_TO_UINT(b);

	if (query->id < id)
		return -1;

	if (query->id > id)
		return 1;

	return 0;
}

static gint compare_query_msgid(gconstpointer a, gconstpointer b)
{
	const struct resolv_query *query = a;
	uint16_t msgid = GPOINTER_TO_UINT(b);

	if (query->msgid < msgid)
		return -1;

	if (query->msgid > msgid)
		return 1;

	return 0;
}

static void parse_response(struct resolv_nameserver *nameserver,
					const unsigned char *buf, int len)
{
	GResolv *resolv = nameserver->resolv;
	GResolvResultStatus status;
	GList *list;
	char **results;
	ns_msg msg;
	ns_rr rr;
	int i, n, rcode, count;

	debug(resolv, "response from %s", nameserver->address);

	ns_initparse(buf, len, &msg);

	rcode = ns_msg_getflag(msg, ns_f_rcode);
	count = ns_msg_count(msg, ns_s_an);

	debug(resolv, "msg id: 0x%04x rcode: %d count: %d",
					ns_msg_id(msg), rcode, count);

	switch (rcode) {
	case 0:
		status = G_RESOLV_RESULT_STATUS_SUCCESS;
		break;
	case 1:
		status = G_RESOLV_RESULT_STATUS_FORMAT_ERROR;
		break;
	case 2:
		status = G_RESOLV_RESULT_STATUS_SERVER_FAILURE;
		break;
	case 3:
		status = G_RESOLV_RESULT_STATUS_NAME_ERROR;
		break;
	case 4:
		status = G_RESOLV_RESULT_STATUS_NOT_IMPLEMENTED;
		break;
	case 5:
		status = G_RESOLV_RESULT_STATUS_REFUSED;
		break;
	default:
		status = G_RESOLV_RESULT_STATUS_ERROR;
		break;
	}

	results = g_try_new(char *, count + 1);
	if (results == NULL)
		return;

	for (i = 0, n = 0; i < count; i++) {
		char result[100];

		ns_parserr(&msg, ns_s_an, i, &rr);

		if (ns_rr_class(rr) != ns_c_in)
			continue;

		if (ns_rr_type(rr) == ns_t_a &&
		    ns_rr_rdlen(rr) == NS_INADDRSZ) {
			inet_ntop(AF_INET, ns_rr_rdata(rr), result, sizeof(result));
		} else if (ns_rr_type(rr) == ns_t_aaaa &&
			   ns_rr_rdlen(rr) == NS_IN6ADDRSZ) {
			inet_ntop(AF_INET6, ns_rr_rdata(rr), result, sizeof(result));
		} else
			continue;

		results[n++] = g_strdup(result);
	}

	results[n] = NULL;

	list = g_queue_find_custom(resolv->query_queue,
			GUINT_TO_POINTER(ns_msg_id(msg)), compare_query_msgid);

	if (list != NULL) {
		struct resolv_query *query = list->data;

		/* FIXME: This set of results is *only* for a single A or AAAA
		   query; we need to merge both results together and then sort
		   them according to RFC3484. While honouring /etc/gai.conf */
		if (query->result_func != NULL)
			query->result_func(status, results,
						query->result_data);

		destroy_query(query);
		g_queue_remove(resolv->query_queue, query);
	}

	g_strfreev(results);
}

static gboolean received_udp_data(GIOChannel *channel, GIOCondition cond,
							gpointer user_data)
{
	struct resolv_nameserver *nameserver = user_data;
	unsigned char buf[4096];
	int sk, len;

	if (cond & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		nameserver->udp_watch = 0;
		return FALSE;
	}

	sk = g_io_channel_unix_get_fd(nameserver->udp_channel);

	len = recv(sk, buf, sizeof(buf), 0);
	if (len < 12)
		return TRUE;

	parse_response(nameserver, buf, len);

	return TRUE;
}

static int connect_udp_channel(struct resolv_nameserver *nameserver)
{
	struct addrinfo hints, *rp;
	char portnr[6];
	int err, sk;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV | AI_NUMERICHOST;

	sprintf(portnr, "%d", nameserver->port);
	err = getaddrinfo(nameserver->address, portnr, &hints, &rp);
	if (err)
		return -EINVAL;

	/* Do not blindly copy this code elsewhere; it doesn't loop over the
	   results using ->ai_next as it should. That's OK in *this* case
	   because it was a numeric lookup; we *know* there's only one. */
	if (!rp)
		return -EINVAL;

	sk = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
	if (sk < 0) {
		freeaddrinfo(rp);
		return -EIO;
	}

	if (connect(sk, rp->ai_addr, rp->ai_addrlen) < 0) {
		close(sk);
		freeaddrinfo(rp);
		return -EIO;
	}

	freeaddrinfo(rp);

	nameserver->udp_channel = g_io_channel_unix_new(sk);
	if (nameserver->udp_channel == NULL) {
		close(sk);
		return -ENOMEM;
	}

	g_io_channel_set_close_on_unref(nameserver->udp_channel, TRUE);

	nameserver->udp_watch = g_io_add_watch(nameserver->udp_channel,
			       G_IO_IN | G_IO_NVAL | G_IO_ERR | G_IO_HUP,
			       received_udp_data, nameserver);

	return 0;
}

GResolv *g_resolv_new(int index)
{
	GResolv *resolv;

	if (index < 0)
		return NULL;

	resolv = g_try_new0(GResolv, 1);
	if (resolv == NULL)
		return NULL;

	resolv->ref_count = 1;

	resolv->next_query_id = 1;
	resolv->query_queue = g_queue_new();

	if (resolv->query_queue == NULL) {
		g_free(resolv);
		return NULL;
	}

	resolv->index = index;
	resolv->nameserver_list = NULL;

	res_ninit(&resolv->res);

	return resolv;
}

GResolv *g_resolv_ref(GResolv *resolv)
{
	if (resolv == NULL)
		return NULL;

	g_atomic_int_inc(&resolv->ref_count);

	return resolv;
}

void g_resolv_unref(GResolv *resolv)
{
	struct resolv_query *query;

	if (resolv == NULL)
		return;

	if (g_atomic_int_dec_and_test(&resolv->ref_count) == FALSE)
		return;

	while ((query = g_queue_pop_head(resolv->query_queue)))
		destroy_query(query);

	g_queue_free(resolv->query_queue);

	flush_nameservers(resolv);

	res_nclose(&resolv->res);

	g_free(resolv);
}

void g_resolv_set_debug(GResolv *resolv,
                                GResolvDebugFunc func, gpointer user_data)
{
	if (resolv == NULL)
		return;

	resolv->debug_func = func;
	resolv->debug_data = user_data;
}

gboolean g_resolv_add_nameserver(GResolv *resolv, const char *address,
					uint16_t port, unsigned long flags)
{
	struct resolv_nameserver *nameserver;

	if (resolv == NULL)
		return FALSE;

	nameserver = g_try_new0(struct resolv_nameserver, 1);
	if (nameserver == NULL)
		return FALSE;

	nameserver->address = g_strdup(address);
	nameserver->port = port;
	nameserver->flags = flags;

	if (connect_udp_channel(nameserver) < 0) {
		free_nameserver(nameserver);
		return FALSE;
	}

	nameserver->resolv = resolv;

	resolv->nameserver_list = g_list_append(resolv->nameserver_list,
								nameserver);

	debug(resolv, "setting nameserver %s", address);

	return TRUE;
}

void g_resolv_flush_nameservers(GResolv *resolv)
{
	if (resolv == NULL)
		return;

	flush_nameservers(resolv);
}

guint g_resolv_lookup_hostname(GResolv *resolv, const char *hostname,
				GResolvResultFunc func, gpointer user_data)
{
	struct resolv_query *query;
	unsigned char buf[4096];
	int len;

	debug(resolv, "lookup hostname %s", hostname);

	if (resolv == NULL)
		return 0;

	if (resolv->nameserver_list == NULL) {
		int i;

		for (i = 0; i < resolv->res.nscount; i++) {
			char buf[100];
			int family = resolv->res.nsaddr_list[i].sin_family;
			void *sa_addr = &resolv->res.nsaddr_list[i].sin_addr;

			if (family != AF_INET && resolv->res._u._ext.nsaddrs[i]) {
				family = AF_INET6;
				sa_addr = &resolv->res._u._ext.nsaddrs[i]->sin6_addr;
			}
			if (family != AF_INET && family != AF_INET6)
				continue;

			if (inet_ntop(family, sa_addr, buf, sizeof(buf)))
				g_resolv_add_nameserver(resolv, buf, 53, 0);
		}

		if (resolv->nameserver_list == NULL)
			g_resolv_add_nameserver(resolv, "127.0.0.1", 53, 0);
	}

	query = g_try_new0(struct resolv_query, 1);
	if (query == NULL)
		return 0;

	query->id = resolv->next_query_id++;

	/* FIXME: Send ns_t_aaaa query too, and see the FIXME in
	   parse_response() re merging and sorting the results */
	len = res_mkquery(ns_o_query, hostname, ns_c_in, ns_t_a,
					NULL, 0, NULL, buf, sizeof(buf));

	query->msgid = buf[0] << 8 | buf[1];

	query->result_func = func;
	query->result_data = user_data;

	if (send_query(resolv, buf, len) < 0) {
		g_free(query);
		return -EIO;
	}

	query->resolv = resolv;

	g_queue_push_tail(resolv->query_queue, query);

	query->timeout = g_timeout_add_seconds(5, query_timeout, query);

	return query->id;
}

gboolean g_resolv_cancel_lookup(GResolv *resolv, guint id)
{
	GList *list;

	list = g_queue_find_custom(resolv->query_queue,
				GUINT_TO_POINTER(id), compare_query_id);

	if (list == NULL)
		return FALSE;

	destroy_query(list->data);
	g_queue_remove(resolv->query_queue, list->data);

	return TRUE;
}
