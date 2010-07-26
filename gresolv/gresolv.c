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
#include <string.h>
#include <resolv.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>

#include "gresolv.h"

struct resolv_nameserver {
	char *address;
	uint16_t port;
	unsigned long flags;

	GIOChannel *udp_channel;
};

struct _GResolv {
	gint ref_count;

	int index;
	GList *nameserver_list;

	GResolvDebugFunc debug_func;
	gpointer debug_data;
};

static void free_nameserver(struct resolv_nameserver *nameserver)
{
	if (nameserver == NULL)
		return;

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

static int connect_udp_channel(struct resolv_nameserver *nameserver)
{
	struct sockaddr_in sin;
	int sk;

	sk = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sk < 0)
		return -EIO;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(nameserver->port);
	sin.sin_addr.s_addr = inet_addr(nameserver->address);

	if (connect(sk, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
		close(sk);
		return -EIO;
	}

	nameserver->udp_channel = g_io_channel_unix_new(sk);
	if (nameserver->udp_channel == NULL) {
		close(sk);
		return -ENOMEM;
	}

	g_io_channel_set_close_on_unref(nameserver->udp_channel, TRUE);

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

	resolv->index = index;
	resolv->nameserver_list = NULL;

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
	if (resolv == NULL)
		return;

	if (g_atomic_int_dec_and_test(&resolv->ref_count) == FALSE)
		return;

	flush_nameservers(resolv);

	g_free(resolv);
}

void g_resolv_set_debug(GResolv *resolv,
                                GResolvDebugFunc func, gpointer data)
{
	if (resolv == NULL)
		return;

	resolv->debug_func = func;
	resolv->debug_data = data;
}

int g_resolv_add_nameserver(GResolv *resolv, const char *address,
					uint16_t port, unsigned long flags)
{
	struct resolv_nameserver *nameserver;

	if (resolv == NULL)
		return -EINVAL;

	nameserver = g_try_new0(struct resolv_nameserver, 1);
	if (nameserver == NULL)
		return -ENOMEM;

	nameserver->address = g_strdup(address);
	nameserver->port = port;
	nameserver->flags = flags;

	if (connect_udp_channel(nameserver) < 0) {
		free_nameserver(nameserver);
		return -EIO;
	}

	resolv->nameserver_list = g_list_append(resolv->nameserver_list,
								nameserver);

	return 0;
}

void g_resolv_flush_nameservers(GResolv *resolv)
{
	if (resolv == NULL)
		return;

	flush_nameservers(resolv);
}
