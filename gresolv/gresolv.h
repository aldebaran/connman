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

#ifndef __G_RESOLV_H
#define __G_RESOLV_H

#include <stdint.h>

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif

struct _GResolv;

typedef struct _GResolv GResolv;

typedef void (*GResolvDebugFunc)(const char *str, gpointer user_data);

GResolv *g_resolv_new(int index);

GResolv *g_resolv_ref(GResolv *resolv);
void g_resolv_unref(GResolv *resolv);

void g_resolv_set_debug(GResolv *resolv,
				GResolvDebugFunc func, gpointer data);

int g_resolv_add_nameserver(GResolv *resolv, const char *address,
					uint16_t port, unsigned long flags);
void g_resolv_flush_nameservers(GResolv *resolv);

int g_resolv_lookup_hostname(GResolv *resolv, const char *hostname);

#ifdef __cplusplus
}
#endif

#endif /* __G_RESOLV_H */
