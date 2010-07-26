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

#include "gresolv.h"

struct _GResolv {
	gint ref_count;

	int index;

	GResolvDebugFunc debug_func;
	gpointer debug_data;
};

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
