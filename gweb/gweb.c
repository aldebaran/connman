/*
 *
 *  Web service library with GLib integration
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

#include <stdio.h>
#include <string.h>

#include "gweb.h"

struct _GWeb {
	gint ref_count;

	GWebDebugFunc debug_func;
	gpointer debug_data;
};

static inline void debug(GWeb *web, const char *format, ...)
{
	char str[256];
	va_list ap;

	if (web->debug_func == NULL)
		return;

	va_start(ap, format);

	if (vsnprintf(str, sizeof(str), format, ap) > 0)
		web->debug_func(str, web->debug_data);

	va_end(ap);
}

GWeb *g_web_new(void)
{
	GWeb *web;

	web = g_try_new0(GWeb, 1);
	if (web == NULL)
		return NULL;

	web->ref_count = 1;

	return web;
}

GWeb *g_web_ref(GWeb *web)
{
	if (web == NULL)
		return NULL;

	g_atomic_int_inc(&web->ref_count);

	return web;
}

void g_web_unref(GWeb *web)
{
	if (web == NULL)
		return;

	if (g_atomic_int_dec_and_test(&web->ref_count) == FALSE)
		return;

	g_free(web);
}

void g_web_set_debug(GWeb *web, GWebDebugFunc func, gpointer user_data)
{
	if (web == NULL)
		return;

	web->debug_func = func;
	web->debug_data = user_data;
}
