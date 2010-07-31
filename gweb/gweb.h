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

#ifndef __G_WEB_H
#define __G_WEB_H

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif

struct _GWeb;

typedef struct _GWeb GWeb;

typedef void (*GWebDebugFunc)(const char *str, gpointer user_data);

GWeb *g_web_new(void);

GWeb *g_web_ref(GWeb *web);
void g_web_unref(GWeb *web);

void g_web_set_debug(GWeb *web, GWebDebugFunc func, gpointer user_data);

#ifdef __cplusplus
}
#endif

#endif /* __G_WEB_H */
