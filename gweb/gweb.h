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

#include <stdint.h>

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif

struct _GWeb;
struct _GWebResult;
struct _GWebParser;

typedef struct _GWeb GWeb;
typedef struct _GWebResult GWebResult;
typedef struct _GWebParser GWebParser;

typedef gboolean (*GWebResultFunc)(GWebResult *result, gpointer user_data);

typedef gboolean (*GWebInputFunc)(const guint8 **data, gsize *length,
							gpointer user_data);

typedef void (*GWebDebugFunc)(const char *str, gpointer user_data);

GWeb *g_web_new(int index);

GWeb *g_web_ref(GWeb *web);
void g_web_unref(GWeb *web);

void g_web_set_debug(GWeb *web, GWebDebugFunc func, gpointer user_data);

gboolean g_web_set_proxy(GWeb *web, const char *proxy);

gboolean g_web_add_nameserver(GWeb *web, const char *address);

gboolean g_web_set_accept(GWeb *web, const char *format, ...)
				__attribute__((format(printf, 2, 3)));
gboolean g_web_set_user_agent(GWeb *web, const char *format, ...)
				__attribute__((format(printf, 2, 3)));
gboolean g_web_set_ua_profile(GWeb *web, const char *profile);

gboolean g_web_set_http_version(GWeb *web, const char *version);

void g_web_set_close_connection(GWeb *web, gboolean enabled);
gboolean g_web_get_close_connection(GWeb *web);

guint g_web_request_get(GWeb *web, const char *url,
				GWebResultFunc func, gpointer user_data);
guint g_web_request_post(GWeb *web, const char *url,
				const char *type, GWebInputFunc input,
				GWebResultFunc func, gpointer user_data);

gboolean g_web_cancel_request(GWeb *web, guint id);

guint16 g_web_result_get_status(GWebResult *result);

gboolean g_web_result_get_header(GWebResult *result,
				const char *header, const char **value);
gboolean g_web_result_get_chunk(GWebResult *result,
				const guint8 **chunk, gsize *length);

typedef void (*GWebParserFunc)(const char *str, gpointer user_data);

GWebParser *g_web_parser_new(const char *begin, const char *end,
				GWebParserFunc func, gpointer user_data);

GWebParser *g_web_parser_ref(GWebParser *parser);
void g_web_parser_unref(GWebParser *parser);

void g_web_parser_feed_data(GWebParser *parser,
				const guint8 *data, gsize length);
void g_web_parser_end_data(GWebParser *parser);

#ifdef __cplusplus
}
#endif

#endif /* __G_WEB_H */
