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
#include <errno.h>
#include <ctype.h>
#include <unistd.h>

#include <gnutls/gnutls.h>

#include "giognutls.h"

//#define DBG(fmt, arg...)  printf("%s: " fmt "\n" , __func__ , ## arg)
#define DBG(fmt, arg...)

typedef struct _GIOGnuTLSChannel GIOGnuTLSChannel;
typedef struct _GIOGnuTLSWatch GIOGnuTLSWatch;

struct _GIOGnuTLSChannel {
	GIOChannel channel;
	GIOChannel *transport;
	gnutls_certificate_credentials_t cred;
	gnutls_session session;
	gboolean established;
};

struct _GIOGnuTLSWatch {
	GSource source;
	GPollFD pollfd;
	GIOChannel *channel;
	GIOCondition condition;
};

static volatile gint global_init_done = 0;

static inline void g_io_gnutls_global_init(void)
{
	if (g_atomic_int_compare_and_exchange(&global_init_done, 0, 1) == TRUE)
		gnutls_global_init();
}

static GIOStatus check_handshake(GIOChannel *channel, GError **err)
{
	GIOGnuTLSChannel *gnutls_channel = (GIOGnuTLSChannel *) channel;
	int result;

	DBG("channel %p", channel);

again:
	if (gnutls_channel->established == TRUE)
		return G_IO_STATUS_NORMAL;

	result = gnutls_handshake(gnutls_channel->session);

	if (result == GNUTLS_E_INTERRUPTED || result == GNUTLS_E_AGAIN) {
		GIOFlags flags = g_io_channel_get_flags(channel);

		if (flags & G_IO_FLAG_NONBLOCK)
			return G_IO_STATUS_AGAIN;

		goto again;
	}

	if (result < 0) {
		g_set_error(err, G_IO_CHANNEL_ERROR,
				G_IO_CHANNEL_ERROR_FAILED, "Handshake failed");
		return G_IO_STATUS_ERROR;
	}

	gnutls_channel->established = TRUE;

	DBG("handshake done");

	return G_IO_STATUS_NORMAL;
}

static GIOStatus g_io_gnutls_read(GIOChannel *channel, gchar *buf,
				gsize count, gsize *bytes_read, GError **err)
{
	GIOGnuTLSChannel *gnutls_channel = (GIOGnuTLSChannel *) channel;
	GIOStatus status;
	ssize_t result;

	DBG("channel %p count %zu", channel, count);

	*bytes_read = 0;

again:
	status = check_handshake(channel, err);
	if (status != G_IO_STATUS_NORMAL)
		return status;

	result = gnutls_record_recv(gnutls_channel->session, buf, count);

	DBG("result %zd", result);

	if (result == GNUTLS_E_REHANDSHAKE) {
		gnutls_channel->established = FALSE;
		goto again;
	}

	if (result == GNUTLS_E_INTERRUPTED || result == GNUTLS_E_AGAIN) {
		GIOFlags flags = g_io_channel_get_flags(channel);

		if (flags & G_IO_FLAG_NONBLOCK)
			return G_IO_STATUS_AGAIN;

		goto again;
	}

	if (result == GNUTLS_E_UNEXPECTED_PACKET_LENGTH)
		return G_IO_STATUS_EOF;

	if (result < 0) {
		g_set_error(err, G_IO_CHANNEL_ERROR,
				G_IO_CHANNEL_ERROR_FAILED, "Stream corrupted");
		return G_IO_STATUS_ERROR;
	}

	*bytes_read = result;

	return (result > 0) ? G_IO_STATUS_NORMAL : G_IO_STATUS_EOF;
}

static GIOStatus g_io_gnutls_write(GIOChannel *channel, const gchar *buf,
				gsize count, gsize *bytes_written, GError **err)
{
	GIOGnuTLSChannel *gnutls_channel = (GIOGnuTLSChannel *) channel;
	GIOStatus status;
	ssize_t result;

	DBG("channel %p count %zu", channel, count);

	*bytes_written = 0;

again:
	status = check_handshake(channel, err);
	if (status != G_IO_STATUS_NORMAL)
		return status;

	result = gnutls_record_send(gnutls_channel->session, buf, count);

	DBG("result %zd", result);

	if (result == GNUTLS_E_REHANDSHAKE) {
		gnutls_channel->established = FALSE;
		goto again;
	}

	if (result == GNUTLS_E_INTERRUPTED || result == GNUTLS_E_AGAIN) {
		GIOFlags flags = g_io_channel_get_flags(channel);

		if (flags & G_IO_FLAG_NONBLOCK)
			return G_IO_STATUS_AGAIN;

		goto again;
	}

	if (result < 0) {
		g_set_error(err, G_IO_CHANNEL_ERROR,
				G_IO_CHANNEL_ERROR_FAILED, "Stream corrupted");
		return G_IO_STATUS_ERROR;
        }

	*bytes_written = result;

	return (result > 0) ? G_IO_STATUS_NORMAL : G_IO_STATUS_EOF;
}

static GIOStatus g_io_gnutls_seek(GIOChannel *channel, gint64 offset,
						GSeekType type, GError **err)
{
	GIOGnuTLSChannel *gnutls_channel = (GIOGnuTLSChannel *) channel;
	GIOChannel *transport = gnutls_channel->transport;

	DBG("channel %p", channel);

	return transport->funcs->io_seek(transport, offset, type, err);
}

static GIOStatus g_io_gnutls_close(GIOChannel *channel, GError **err)
{
	GIOGnuTLSChannel *gnutls_channel = (GIOGnuTLSChannel *) channel;
	GIOChannel *transport = gnutls_channel->transport;

	DBG("channel %p", channel);

	if (gnutls_channel->established == TRUE)
		gnutls_bye(gnutls_channel->session, GNUTLS_SHUT_RDWR);

	return transport->funcs->io_close(transport, err);
}

static void g_io_gnutls_free(GIOChannel *channel)
{
	GIOGnuTLSChannel *gnutls_channel = (GIOGnuTLSChannel *) channel;

	DBG("channel %p", channel);

	g_io_channel_unref(gnutls_channel->transport);

	gnutls_deinit(gnutls_channel->session);

	gnutls_certificate_free_credentials(gnutls_channel->cred);

	g_free(gnutls_channel);
}

static GIOStatus g_io_gnutls_set_flags(GIOChannel *channel,
						GIOFlags flags, GError **err)
{
	GIOGnuTLSChannel *gnutls_channel = (GIOGnuTLSChannel *) channel;
	GIOChannel *transport = gnutls_channel->transport;

	DBG("channel %p flags %u", channel, flags);

	return transport->funcs->io_set_flags(transport, flags, err);
}

static GIOFlags g_io_gnutls_get_flags(GIOChannel *channel)
{
	GIOGnuTLSChannel *gnutls_channel = (GIOGnuTLSChannel *) channel;
	GIOChannel *transport = gnutls_channel->transport;

	DBG("channel %p", channel);

	return transport->funcs->io_get_flags(transport);
}

static gboolean g_io_gnutls_prepare(GSource *source, gint *timeout)
{
	DBG("source %p", source);

	*timeout = -1;

	return FALSE;
}

static gboolean g_io_gnutls_check(GSource *source)
{
	GIOGnuTLSWatch *watch = (GIOGnuTLSWatch *) source;
	GIOCondition condition = watch->pollfd.revents;

	DBG("source %p condition %u", source, condition);

	if (condition & watch->condition)
		return TRUE;

	return FALSE;
}

static gboolean g_io_gnutls_dispatch(GSource *source, GSourceFunc callback,
							gpointer user_data)
{
	GIOGnuTLSWatch *watch = (GIOGnuTLSWatch *) source;
	GIOFunc func = (GIOFunc) callback;
	GIOCondition condition = watch->pollfd.revents;

	DBG("source %p condition %u", source, condition);

	if (func == NULL)
		return FALSE;

	return func(watch->channel, condition & watch->condition, user_data);
}

static void g_io_gnutls_finalize(GSource *source)
{
	GIOGnuTLSWatch *watch = (GIOGnuTLSWatch *) source;

	DBG("source %p", source);

	g_io_channel_unref(watch->channel);
}

static GSourceFuncs gnutls_watch_funcs = {
	g_io_gnutls_prepare,
	g_io_gnutls_check,
	g_io_gnutls_dispatch,
	g_io_gnutls_finalize,
};

static GSource *g_io_gnutls_create_watch(GIOChannel *channel,
						GIOCondition condition)
{
	GIOGnuTLSChannel *gnutls_channel = (GIOGnuTLSChannel *) channel;
	GIOGnuTLSWatch *watch;
	GSource *source;

	DBG("channel %p condition %u", channel, condition);

	source = g_source_new(&gnutls_watch_funcs, sizeof(GIOGnuTLSWatch));

	watch = (GIOGnuTLSWatch *) source;

	watch->channel = channel;
	g_io_channel_ref(channel);

	watch->condition = condition;

	watch->pollfd.fd = g_io_channel_unix_get_fd(gnutls_channel->transport);
	watch->pollfd.events = condition;

	g_source_add_poll(source, &watch->pollfd);

	return source;
}

static GIOFuncs gnutls_channel_funcs = {
	g_io_gnutls_read,
	g_io_gnutls_write,
	g_io_gnutls_seek,
	g_io_gnutls_close,
	g_io_gnutls_create_watch,
	g_io_gnutls_free,
	g_io_gnutls_set_flags,
	g_io_gnutls_get_flags,
};

static ssize_t g_io_gnutls_push_func(gnutls_transport_ptr_t transport_data,
						const void *buf, size_t count)
{
	GIOGnuTLSChannel *gnutls_channel = transport_data;
	ssize_t result;
	int fd;

	DBG("transport %p count %zu", gnutls_channel->transport, count);

	fd = g_io_channel_unix_get_fd(gnutls_channel->transport);

	result = write(fd, buf, count);

	DBG("result %zd", result);

	return result;
}

static ssize_t g_io_gnutls_pull_func(gnutls_transport_ptr_t transport_data,
						void *buf, size_t count)
{
	GIOGnuTLSChannel *gnutls_channel = transport_data;
	ssize_t result;
	int fd;

	DBG("transport %p count %zu", gnutls_channel->transport, count);

	fd = g_io_channel_unix_get_fd(gnutls_channel->transport);

	result = read(fd, buf, count);

	DBG("result %zd", result);

	return result;
}

GIOChannel *g_io_channel_gnutls_new(int fd)
{
	GIOGnuTLSChannel *gnutls_channel;
	GIOChannel *channel;
	int err;

	DBG("");

	gnutls_channel = g_new(GIOGnuTLSChannel, 1);

	channel = (GIOChannel *) gnutls_channel;

	g_io_channel_init(channel);
	channel->funcs = &gnutls_channel_funcs;

	gnutls_channel->transport = g_io_channel_unix_new(fd);

	g_io_channel_set_encoding(gnutls_channel->transport, NULL, NULL);
	g_io_channel_set_buffered(gnutls_channel->transport, FALSE);

	channel->is_seekable = FALSE;
	channel->is_readable = TRUE;
	channel->is_writeable = TRUE;

	channel->do_encode = FALSE;

	g_io_gnutls_global_init();

        err = gnutls_init(&gnutls_channel->session, GNUTLS_CLIENT);
	if (err < 0) {
		g_free(gnutls_channel);
		return NULL;
	}

	gnutls_transport_set_ptr(gnutls_channel->session, gnutls_channel);
        gnutls_transport_set_push_function(gnutls_channel->session,
						g_io_gnutls_push_func);
        gnutls_transport_set_pull_function(gnutls_channel->session,
						g_io_gnutls_pull_func);
	gnutls_transport_set_lowat(gnutls_channel->session, 0);

	gnutls_priority_set_direct(gnutls_channel->session,
				"NORMAL:!VERS-TLS1.1:!VERS-TLS1.0", NULL);

	gnutls_certificate_allocate_credentials(&gnutls_channel->cred);
	gnutls_credentials_set(gnutls_channel->session,
				GNUTLS_CRD_CERTIFICATE, gnutls_channel->cred);

	DBG("channel %p transport %p", channel, gnutls_channel->transport);

	return channel;
}
