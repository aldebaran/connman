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

#define _GNU_SOURCE
#include <stdarg.h>
#include <syslog.h>
#include <execinfo.h>
#include <dlfcn.h>
#include <stdlib.h>

#include "connman.h"

/**
 * connman_info:
 * @format: format string
 * @Varargs: list of arguments
 *
 * Output general information
 */
void connman_info(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);

	vsyslog(LOG_INFO, format, ap);

	va_end(ap);
}

/**
 * connman_warn:
 * @format: format string
 * @Varargs: list of arguments
 *
 * Output warning messages
 */
void connman_warn(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);

	vsyslog(LOG_WARNING, format, ap);

	va_end(ap);
}

/**
 * connman_error:
 * @format: format string
 * @varargs: list of arguments
 *
 * Output error messages
 */
void connman_error(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);

	vsyslog(LOG_ERR, format, ap);

	va_end(ap);
}

/**
 * connman_debug:
 * @format: format string
 * @varargs: list of arguments
 *
 * Output debug message
 */
void connman_debug(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);

	vsyslog(LOG_DEBUG, format, ap);

	va_end(ap);
}

extern struct connman_debug_desc __start___debug[];
extern struct connman_debug_desc __stop___debug[];

void __connman_debug_list_available(DBusMessageIter *iter, void *user_data)
{
	struct connman_debug_desc *desc;

	for (desc = __start___debug; desc < __stop___debug; desc++) {
		if ((desc->flags & CONNMAN_DEBUG_FLAG_ALIAS) &&
						desc->name != NULL)
			dbus_message_iter_append_basic(iter,
					DBUS_TYPE_STRING, &desc->name);
	}
}

static gchar **enabled = NULL;

void __connman_debug_list_enabled(DBusMessageIter *iter, void *user_data)
{
	int i;

	if (enabled == NULL)
		return;

	for (i = 0; enabled[i] != NULL; i++)
		dbus_message_iter_append_basic(iter,
					DBUS_TYPE_STRING, &enabled[i]);
}

static connman_bool_t is_enabled(struct connman_debug_desc *desc)
{
	int i;

	if (enabled == NULL)
		return FALSE;

	for (i = 0; enabled[i] != NULL; i++) {
		if (desc->name != NULL && g_pattern_match_simple(enabled[i],
							desc->name) == TRUE)
			return TRUE;
		if (desc->file != NULL && g_pattern_match_simple(enabled[i],
							desc->file) == TRUE)
			return TRUE;
	}

	return FALSE;
}

static void signal_handler(int signo)
{
	void *frames[64];
	char **symbols;
	size_t n_ptrs;
	unsigned int i;

	n_ptrs = backtrace(frames, G_N_ELEMENTS(frames));
	symbols = backtrace_symbols(frames, n_ptrs);
	if (symbols == NULL) {
		connman_error("No backtrace symbols");
		exit(1);
	}

	connman_error("Aborting (signal %d)", signo);
	connman_error("++++++++ ConnMan backtrace ++++++++");

	for (i = 1; i < n_ptrs; i++)
		connman_error("[%d]: %s", i - 1, symbols[i]);

	connman_error("++++++++++++++++++++++++++++++++++++");

	g_free(symbols);
	exit(1);
}

static void signal_setup(sighandler_t handler)
{
	struct sigaction sa;
	sigset_t mask;

	sigemptyset(&mask);
	sa.sa_handler = handler;
	sa.sa_mask = mask;
	sa.sa_flags = 0;
	sigaction(SIGBUS, &sa, NULL);
	sigaction(SIGILL, &sa, NULL);
	sigaction(SIGFPE, &sa, NULL);
	sigaction(SIGSEGV, &sa, NULL);
	sigaction(SIGABRT, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);
}

int __connman_log_init(const char *debug, connman_bool_t detach)
{
	int option = LOG_NDELAY | LOG_PID;
	struct connman_debug_desc *desc;
	const char *name = NULL, *file = NULL;

	if (debug != NULL)
		enabled = g_strsplit_set(debug, ":, ", 0);

	for (desc = __start___debug; desc < __stop___debug; desc++) {
		if (desc->flags & CONNMAN_DEBUG_FLAG_ALIAS) {
			file = desc->file;
			name = desc->name;
			continue;
		}

		if (file != NULL || name != NULL) {
			if (g_strcmp0(desc->file, file) == 0) {
				if (desc->name == NULL)
					desc->name = name;
			} else
				file = NULL;
		}

		if (is_enabled(desc) == TRUE)
			desc->flags |= CONNMAN_DEBUG_FLAG_PRINT;
	}

	if (detach == FALSE)
		option |= LOG_PERROR;

	signal_setup(signal_handler);

	openlog("connmand", option, LOG_DAEMON);

	syslog(LOG_INFO, "Connection Manager version %s", VERSION);

	return 0;
}

void __connman_log_cleanup(void)
{
	syslog(LOG_INFO, "Exit");

	closelog();

	g_strfreev(enabled);

	signal_setup(SIG_DFL);
}
