/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007  Intel Corporation. All rights reserved.
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

#include <stdarg.h>
#include <syslog.h>

#include "connman.h"

static volatile int debug_enabled = 0;

void connman_info(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);

	vsyslog(LOG_INFO, format, ap);

	va_end(ap);
}

void connman_error(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);

	vsyslog(LOG_ERR, format, ap);

	va_end(ap);
}

void connman_debug(const char *format, ...)
{
	va_list ap;

	if (!debug_enabled)
		return;

	va_start(ap, format);

	vsyslog(LOG_DEBUG, format, ap);

	va_end(ap);
}

int __connman_log_init(int detach, int debug)
{
	int option = LOG_NDELAY | LOG_PID;

	if (!detach)
		option |= LOG_PERROR;

	openlog("connmand", option, LOG_DAEMON);

	syslog(LOG_INFO, "Connection Manager version %s", VERSION);

	debug_enabled = debug;

	return 0;
}

void __connman_log_cleanup(void)
{
	syslog(LOG_INFO, "Exit");

	closelog();
}
