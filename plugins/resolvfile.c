/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2008  Intel Corporation. All rights reserved.
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
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

#include <connman/plugin.h>
#include <connman/resolver.h>
#include <connman/log.h>

#include <glib.h>

static int resolvfile_append(const char *interface, const char *domain,
							const char *server)
{
	char *cmd;
	int fd, len, err;

	DBG("server %s", server);

	fd = open("/etc/resolv.conf", O_RDWR | O_CREAT,
					S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fd < 0)
		return errno;

	err = ftruncate(fd, 0);

	cmd = g_strdup_printf("nameserver %s\n", server);

	len = write(fd, cmd, strlen(cmd));

	g_free(cmd);

	close(fd);

	return 0;
}

static int resolvfile_remove(const char *interface, const char *domain,
							const char *server)
{
	DBG("server %s", server);

	return 0;
}

static struct connman_resolver resolvfile_resolver = {
	.name		= "resolvfile",
	.priority	= CONNMAN_RESOLVER_PRIORITY_LOW,
	.append		= resolvfile_append,
	.remove		= resolvfile_remove,
};

static int resolvfile_init(void)
{
	return connman_resolver_register(&resolvfile_resolver);
}

static void resolvfile_exit(void)
{
	connman_resolver_unregister(&resolvfile_resolver);
}

CONNMAN_PLUGIN_DEFINE(resolvfile, "Name resolver plugin", VERSION,
					resolvfile_init, resolvfile_exit)
