/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2009  Intel Corporation. All rights reserved.
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
#include <stdlib.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/resolver.h>
#include <connman/log.h>

#include <glib.h>

static int resolvconf_append(const char *interface, const char *domain,
							const char *server)
{
	char *cmd;
	int err;

	DBG("interface %s server %s", interface, server);

	if (access(RESOLVCONF, X_OK) < 0)
		return -errno;

	cmd = g_strdup_printf("echo \"nameserver %s\" | %s -a %s",
						server, RESOLVCONF, interface);

	DBG("%s", cmd);

	err = system(cmd);

	g_free(cmd);

	return err;
}

static int resolvconf_remove(const char *interface, const char *domain,
							const char *server)
{
	char *cmd;
	int err;

	DBG("interface %s server %s", interface, server);

	cmd = g_strdup_printf("%s -d %s", RESOLVCONF, interface);

	DBG("%s", cmd);

	err = system(cmd);

	g_free(cmd);

	return err;
}

static struct connman_resolver resolvconf_resolver = {
	.name		= "resolvconf",
	.priority	= CONNMAN_RESOLVER_PRIORITY_DEFAULT,
	.append		= resolvconf_append,
	.remove		= resolvconf_remove,
};

static int resolvconf_init(void)
{
	return connman_resolver_register(&resolvconf_resolver);
}

static void resolvconf_exit(void)
{
	connman_resolver_unregister(&resolvconf_resolver);
}

CONNMAN_PLUGIN_DEFINE(resolvconf, "Name resolver plugin", VERSION,
		CONNMAN_PLUGIN_PRIORITY_DEFAULT, resolvconf_init, resolvconf_exit)
