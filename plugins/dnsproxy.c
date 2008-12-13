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

#include <connman/plugin.h>
#include <connman/resolver.h>
#include <connman/log.h>

static int dnsproxy_append(const char *interface, const char *domain,
							const char *server)
{
	DBG("server %s", server);

	return -1;
}

static int dnsproxy_remove(const char *interface, const char *domain,
							const char *server)
{
	DBG("server %s", server);

	return 0;
}

static struct connman_resolver dnsproxy_resolver = {
	.name		= "dnsproxy",
	.priority	= CONNMAN_RESOLVER_PRIORITY_HIGH,
	.append		= dnsproxy_append,
	.remove		= dnsproxy_remove,
};

static int dnsproxy_init(void)
{
	return connman_resolver_register(&dnsproxy_resolver);
}

static void dnsproxy_exit(void)
{
	connman_resolver_unregister(&dnsproxy_resolver);
}

CONNMAN_PLUGIN_DEFINE(dnsproxy, "DNS proxy resolver plugin", VERSION,
					dnsproxy_init, dnsproxy_exit)
