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

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

#include "connman.h"

struct entry_data {
	struct connman_resolver *resolver;
	char *interface;
	char *domain;
	char *server;
};

static GSList *entry_list = NULL;
static GSList *resolver_list = NULL;

static void remove_entries(GSList *entries)
{
	GSList *list;

	for (list = entries; list; list = list->next) {
		struct entry_data *entry = list->data;
		struct connman_resolver *resolver = entry->resolver;

		entry_list = g_slist_remove(entry_list, entry);

		if (resolver->remove)
			resolver->remove(entry->interface, entry->domain,
								entry->server);

		g_free(entry->server);
		g_free(entry->domain);
		g_free(entry->interface);
		g_free(entry);
	}

	g_slist_free(entries);
}

static gint compare_priority(gconstpointer a, gconstpointer b)
{
	const struct connman_resolver *resolver1 = a;
	const struct connman_resolver *resolver2 = b;

	return resolver2->priority - resolver1->priority;
}

/**
 * connman_resolver_register:
 * @resolver: resolver module
 *
 * Register a new resolver module
 *
 * Returns: %0 on success
 */
int connman_resolver_register(struct connman_resolver *resolver)
{
	GSList *list;

	DBG("resolver %p name %s", resolver, resolver->name);

	resolver_list = g_slist_insert_sorted(resolver_list, resolver,
							compare_priority);

	if (resolver->append == NULL)
		return 0;

	for (list = entry_list; list; list = list->next) {
		struct entry_data *entry = list->data;

		if (entry->resolver)
			continue;

		if (resolver->append(entry->interface, entry->domain,
							entry->server) == 0)
			entry->resolver = resolver;
	}

	return 0;
}

/**
 * connman_resolver_unregister:
 * @resolver: resolver module
 *
 * Remove a previously registered resolver module
 */
void connman_resolver_unregister(struct connman_resolver *resolver)
{
	GSList *list, *matches = NULL;

	DBG("resolver %p name %s", resolver, resolver->name);

	resolver_list = g_slist_remove(resolver_list, resolver);

	for (list = entry_list; list; list = list->next) {
		struct entry_data *entry = list->data;

		if (entry->resolver != resolver)
			continue;

		matches = g_slist_append(matches, entry);
	}

	remove_entries(matches);
}

/**
 * connman_resolver_append:
 * @interface: network interface
 * @domain: domain limitation
 * @server: server address
 *
 * Append resolver server address to current list
 */
int connman_resolver_append(const char *interface, const char *domain,
							const char *server)
{
	struct entry_data *entry;
	GSList *list;

	DBG("interface %s domain %s server %s", interface, domain, server);

	entry = g_try_new0(struct entry_data, 1);
	if (entry == NULL)
		return -ENOMEM;

	entry->interface = g_strdup(interface);
	entry->domain = g_strdup(domain);
	entry->server = g_strdup(server);

	entry_list = g_slist_append(entry_list, entry);

	for (list = resolver_list; list; list = list->next) {
		struct connman_resolver *resolver = list->data;

		if (resolver->append == NULL)
			continue;

		if (resolver->append(interface, domain, server) == 0) {
			entry->resolver = resolver;
			break;
		}
	}

	return 0;
}

/**
 * connman_resolver_remove_all:
 * @interface: network interface
 *
 * Remove all resolver server address for the specified interface
 */
int connman_resolver_remove_all(const char *interface)
{
	GSList *list, *matches = NULL;

	DBG("interface %s", interface);

	for (list = entry_list; list; list = list->next) {
		struct entry_data *entry = list->data;

		if (g_str_equal(entry->interface, interface) == FALSE)
			continue;

		matches = g_slist_append(matches, entry);
	}

	remove_entries(matches);

	return 0;
}

static int selftest_append(const char *interface, const char *domain,
							const char *server)
{
	DBG("server %s", server);

	return 0;
}

static int selftest_remove(const char *interface, const char *domain,
							const char *server)
{
	DBG("server %s", server);

	return 0;
}

static struct connman_resolver selftest_resolver = {
	.name     = "selftest",
	.priority = CONNMAN_RESOLVER_PRIORITY_HIGH + 42,
	.append   = selftest_append,
	.remove   = selftest_remove,
};

int __connman_resolver_selftest(void)
{
	connman_resolver_append("wlan0", "lwn.net", "192.168.0.1");

	connman_resolver_register(&selftest_resolver);

	connman_resolver_append("eth0", "moblin.org", "192.168.42.1");
	connman_resolver_append("wlan0", "lwn.net", "192.168.0.2");

	connman_resolver_remove_all("wlan0");

	connman_resolver_unregister(&selftest_resolver);

	return 0;
}

static int resolvfile_append(const char *interface, const char *domain,
							const char *server)
{
	char *cmd;
	int fd, len, err;

	DBG("interface %s server %s", interface, server);

	fd = open("/etc/resolv.conf", O_RDWR | O_CREAT,
					S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fd < 0)
		return errno;

	err = ftruncate(fd, 0);

	cmd = g_strdup_printf("# Generated by Connection Manager\n"
						"domain localdomain\n"
						"search localdomain\n"
						"nameserver %s\n", server);

	len = write(fd, cmd, strlen(cmd));

	g_free(cmd);

	close(fd);

	return 0;
}

static int resolvfile_remove(const char *interface, const char *domain,
							const char *server)
{
	DBG("interface %s server %s", interface, server);

	return 0;
}

static struct connman_resolver resolvfile_resolver = {
	.name		= "resolvfile",
	.priority	= CONNMAN_RESOLVER_PRIORITY_LOW,
	.append		= resolvfile_append,
	.remove		= resolvfile_remove,
};

int __connman_resolver_init(void)
{
	DBG("");

	return connman_resolver_register(&resolvfile_resolver);
}

void __connman_resolver_cleanup(void)
{
	DBG("");

	connman_resolver_unregister(&resolvfile_resolver);
}
