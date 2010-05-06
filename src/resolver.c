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

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <resolv.h>

#include "connman.h"

#define RESOLVER_FLAG_PUBLIC (1 << 0)

struct entry_data {
	struct connman_resolver *resolver;
	char *interface;
	char *domain;
	char *server;
	unsigned int flags;
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

		if (resolver && resolver->remove)
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

static int append_resolver(const char *interface, const char *domain,
					const char *server, unsigned int flags)
{
	struct entry_data *entry;
	GSList *list;

	DBG("interface %s domain %s server %s flags %d",
					interface, domain, server, flags);

	if (server == NULL)
		return -EINVAL;

	entry = g_try_new0(struct entry_data, 1);
	if (entry == NULL)
		return -ENOMEM;

	entry->interface = g_strdup(interface);
	entry->domain = g_strdup(domain);
	entry->server = g_strdup(server);
	entry->flags = flags;

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
	DBG("interface %s domain %s server %s", interface, domain, server);

	return append_resolver(interface, domain, server, 0);
}

/**
 * connman_resolver_remove:
 * @interface: network interface
 * @domain: domain limitation
 * @server: server address
 *
 * Remover resolver server address from current list
 */
int connman_resolver_remove(const char *interface, const char *domain,
							const char *server)
{
	GSList *list, *matches = NULL;

	DBG("interface %s domain %s server %s", interface, domain, server);

	if (server == NULL)
		return -EINVAL;

	for (list = entry_list; list; list = list->next) {
		struct entry_data *entry = list->data;

		if (interface != NULL &&
				g_strcmp0(entry->interface, interface) != 0)
			continue;

		if (domain != NULL && g_strcmp0(entry->domain, domain) != 0)
			continue;

		if (g_strcmp0(entry->server, server) != 0)
			continue;

		matches = g_slist_append(matches, entry);
	}

	if (matches == NULL)
		return -ENOENT;

	remove_entries(matches);

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

	if (interface == NULL)
		return -EINVAL;

	for (list = entry_list; list; list = list->next) {
		struct entry_data *entry = list->data;

		if (g_strcmp0(entry->interface, interface) != 0)
			continue;

		matches = g_slist_append(matches, entry);
	}

	if (matches == NULL)
		return -ENOENT;

	remove_entries(matches);

	return 0;
}

/**
 * connman_resolver_append_public_server:
 * @server: server address
 *
 * Append public resolver server address to current list
 */
int connman_resolver_append_public_server(const char *server)
{
	DBG("server %s", server);

	return append_resolver(NULL, NULL, server, RESOLVER_FLAG_PUBLIC);
}

/**
 * connman_resolver_remove_public_server:
 * @server: server address
 *
 * Remove public resolver server address to current list
 */
int connman_resolver_remove_public_server(const char *server)
{
	DBG("server %s", server);

	return connman_resolver_remove(NULL, NULL, server);
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

	connman_resolver_append_public_server("8.8.8.8");

	connman_resolver_remove_public_server("8.8.8.8");

	connman_resolver_remove_all("wlan0");

	connman_resolver_unregister(&selftest_resolver);

	return 0;
}

struct resolvfile_entry {
	char *interface;
	char *domain;
	char *server;
};

static GList *resolvfile_list = NULL;

static void resolvfile_remove_entries(GList *entries)
{
	GList *list;

	for (list = entries; list; list = list->next) {
		struct resolvfile_entry *entry = list->data;

		resolvfile_list = g_list_remove(
					resolvfile_list, entry);

		g_free(entry->server);
		g_free(entry->domain);
		g_free(entry->interface);
		g_free(entry);
	}

	g_list_free(entries);
}

static int resolvfile_export(void)
{
	GList *list;
	GString *content;
	int fd, err;
	unsigned int count;
	mode_t old_umask;

	content = g_string_new("# Generated by Connection Manager\n"
						"options edns0\n");

	/* Nameservers are added in reverse so that the most recently appended
	 * entry is the primary nameserver.  No more than MAXNS nameservers are
	 * used.
	 */
	for (count = 0, list = g_list_last(resolvfile_list);
						list && (count < MAXNS);
						list = g_list_previous(list)) {
		struct resolvfile_entry *entry = list->data;
		g_string_append_printf(content, "nameserver %s\n",
								entry->server);
		count++;
	}

	old_umask = umask(022);

	fd = open("/etc/resolv.conf", O_RDWR | O_CREAT,
					S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fd < 0) {
		err = -errno;
		goto done;
	}

	if (ftruncate(fd, 0) < 0) {
		err = -errno;
		goto failed;
	}

	err = 0;

	if (write(fd, content->str, content->len) < 0)
		err = -errno;

failed:
	close(fd);

done:
	g_string_free(content, TRUE);
	umask(old_umask);

	return err;
}

static int resolvfile_append(const char *interface, const char *domain,
							const char *server)
{
	struct resolvfile_entry *entry;

	DBG("interface %s server %s", interface, server);

	if (interface == NULL)
		return -ENOENT;

	entry = g_try_new0(struct resolvfile_entry, 1);
	if (entry == NULL)
		return -ENOMEM;

	entry->interface = g_strdup(interface);
	entry->domain = g_strdup(domain);
	entry->server = g_strdup(server);

	resolvfile_list = g_list_append(resolvfile_list, entry);

	return resolvfile_export();
}

static int resolvfile_remove(const char *interface, const char *domain,
							const char *server)
{
	GList *list, *matches = NULL;

	DBG("interface %s server %s", interface, server);

	for (list = resolvfile_list; list; list = g_list_next(list)) {
		struct resolvfile_entry *entry = list->data;

		if (interface != NULL &&
				g_strcmp0(entry->interface, interface) != 0)
			continue;

		if (domain != NULL && g_strcmp0(entry->domain, domain) != 0)
			continue;

		if (g_strcmp0(entry->server, server) != 0)
			continue;

		matches = g_list_append(matches, entry);
	}

	resolvfile_remove_entries(matches);

	return resolvfile_export();
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
