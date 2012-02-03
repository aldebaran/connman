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

#include <errno.h>

#include <glib.h>

#include "connman.h"

static GSList *driver_list = NULL;
static GHashTable *server_hash = NULL;

static void save_timeservers(char **servers)
{
	GKeyFile *keyfile;
	int cnt;

	keyfile = __connman_storage_load_global();
	if (keyfile == NULL)
		keyfile = g_key_file_new();

	for (cnt = 0; servers != NULL && servers[cnt] != NULL; cnt++);

	g_key_file_set_string_list(keyfile, "global", "Timeservers",
			   (const gchar **)servers, cnt);

	__connman_storage_save_global(keyfile);

	g_key_file_free(keyfile);

	return;
}

static char **load_timeservers()
{
	GKeyFile *keyfile;
	GError *error = NULL;
	char **servers = NULL;

	keyfile = __connman_storage_load_global();
	if (keyfile == NULL)
		return NULL;

	servers = g_key_file_get_string_list(keyfile, "global",
						"Timeservers", NULL, &error);
	if (error) {
		DBG("Error loading timeservers: %s", error->message);
		g_error_free(error);
	}

	g_key_file_free(keyfile);

	return servers;
}

static gint compare_priority(gconstpointer a, gconstpointer b)
{
	const struct connman_timeserver_driver *driver1 = a;
	const struct connman_timeserver_driver *driver2 = b;

	return driver2->priority - driver1->priority;
}

/**
 * connman_timeserver_driver_register:
 * @driver: timeserver driver definition
 *
 * Register a new timeserver driver
 *
 * Returns: %0 on success
 */
int connman_timeserver_driver_register(struct connman_timeserver_driver *driver)
{
	DBG("driver %p name %s", driver, driver->name);

	driver_list = g_slist_insert_sorted(driver_list, driver,
							compare_priority);

	return 0;
}

/**
 * connman_timeserver_driver_unregister:
 * @driver: timeserver driver definition
 *
 * Remove a previously registered timeserver driver
 */
void connman_timeserver_driver_unregister(struct connman_timeserver_driver *driver)
{
	DBG("driver %p name %s", driver, driver->name);

	driver_list = g_slist_remove(driver_list, driver);
}

/**
 * connman_timeserver_append:
 * @server: server address
 *
 * Append time server server address to current list
 */
int connman_timeserver_append(const char *server)
{
	GSList *list;

	DBG("server %s", server);

	if (server == NULL)
		return -EINVAL;

	/* This server is already handled by a driver */
	if (g_hash_table_lookup(server_hash, server))
		return 0;

	for (list = driver_list; list; list = list->next) {
		struct connman_timeserver_driver *driver = list->data;
		char *new_server;

		if (driver->append == NULL)
			continue;

		new_server = g_strdup(server);
		if (new_server == NULL)
			return -ENOMEM;

		if (driver->append(server) == 0) {
			g_hash_table_insert(server_hash, new_server, driver);
			return 0;
		} else {
			g_free(new_server);
		}
	}

	return -ENOENT;
}

/**
 * connman_timeserver_remove:
 * @server: server address
 *
 * Remover time server server address from current list
 */
int connman_timeserver_remove(const char *server)
{
	struct connman_timeserver_driver *driver;

	DBG("server %s", server);

	if (server == NULL)
		return -EINVAL;

	driver = g_hash_table_lookup(server_hash, server);
	if (driver == NULL)
		return -EINVAL;

	g_hash_table_remove(server_hash, server);

	if (driver->remove == NULL)
		return -ENOENT;

	return driver->remove(server);
}

void connman_timeserver_sync(void)
{
	GSList *list;

	DBG("");

	for (list = driver_list; list; list = list->next) {
		struct connman_timeserver_driver *driver = list->data;

		if (driver->sync == NULL)
			continue;

		driver->sync();
	}
}

int __connman_timeserver_system_append(const char *server)
{
	int len;
	char **servers = NULL;

	if (server == NULL) {
		save_timeservers(servers);
		return 0;
	}

	DBG("server %s", server);

	servers = load_timeservers();

	if (servers != NULL) {
		int i;

		for (i = 0; servers[i] != NULL; i++)
			if (g_strcmp0(servers[i], server) == 0) {
				g_strfreev(servers);
				return -EEXIST;
			}

		len = g_strv_length(servers);
		servers = g_try_renew(char *, servers, len + 2);
	} else {
		len = 0;
		servers = g_try_new0(char *, len + 2);
	}

	if (servers == NULL)
		return -ENOMEM;

	servers[len] = g_strdup(server);
	servers[len + 1] = NULL;

	save_timeservers(servers);

	g_strfreev(servers);

	return 0;
}

int __connman_timeserver_system_remove(const char *server)
{
	char **servers;
	char **temp;
	int len, i, j;

	if (server == NULL)
		return -EINVAL;

	DBG("server %s", server);

	servers = load_timeservers();

	if (servers == NULL)
		return 0;

	len = g_strv_length(servers);
	if (len == 1) {
		if (g_strcmp0(servers[0], server) != 0) {
			g_strfreev(servers);
			return 0;
		}

		g_strfreev(servers);
		servers = NULL;
		save_timeservers(servers);
		return 0;
	}

	temp = g_try_new0(char *, len - 1);
	if (temp == NULL) {
			g_strfreev(servers);
			return -ENOMEM;
	}

	for (i = 0, j = 0; i < len; i++) {
		if (g_strcmp0(servers[i], server) != 0) {
			temp[j] = g_strdup(servers[i]);
			j++;
		}
	}
	temp[len - 1] = NULL;

	g_strfreev(servers);
	servers = g_strdupv(temp);
	g_strfreev(temp);

	save_timeservers(servers);
	g_strfreev(servers);

	return 0;
}

char **__connman_timeserver_system_get()
{
	char **servers;

	servers = load_timeservers();
	return servers;
}

int __connman_timeserver_init(void)
{
	DBG("");

	server_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						g_free, NULL);

	return 0;
}

void __connman_timeserver_cleanup(void)
{
	DBG("");

	g_hash_table_destroy(server_hash);
}
