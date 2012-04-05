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
#include <stdlib.h>
#include <gweb/gresolv.h>

#include "connman.h"

static char **system_timeservers = NULL;
static char **timeservers = NULL;

static GResolv *resolv = NULL;
static int resolv_id = 0;
static volatile int count;

static void resolv_debug(const char *str, void *data)
{
	connman_info("%s: %s\n", (const char *) data, str);
}
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

/* Restart NTP procedure */
static void connman_timeserver_restart()
{
	/* If service timeservers are in use, dont restart ntp */
	if (timeservers != NULL)
		return;

	if (resolv == NULL) {
		DBG("No online service.");
		return;
	}

	/* Cancel current lookup */
	if(resolv_id > 0)
		g_resolv_cancel_lookup(resolv, resolv_id);

	/* Reload system timeserver list */
	if (system_timeservers != NULL) {
		g_strfreev(system_timeservers);
		system_timeservers = NULL;
	}

	system_timeservers = load_timeservers();

	if (system_timeservers == NULL)
		return;

	__connman_ntp_stop();

	count = 0;

	__connman_timeserver_sync_next();
}

static void resolv_result(GResolvResultStatus status, char **results, gpointer user_data)
{
	int i;

	DBG("status %d", status);

	__sync_fetch_and_add(&count, 1);

	if (status == G_RESOLV_RESULT_STATUS_SUCCESS) {
		if (results != NULL) {
			for (i = 0; results[i]; i++)
				DBG("result: %s", results[i]);

			__connman_ntp_start(results[0]);

			return;
		}
	}

	__connman_timeserver_sync_next();
}

void __connman_timeserver_sync_next()
{
	if (system_timeservers == NULL ||
	system_timeservers[count] == NULL)
		return;

	DBG("Trying timeserver %s", system_timeservers[count]);

	if (resolv)
		resolv_id = g_resolv_lookup_hostname(resolv,
			system_timeservers[count], resolv_result,
						NULL);
}

int __connman_timeserver_sync(struct connman_service *service)
{
	char **nameservers = NULL;
	int i;

	DBG("service %p", service);

	i = __connman_service_get_index(service);
	if (i < 0)
		return -EINVAL;

	nameservers = connman_service_get_nameservers(service);
	if (nameservers == NULL)
		return -EINVAL;

	resolv = g_resolv_new(i);
	if (resolv == NULL)
		return -ENOMEM;

	if (getenv("CONNMAN_RESOLV_DEBUG"))
		g_resolv_set_debug(resolv, resolv_debug, "RESOLV");

	for (i = 0; nameservers[i] != NULL; i++)
		g_resolv_add_nameserver(resolv, nameservers[i], 53, 0);

	count = 0;

	system_timeservers = load_timeservers();

	timeservers = connman_service_get_timeservers(service);

	if (timeservers != NULL && timeservers[0] != NULL) {
		DBG("Using service tiemservers");
		__connman_ntp_start(timeservers[0]);
		return 0;
	}

	if (system_timeservers == NULL || system_timeservers[count] == NULL) {
		DBG("No timeservers set.");
		return 0;
	}

	DBG("Trying server %s", system_timeservers[count]);

	resolv_id = g_resolv_lookup_hostname(resolv, system_timeservers[count],
						resolv_result, NULL);
	return 0;
}

void __connman_timeserver_stop()
{
	DBG(" ");

	if (resolv != NULL) {
		g_resolv_unref(resolv);
		resolv = NULL;
	}

	if (system_timeservers != NULL) {
		g_strfreev(system_timeservers);
		system_timeservers = NULL;
	}

	timeservers = NULL;

	count = 0;

	__connman_ntp_stop();
}

int __connman_timeserver_system_set(char **servers)
{
	save_timeservers(servers);

	connman_timeserver_restart();

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

	return 0;
}

void __connman_timeserver_cleanup(void)
{
	DBG("");
}
