/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2012  Intel Corporation. All rights reserved.
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
#include <netdb.h>

#include "connman.h"

static GSList *ts_list = NULL;

static GResolv *resolv = NULL;
static int resolv_id = 0;

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
	char **servers = NULL;

	keyfile = __connman_storage_load_global();
	if (keyfile == NULL)
		return NULL;

	servers = g_key_file_get_string_list(keyfile, "global",
						"Timeservers", NULL, NULL);

	g_key_file_free(keyfile);

	return servers;
}

static void resolv_result(GResolvResultStatus status, char **results, gpointer user_data)
{
	int i;

	DBG("status %d", status);

	if (status == G_RESOLV_RESULT_STATUS_SUCCESS) {
		if (results != NULL) {
			for (i = 0; results[i]; i++)
				DBG("result: %s", results[i]);

			__connman_ntp_start(results[0]);

			return;
		}
	}

	/* If resolving fails, move to the next server */
	__connman_timeserver_sync_next();
}

/*
 * Once the timeserver list (ts_list) is created, we start querying the
 * servers one by one. If resolving fails on one of them, we move to the
 * next one. The user can enter either an IP address or a URL for the
 * timeserver. We only resolve the urls. Once we have a IP for the NTP
 * server, we start querying it for time corrections.
 */
void __connman_timeserver_sync_next()
{
	char *server;

	__connman_ntp_stop();

	/* Get the 1st server in the list */
	if (ts_list == NULL)
		return;

	server = ts_list->data;

	ts_list = g_slist_delete_link(ts_list, ts_list);

	/* if its a IP , directly query it. */
	if (connman_inet_check_ipaddress(server) > 0) {
		DBG("Using timeservers %s", server);

		__connman_ntp_start(server);

		g_free(server);
		return;
	}

	DBG("Resolving server %s", server);

	resolv_id = g_resolv_lookup_hostname(resolv, server,
						resolv_result, NULL);

	g_free(server);

	return;
}

GSList *__connman_timeserver_add_list(GSList *server_list,
		const char *timeserver)
{
	GSList *list = server_list;

	if (timeserver == NULL)
		return server_list;

	while (list != NULL) {
		char *existing_server = list->data;
		if (strcmp(timeserver, existing_server) == 0)
			return server_list;
		list = g_slist_next(list);
	}
	return g_slist_prepend(server_list, g_strdup(timeserver));
}

/*
 * __connman_timeserver_get_all function creates the timeserver
 * list which will be used to determine NTP server for time corrections.
 * The service settings take priority over the global timeservers.
 */
GSList *__connman_timeserver_get_all(struct connman_service *service)
{
	GSList *list = NULL;
	struct connman_network *network;
	char **timeservers;
	char **service_ts;
	char **service_ts_config;
	const char *service_gw;
	char **fallback_ts;
	int index, i;

	service_ts_config = connman_service_get_timeservers_config(service);

	/* First add Service Timeservers.Configuration to the list */
	for (i = 0; service_ts_config != NULL && service_ts_config[i] != NULL;
			i++)
		list = __connman_timeserver_add_list(list,
				service_ts_config[i]);

	service_ts = connman_service_get_timeservers(service);

	/* First add Service Timeservers via DHCP to the list */
	for (i = 0; service_ts != NULL && service_ts[i] != NULL; i++)
		list = __connman_timeserver_add_list(list, service_ts[i]);

	network = __connman_service_get_network(service);
	if (network != NULL) {
		index = connman_network_get_index(network);
		service_gw = __connman_ipconfig_get_gateway_from_index(index,
			CONNMAN_IPCONFIG_TYPE_ALL);

		/* Then add Service Gateway to the list */
		if (service_gw != NULL)
			list = __connman_timeserver_add_list(list, service_gw);
	}

	/* Then add Global Timeservers to the list */
	timeservers = load_timeservers();

	for (i = 0; timeservers != NULL && timeservers[i] != NULL; i++)
		list = __connman_timeserver_add_list(list, timeservers[i]);

	g_strfreev(timeservers);

	fallback_ts = connman_setting_get_string_list("FallbackTimeservers");

	/* Lastly add the fallback servers */
	for (i = 0; fallback_ts != NULL && fallback_ts[i] != NULL; i++)
		list = __connman_timeserver_add_list(list, fallback_ts[i]);

	return g_slist_reverse(list);
}

/*
 * This function must be called everytime the default service changes, the
 * service timeserver(s) or gatway changes or the global timeserver(s) changes.
 */
int __connman_timeserver_sync(struct connman_service *default_service)
{
	struct connman_service *service;

	if (default_service != NULL)
		service = default_service;
	else
		service = __connman_service_get_default();

	if (service == NULL)
		return -EINVAL;

	if (resolv == NULL)
		return 0;
	/*
	 * Before we start creating the new timeserver list we must stop
	 * any ongoing ntp query and server resolution.
	 */

	__connman_ntp_stop();

	if (resolv_id > 0)
		g_resolv_cancel_lookup(resolv, resolv_id);

	g_slist_free_full(ts_list, g_free);

	ts_list = __connman_timeserver_get_all(service);

	__connman_service_timeserver_changed(service, ts_list);

	if (ts_list == NULL) {
		DBG("No timeservers set.");
		return 0;
	}

        __connman_timeserver_sync_next();

	return 0;
}

static int timeserver_start(struct connman_service *service)
{
	char **nameservers;
	int i;

	DBG("service %p", service);

	i = __connman_service_get_index(service);
	if (i < 0)
		return -EINVAL;

	nameservers = connman_service_get_nameservers(service);
	if (nameservers == NULL)
		return -EINVAL;

	/* Stop an already ongoing resolution, if there is one */
	if (resolv != NULL && resolv_id > 0)
		g_resolv_cancel_lookup(resolv, resolv_id);

	/* get rid of the old resolver */
	if (resolv != NULL) {
		g_resolv_unref(resolv);
		resolv = NULL;
	}

	resolv = g_resolv_new(i);
	if (resolv == NULL) {
		g_strfreev(nameservers);
		return -ENOMEM;
	}

	if (getenv("CONNMAN_RESOLV_DEBUG"))
		g_resolv_set_debug(resolv, resolv_debug, "RESOLV");

	for (i = 0; nameservers[i] != NULL; i++)
		g_resolv_add_nameserver(resolv, nameservers[i], 53, 0);

	g_strfreev(nameservers);

	return __connman_timeserver_sync(service);
}

static void timeserver_stop()
{
	DBG(" ");

	if (resolv != NULL) {
		g_resolv_unref(resolv);
		resolv = NULL;
	}

	g_slist_free_full(ts_list, g_free);

	ts_list = NULL;

	__connman_ntp_stop();
}

int __connman_timeserver_system_set(char **servers)
{
	save_timeservers(servers);

	__connman_timeserver_sync(NULL);

	return 0;
}

char **__connman_timeserver_system_get()
{
	char **servers;

	servers = load_timeservers();
	return servers;
}

static void default_changed(struct connman_service *default_service)
{
	if (default_service != NULL)
		timeserver_start(default_service);
	else
		timeserver_stop();
}

static struct connman_notifier timeserver_notifier = {
	.name			= "timeserver",
	.default_changed	= default_changed,
};

int __connman_timeserver_init(void)
{
	DBG("");

	connman_notifier_register(&timeserver_notifier);

	return 0;
}

void __connman_timeserver_cleanup(void)
{
	DBG("");

	connman_notifier_unregister(&timeserver_notifier);
}
