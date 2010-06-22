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
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/task.h>
#include <connman/timeserver.h>
#include <connman/driver.h>
#include <connman/log.h>

/*
 * The peers list are the peers currently added to a running ntpd,
 * while pending_peers are the one appended but not used by ntpd yet.
 */
static GList *peers = NULL;
static GList *pending_peers = NULL;

#define NTPD_PORT 123

struct ntpd_peer {
	char *server;
	gint refcount;
};

struct ntpdate_task {
	struct connman_task *task;
	gint conf_fd;
	char *conf_path;
};

static struct ntpd_peer *find_peer(GList *peer_list, const char* server)
{
	GList *list;
	struct ntpd_peer *peer;

	for (list = peer_list; list; list = list->next) {
		peer = list->data;

		if (g_str_equal(peer->server, server))
			return peer;
	}

	return NULL;
}

static void remove_peer(GList *peer_list, struct ntpd_peer *peer)
{
	if (!g_atomic_int_dec_and_test(&peer->refcount))
		return;

	g_free(peer->server);
	g_free(peer);
	peer_list = g_list_remove(peer_list, peer);
}

static connman_bool_t ntpd_running(void)
{
	int sock;
	connman_bool_t ret;
	struct sockaddr_in server_addr;

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		return FALSE;

	server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(NTPD_PORT);
        server_addr.sin_addr.s_addr = INADDR_ANY;
        memset(&(server_addr.sin_zero), 0, 8);

	if (bind(sock, (struct sockaddr *)&server_addr,
			sizeof(struct sockaddr)) == -1) {
		if (errno == EADDRINUSE)
			ret = TRUE;
		else
			ret = FALSE;
        }

	close(sock);

	return ret;
}

static void ntpdate_died(struct connman_task *task, void *user_data)
{
	struct ntpdate_task *ntpdate = user_data;

	DBG("");

	unlink(ntpdate->conf_path);
	g_free(ntpdate->conf_path);
	connman_task_destroy(ntpdate->task);
}

static void ntpdate_add_peer(struct ntpdate_task *ntpdate, char *peer)
{
	FILE *conf_file;

	DBG("%s", peer);

	conf_file = fdopen(ntpdate->conf_fd, "a+");
	if (conf_file == NULL) {
		connman_error("fdopen failed");
		return;
	}

	fprintf(conf_file, "server %s iburst\n", peer);

	fclose(conf_file);
}

static int ntpdate(void)
{
	int err;
	GError *g_err;
	GList *list;
	struct ntpd_peer *peer;
	struct ntpdate_task *ntpdate;

	DBG("");

	ntpdate = g_try_new0(struct ntpdate_task, 1);
	if (ntpdate == NULL)
		return -ENOMEM;

	/* ntpdate is deprecated, we use ntpd -q instead */
	ntpdate->task = connman_task_create(NTPD);
	if (ntpdate->task == NULL) {
		err = -ENOMEM;
		goto error_task;
	}

	connman_task_add_argument(ntpdate->task, "-q", NULL);

	/* The servers are added through a temp configuration file */
	ntpdate->conf_fd = g_file_open_tmp("connman.ntp.conf_XXXXXX",
						&ntpdate->conf_path, &g_err);
	if  (ntpdate->conf_fd == -1) {
		err = g_err->code;
		g_free(g_err);
		goto error_open;
	}

	connman_task_add_argument(ntpdate->task, "-c", ntpdate->conf_path);

	DBG("conf path %s", ntpdate->conf_path);

	for (list = pending_peers; list; list = list->next) {
		peer = list->data;

		ntpdate_add_peer(ntpdate, peer->server);
	}

	for (list = peers; list; list = list->next) {
		peer = list->data;

		ntpdate_add_peer(ntpdate, peer->server);
	}

	close(ntpdate->conf_fd);

	return connman_task_run(ntpdate->task, ntpdate_died, ntpdate,
						NULL, NULL, NULL);
error_open:
	connman_task_destroy(ntpdate->task);

error_task:
	g_free(ntpdate);

	return err;
}

static int ntpd_add_peer(char *peer)
{
	DBG("%s", peer);

	return 0;
}

static void ntpd_sync(void)
{
	int err;
	GList *list;

	DBG("");

	if (g_list_length(pending_peers) == 0 &&
			g_list_length(peers) == 0)
		return;

	if (!ntpd_running()) {
		ntpdate();
		return;
	}

	/* TODO Grab ntp keys path */

	list = g_list_first(pending_peers);
	while(list) {
		struct ntpd_peer *peer = list->data;

		err = ntpd_add_peer(peer->server);
		if (err)
			continue;

		peers = g_list_prepend(peers, peer);

		list = g_list_next(list);

		pending_peers = g_list_remove(pending_peers, peer);
	};
}

static int ntpd_append(const char *server)
{
	struct ntpd_peer *peer;

	DBG("");

	if (server == NULL)
		return 0;

	if ((peer = find_peer(pending_peers, server)) ||
			(peer = find_peer(peers, server))) {
		g_atomic_int_inc(&peer->refcount);
		return 0;
	}

	peer = g_try_new0(struct ntpd_peer, 1);
	if (peer == NULL)
		return -ENOMEM;

	peer->server = g_strdup(server);
	if (peer->server == NULL) {
		g_free(peer);
		return -ENOMEM;
	}

	peer->refcount = 1;

	pending_peers = g_list_prepend(pending_peers, peer);

	return 0;
}

static int ntpd_remove(const char *server)
{
	struct ntpd_peer *peer;

	DBG("");

	if (server == NULL)
		return 0;

	peer = find_peer(peers, server);
	if (peer == NULL)
		goto remove;

	remove_peer(peers, peer);

remove:
	/* TODO: send ntpd remove command */

	peer = find_peer(pending_peers, server);
	if (peer == NULL)
		return 0;

	remove_peer(pending_peers, peer);

	return 0;
}

static struct connman_timeserver_driver ntpd_driver = {
	.name		= "ntpd",
	.priority	= CONNMAN_DRIVER_PRIORITY_DEFAULT,
	.append		= ntpd_append,
	.remove		= ntpd_remove,
	.sync		= ntpd_sync,
};

static int ntpd_init(void)
{
	return connman_timeserver_driver_register(&ntpd_driver);
}

static void ntpd_exit(void)
{
	connman_timeserver_driver_unregister(&ntpd_driver);
}

CONNMAN_PLUGIN_DEFINE(ntpd, "ntpd plugin", VERSION,
		CONNMAN_PLUGIN_PRIORITY_DEFAULT, ntpd_init, ntpd_exit)
