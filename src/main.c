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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#include <getopt.h>
#include <sys/stat.h>

#include <gdbus.h>

#include "connman.h"

static GMainLoop *main_loop = NULL;

static void sig_term(int sig)
{
	g_main_loop_quit(main_loop);
}

static void usage(void)
{
	printf("Connection Manager version %s\n\n", VERSION);

	printf("Usage:\n"
		"\tconnmand [options]\n"
		"\n");

	printf("Options:\n"
		"\t-c, --compat         Enable Network Manager compatibility\n"
		"\t-n, --nodaemon       Don't fork daemon to background\n"
		"\t-h, --help           Display help\n"
		"\n");
}

static struct option options[] = {
	{ "nodaemon", 0, 0, 'n' },
	{ "compat",   0, 0, 'c' },
	{ "help",     0, 0, 'h' },
	{ }
};

int main(int argc, char *argv[])
{
	DBusConnection *conn;
	struct sigaction sa;
	int log_option = LOG_NDELAY | LOG_PID;
	int opt, detach = 1, compat = 0;

	while ((opt = getopt_long(argc, argv, "+nch", options, NULL)) != EOF) {
		switch(opt) {
		case 'n':
			detach = 0;
			break;
		case 'c':
			compat = 1;
			break;
		case 'h':
		default:
			usage();
			exit(0);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (detach) {
		if (daemon(0, 0)) {
			perror("Can't start daemon");
			exit(1);
		}
	} else
		log_option |= LOG_PERROR;

	openlog("connmand", log_option, LOG_DAEMON);

	mkdir(STATEDIR, S_IRUSR | S_IWUSR | S_IXUSR |
			S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);

	mkdir(STORAGEDIR, S_IRUSR | S_IWUSR | S_IXUSR |
			S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);

	main_loop = g_main_loop_new(NULL, FALSE);

	conn = g_dbus_setup_bus(DBUS_BUS_SYSTEM, CONNMAN_SERVICE);
	if (conn == NULL) {
		fprintf(stderr, "Can't register with system bus\n");
		exit(1);
	}

	if (compat) {
		if (g_dbus_request_name(conn, NM_SERVICE) == FALSE)
			compat = 0;
	}

	__connman_manager_init(conn, compat);

	__connman_plugin_init();

	__connman_rtnl_init();

	__connman_iface_init(conn);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_term;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	g_main_loop_run(main_loop);

	__connman_iface_cleanup();

	__connman_rtnl_cleanup();

	__connman_plugin_cleanup();

	__connman_manager_cleanup();

	g_dbus_cleanup_connection(conn);

	g_main_loop_unref(main_loop);

	rmdir(STORAGEDIR);

	rmdir(STATEDIR);

	closelog();

	return 0;
}
