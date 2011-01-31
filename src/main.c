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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <sys/stat.h>
#include <net/if.h>

#include <gdbus.h>

#ifdef HAVE_CAPNG
#include <cap-ng.h>
#endif

#include "connman.h"

static GMainLoop *main_loop = NULL;

static void sig_term(int sig)
{
	connman_info("Terminating");

	g_main_loop_quit(main_loop);
}

static void disconnect_callback(DBusConnection *conn, void *user_data)
{
	connman_error("D-Bus disconnect");

	g_main_loop_quit(main_loop);
}

static gchar *option_debug = NULL;
static gchar *option_device = NULL;
static gchar *option_plugin = NULL;
static gchar *option_nodevice = NULL;
static gchar *option_noplugin = NULL;
static gchar *option_wifi = NULL;
static gboolean option_detach = TRUE;
static gboolean option_dnsproxy = TRUE;
static gboolean option_compat = FALSE;
static gboolean option_version = FALSE;

static gboolean parse_debug(const char *key, const char *value,
					gpointer user_data, GError **error)
{
	if (value)
		option_debug = g_strdup(value);
	else
		option_debug = g_strdup("*");

	return TRUE;
}

static GOptionEntry options[] = {
	{ "debug", 'd', G_OPTION_FLAG_OPTIONAL_ARG,
				G_OPTION_ARG_CALLBACK, parse_debug,
				"Specify debug options to enable", "DEBUG" },
	{ "device", 'i', 0, G_OPTION_ARG_STRING, &option_device,
			"Specify networking device or interface", "DEV" },
	{ "nodevice", 'I', 0, G_OPTION_ARG_STRING, &option_nodevice,
			"Specify networking interface to ignore", "DEV" },
	{ "plugin", 'p', 0, G_OPTION_ARG_STRING, &option_plugin,
				"Specify plugins to load", "NAME,..." },
	{ "noplugin", 'P', 0, G_OPTION_ARG_STRING, &option_noplugin,
				"Specify plugins not to load", "NAME,..." },
	{ "wifi", 'W', 0, G_OPTION_ARG_STRING, &option_wifi,
				"Specify driver for WiFi/Supplicant", "NAME" },
	{ "nodaemon", 'n', G_OPTION_FLAG_REVERSE,
				G_OPTION_ARG_NONE, &option_detach,
				"Don't fork daemon to background" },
	{ "nodnsproxy", 'r', G_OPTION_FLAG_REVERSE,
				G_OPTION_ARG_NONE, &option_dnsproxy,
				"Don't enable DNS Proxy" },
	{ "compat", 'c', 0, G_OPTION_ARG_NONE, &option_compat,
				"(obsolete)" },
	{ "version", 'v', 0, G_OPTION_ARG_NONE, &option_version,
				"Show version information and exit" },
	{ NULL },
};

const char *connman_option_get_string(const char *key)
{
	if (g_strcmp0(key, "wifi") == 0) {
		if (option_wifi == NULL)
			return "nl80211,wext";
		else
			return option_wifi;
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	GOptionContext *context;
	GError *error = NULL;
	DBusConnection *conn;
	DBusError err;
	struct sigaction sa;
	mode_t old_umask;

#ifdef HAVE_CAPNG
	/* Drop capabilities */
#endif

#ifdef NEED_THREADS
	if (g_thread_supported() == FALSE)
		g_thread_init(NULL);
#endif

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);

	if (g_option_context_parse(context, &argc, &argv, &error) == FALSE) {
		if (error != NULL) {
			g_printerr("%s\n", error->message);
			g_error_free(error);
		} else
			g_printerr("An unknown error occurred\n");
		exit(1);
	}

	g_option_context_free(context);

	if (option_version == TRUE) {
		printf("%s\n", VERSION);
		exit(0);
	}

	if (option_detach == TRUE) {
		if (daemon(0, 0)) {
			perror("Can't start daemon");
			exit(1);
		}
	}

	if (mkdir(STATEDIR, S_IRUSR | S_IWUSR | S_IXUSR |
				S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) < 0) {
		if (errno != EEXIST)
			perror("Failed to create state directory");
	}

	if (mkdir(STORAGEDIR, S_IRUSR | S_IWUSR | S_IXUSR |
				S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) < 0) {
		if (errno != EEXIST)
			perror("Failed to create storage directory");
	}

	if (mkdir(STORAGEDIR "/stats", S_IRUSR | S_IWUSR | S_IXUSR |
				S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) < 0) {
		if (errno != EEXIST)
			perror("Failed to create statistics directory");
	}

	old_umask = umask(077);

	main_loop = g_main_loop_new(NULL, FALSE);

#ifdef NEED_THREADS
	if (dbus_threads_init_default() == FALSE) {
		fprintf(stderr, "Can't init usage of threads\n");
		exit(1);
	}
#endif

	dbus_error_init(&err);

	conn = g_dbus_setup_bus(DBUS_BUS_SYSTEM, CONNMAN_SERVICE, &err);
	if (conn == NULL) {
		if (dbus_error_is_set(&err) == TRUE) {
			fprintf(stderr, "%s\n", err.message);
			dbus_error_free(&err);
		} else
			fprintf(stderr, "Can't register with system bus\n");
		exit(1);
	}

	g_dbus_set_disconnect_function(conn, disconnect_callback, NULL, NULL);

	__connman_log_init(option_debug, option_detach);

	__connman_dbus_init(conn);

	__connman_storage_init();
	__connman_element_init(option_device, option_nodevice);

	__connman_agent_init();
	__connman_iptables_init();
	__connman_tethering_init();
	__connman_counter_init();
	__connman_manager_init();
	__connman_profile_init();
	__connman_config_init();
	__connman_stats_init();

	__connman_resolver_init(option_dnsproxy);
	__connman_dnsproxy_init(option_dnsproxy);
	__connman_ipconfig_init();
	__connman_rtnl_init();
	__connman_task_init();
	__connman_proxy_init();
	__connman_detect_init();
	__connman_session_init();
	__connman_timeserver_init();

	__connman_plugin_init(option_plugin, option_noplugin);

	__connman_element_start();

	g_free(option_device);
	g_free(option_plugin);
	g_free(option_nodevice);
	g_free(option_noplugin);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_term;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	g_main_loop_run(main_loop);

	__connman_element_stop();

	__connman_plugin_cleanup();

	__connman_timeserver_cleanup();
	__connman_session_cleanup();
	__connman_detect_cleanup();
	__connman_proxy_cleanup();
	__connman_task_cleanup();
	__connman_rtnl_cleanup();
	__connman_ipconfig_cleanup();
	__connman_dnsproxy_cleanup();
	__connman_resolver_cleanup();

	__connman_stats_cleanup();
	__connman_config_cleanup();
	__connman_profile_cleanup();
	__connman_manager_cleanup();
	__connman_counter_cleanup();
	__connman_agent_cleanup();
	__connman_tethering_cleanup();
	__connman_iptables_cleanup();

	__connman_element_cleanup();
	__connman_storage_cleanup();

	__connman_dbus_cleanup();

	__connman_log_cleanup();

	dbus_connection_unref(conn);

	g_main_loop_unref(main_loop);

	return 0;
}
