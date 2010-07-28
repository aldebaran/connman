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
#include <string.h>
#include <signal.h>

#include <gdbus.h>

#define INTERFACE "isc.dhclient"
#define PATH "/dhclient"

static GTimer *timer;

static GMainLoop *main_loop;

static guint child_watch = 0;
static pid_t pid = 0;

static void sig_term(int sig)
{
	g_main_loop_quit(main_loop);
}

static void free_pointer(gpointer data, gpointer user_data)
{
	g_free(data);
}

static void dhclient_died(GPid pid, gint status, gpointer user_data)
{
	if (WIFEXITED(status))
		printf("exit status %d\n", WEXITSTATUS(status));
	else
		printf("signal %d\n", WTERMSIG(status));

	g_spawn_close_pid(pid);

	child_watch = 0;
}

static void dhclient_setup(gpointer user_data)
{
	printf("dhclient process setup\n");
}

static void add_argument(GPtrArray *array, const char *name,
						const char *format, ...)
{
	va_list ap;
	char *str;

	str = g_strdup(name);
	g_ptr_array_add(array, str);

	va_start(ap, format);

	if (format != NULL) {
		str = g_strdup_vprintf(format, ap);
		g_ptr_array_add(array, str);
	}

	va_end(ap);
}

static void start_dhclient(DBusConnection *conn, const char *ifname)
{
	GSpawnFlags flags = G_SPAWN_DO_NOT_REAP_CHILD;
	GPtrArray *argv;
	GPtrArray *envp;
	gboolean result;
	const char *busname;

	busname = dbus_bus_get_unique_name(conn);
	busname = "org.moblin.connman";

	argv = g_ptr_array_new();
	add_argument(argv, DHCLIENT, NULL);
	add_argument(argv, "-d", NULL);
	add_argument(argv, "-q", NULL);
	add_argument(argv, "-e", "BUSNAME=%s", busname);
	add_argument(argv, "-e", "BUSINTF=%s", INTERFACE);
	add_argument(argv, "-e", "BUSPATH=%s", PATH);
	add_argument(argv, "-pf", "%s/dhclient.%s.pid", STATEDIR, ifname);
	add_argument(argv, "-lf", "%s/dhclient.%s.leases", STATEDIR, ifname);
	add_argument(argv, "-cf", "%s/dhclient.conf", SCRIPTDIR);
	add_argument(argv, "-sf", "%s/dhclient-script", SCRIPTDIR);
	add_argument(argv, ifname, NULL);
	add_argument(argv, "-n", NULL);
	g_ptr_array_add(argv, NULL);

	envp = g_ptr_array_new();
	g_ptr_array_add(envp, NULL);

	result = g_spawn_async_with_pipes(NULL, (char **) argv->pdata,
						(char **) envp->pdata,
						flags, dhclient_setup, NULL,
						&pid, NULL, NULL, NULL, NULL);

	child_watch = g_child_watch_add(pid, dhclient_died, NULL);

	g_ptr_array_foreach(envp, free_pointer, NULL);
	g_ptr_array_free(envp, TRUE);

	g_ptr_array_foreach(argv, free_pointer, NULL);
	g_ptr_array_free(argv, TRUE);
}

static void parse_notification(DBusMessage *msg)
{
	DBusMessageIter iter, dict;
	dbus_uint32_t pid;
	gdouble elapsed;
	const char *text, *key, *value;

	dbus_message_iter_init(msg, &iter);

	dbus_message_iter_get_basic(&iter, &pid);
	dbus_message_iter_next(&iter);

	dbus_message_iter_get_basic(&iter, &text);
	dbus_message_iter_next(&iter);

	printf("change %d to %s\n", pid, text);

	dbus_message_iter_recurse(&iter, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);
		dbus_message_iter_get_basic(&entry, &value);

		printf("%s = %s\n", key, value);

		dbus_message_iter_next(&dict);
	}

	if (g_strcmp0(text, "PREINIT") == 0)
		return;

	elapsed = g_timer_elapsed(timer, NULL);

	g_print("elapsed %f seconds\n", elapsed);

	g_main_loop_quit(main_loop);
}

static DBusHandlerResult notify_filter(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	if (dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_METHOD_CALL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (dbus_message_has_interface(msg, INTERFACE) == FALSE)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (dbus_message_has_path(msg, PATH) == FALSE)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (dbus_message_has_member(msg, "Notify") == FALSE)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	parse_notification(msg);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static const char *notify_rule = "type=method_call"
					",interface=" INTERFACE;

int main(int argc, char *argv[])
{
	DBusConnection *conn;
	DBusError err;
	struct sigaction sa;
	const char *ifname;

	if (argc < 2) {
		printf("Usage: dhclient-test <interface name>\n");
		exit(0);
	}

	ifname = argv[1];

	printf("Create DHCP client for interface %s\n", ifname);

	main_loop = g_main_loop_new(NULL, FALSE);

	dbus_error_init(&err);

	conn = g_dbus_setup_bus(DBUS_BUS_SYSTEM, "org.moblin.connman", &err);
	if (conn == NULL) {
		if (dbus_error_is_set(&err) == TRUE) {
			fprintf(stderr, "%s\n", err.message);
			dbus_error_free(&err);
		} else
			fprintf(stderr, "Can't register with system bus\n");
		exit(1);
	}

	dbus_connection_add_filter(conn, notify_filter, NULL, NULL);

	dbus_bus_add_match(conn, notify_rule, NULL);
	dbus_connection_flush(conn);

	printf("Start DHCP operation\n");

	timer = g_timer_new();

	start_dhclient(conn, ifname);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_term;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	g_main_loop_run(main_loop);

	if (pid > 0)
		kill(pid, SIGTERM);

	if (child_watch > 0)
		g_source_remove(child_watch);

	g_timer_destroy(timer);

	dbus_bus_remove_match(conn, notify_rule, NULL);
	dbus_connection_flush(conn);

	dbus_connection_remove_filter(conn, notify_filter, NULL);

	dbus_connection_unref(conn);

	g_main_loop_unref(main_loop);

	return 0;
}
