/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
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
#include <errno.h>
#include <getopt.h>

#include <glib.h>
#include <gdbus.h>

#include "services.h"
#include "technology.h"
#include "data_manager.h"
#include "monitor.h"
#include "interactive.h"

#define MANDATORY_ARGS 3

static char *ipv4[] = {
	"Method",
	"Address",
	"Netmask",
	"Gateway",
	NULL
};

static char *ipv6[] = {
	"Method",
	"Address",
	"PrefixLength",
	"Gateway",
	"Privacy",
	NULL
};

static char *proxy_simple[] = {
	"Method",
	"URL",
	NULL
};

static int cmd_help(char *args[], int num, struct option *options);

static int parse_args(char *arg, struct option *options)
{
	int i;

	if (arg == NULL)
		return -1;

	for (i = 0; options[i].name != NULL; i++) {
		if (strcmp(options[i].name, arg) == 0 ||
				(strncmp(arg, "--", 2) == 0 &&
					strcmp(&arg[2], options[i].name) == 0))
			return options[i].val;
	}

	return '?';
}

static int cmd_enable(char *args[], int num, struct option *options)
{
	DBusMessage *message;
	int err;

	if (num > 2)
		return -E2BIG;

	if (num < 2)
		return -EINVAL;

	if (strcmp(args[1], "offlinemode") == 0) {
		err = set_manager(connection, "OfflineMode", TRUE);
		if (err == 0)
			printf("OfflineMode enabled\n");

		return 0;
	}

	message = get_message(connection, "GetTechnologies");
	if (message == NULL)
		return -ENOMEM;

	set_technology(connection, message, "Powered", args[1], TRUE);

	return 0;
}

static int cmd_disable(char *args[], int num, struct option *options)
{
	DBusMessage *message;
	int err;

	if (num > 2)
		return -E2BIG;

	if (num < 2)
		return -EINVAL;

	if (strcmp(args[1], "offlinemode") == 0) {
		err = set_manager(connection, "OfflineMode", FALSE);
		if (err == 0)
			printf("OfflineMode enabled\n");

		return 0;
	}

	message = get_message(connection, "GetTechnologies");
	if (message == NULL)
		return -ENOMEM;

	set_technology(connection, message, "Powered", args[1], FALSE);

	return 0;
}

static int cmd_state(char *args[], int num, struct option *options)
{
	if (num > 1)
		return -E2BIG;

	return list_properties(connection, "GetProperties", NULL);
}

static int cmd_services(char *args[], int num, struct option *options)
{
	char *service_name = NULL;
	int err = 0;
	int c;
	DBusMessage *message;

	if (num > 3)
		return -E2BIG;

	c = parse_args(args[1], options);
	switch (c) {
	case -1:
		break;
	case 'p':
		if (num < 3)
			return -EINVAL;
		service_name = args[2];
		break;
	default:
		if (num > 2)
			return -E2BIG;
		service_name = args[1];
		break;
	}

	message = get_message(connection, "GetServices");
	if (message == NULL)
		return -ENOMEM;

	err = list_properties(connection, "GetServices", service_name);
	dbus_message_unref(message);

	return err;
}

static int cmd_technologies(char *args[], int num, struct option *options)
{
	if (num > 1)
		return -E2BIG;

	return list_properties(connection, "GetTechnologies", NULL);
}

static int cmd_scan(char *args[], int num, struct option *options)
{
	DBusMessage *message;
	int err;

	if (num > 2)
		return -E2BIG;

	if (num < 2)
		return -EINVAL;

	message = get_message(connection, "GetTechnologies");
	if (message == NULL)
		err = -ENOMEM;
	else {
		err = scan_technology(connection, message, args[1]);
		if (err == 0)
			printf("Scan completed\n");
	}

	return 0;
}

static int cmd_connect(char *args[], int num, struct option *options)
{
	int err;

	if (num > 2)
		return -E2BIG;

	if (num < 2)
		return -EINVAL;

	err = connect_service(connection, args[1]);
	if (err == 0)
		printf("Connected\n");

	return 0;
}

static int cmd_disconnect(char *args[], int num, struct option *options)
{
	int err;

	if (num > 2)
		return -E2BIG;

	if (num < 2)
		return -EINVAL;

	err = disconnect_service(connection, args[1]);
	if (err == 0)
		printf("Disconnected\n");

	return 0;
}

static int cmd_config(char *args[], int num, struct option *options)
{
	int res = 0, index = 2, oldindex = 0;
	int c;
	char *service_name;
	DBusMessage *message;
	char **opt_start;
	dbus_bool_t val;

	service_name = args[1];
	if (service_name == NULL)
		return -EINVAL;

	while (index < num && args[index] != NULL) {
		c = parse_args(args[index], options);
		opt_start = &args[index + 1];
		res = 0;

		message = get_message(connection, "GetServices");
		if (message == NULL)
			return -ENOMEM;

		oldindex = index;

		switch (c) {
		case 'a':
			switch (parse_boolean(*opt_start)) {
			case 1:
				val = TRUE;
				break;
			case 0:
				val = FALSE;
				break;
			default:
				res = -EINVAL;
				break;
			}
			if (res == 0)
				res = set_service_property(connection, message,
						service_name, "AutoConnect",
						NULL, &val, 0);
			break;
		case 'i':
			res = set_service_property(connection, message,
					service_name, "IPv4.Configuration",
					ipv4, opt_start, 0);
			if (res < 0)
				index += 4;
			break;
		case 'v':
			res = set_service_property(connection, message,
					service_name, "IPv6.Configuration",
					ipv6, opt_start, 0);
			if (res < 0)
				index += 5;
			break;
		case 'n':
			res = set_service_property(connection, message,
					service_name,
					"Nameservers.Configuration",
					NULL, opt_start, 0);
			break;
		case 't':
			res = set_service_property(connection, message,
					service_name,
					"Timeservers.Configuration",
					NULL, opt_start, 0);
			break;
		case 'd':
			res = set_service_property(connection, message,
					service_name,
					"Domains.Configuration",
					NULL, opt_start, 0);
			break;
		case 'x':
			if (*opt_start == NULL) {
				res = -EINVAL;
				break;
			}

			if (strcmp(*opt_start, "direct") == 0) {
				res = set_service_property(connection, message,
						service_name,
						"Proxy.Configuration",
						proxy_simple, opt_start, 1);
				break;
			}

			if (strcmp(*opt_start, "auto") == 0) {
				res = set_service_property(connection, message,
						service_name,
						"Proxy.Configuration",
						proxy_simple, opt_start, 1);
				break;
			}

			if (strcmp(*opt_start, "manual") == 0) {
					char **url_start = &args[index + 2];

					if (*url_start != NULL &&
						strcmp(*url_start,
							"servers") == 0) {
						url_start = &args[index + 3];
						index++;
					}
					res = store_proxy_input(connection,
							message, service_name,
							0, url_start);
			}

			break;
		case 'r':
			res = remove_service(connection, message, service_name);
			break;
		default:
			res = -EINVAL;
			break;
		}

		dbus_message_unref(message);

		if (res < 0) {
			printf("Error '%s': %s\n", args[oldindex],
					strerror(-res));
		} else
			index += res;

		index++;
	}

	return 0;
}

static int cmd_monitor(char *args[], int num, struct option *options)
{
	int c;

	if (num > 3)
		return -E2BIG;

	c = parse_args(args[1], options);
	switch (c) {
	case -1:
		monitor_connman_service(connection);
		monitor_connman_technology(connection);
		monitor_connman_manager(connection);
		break;

	case 's':
		monitor_connman_service(connection);
		break;

	case 'c':
		monitor_connman_technology(connection);
		break;

	case 'm':
		monitor_connman_manager(connection);
		break;

	default:
		return -EINVAL;
	}

	return 0;
}

static int cmd_exit(char *args[], int num, struct option *options)
{
	return 0;
}

static struct option service_options[] = {
	{"properties", required_argument, 0, 'p'},
	{ NULL, }
};

static const char *service_desc[] = {
	"[<service>]      (obsolete)",
	NULL
};

static struct option config_options[] = {
	{"nameservers", required_argument, 0, 'n'},
	{"timeservers", required_argument, 0, 't'},
	{"domains", required_argument, 0, 'd'},
	{"ipv6", required_argument, 0, 'v'},
	{"proxy", required_argument, 0, 'x'},
	{"autoconnect", required_argument, 0, 'a'},
	{"ipv4", required_argument, 0, 'i'},
	{"remove", 0, 0, 'r'},
	{ NULL, }
};

static const char *config_desc[] = {
	"<dns1> [<dns2>] [<dns3>]",
	"<ntp1> [<ntp2>] [...]",
	"<domain1> [<domain2>] [...]",
	"off|auto|manual <address> <prefixlength> <gateway> <privacy>",
	"direct|auto <URL>|manual <URL1> [<URL2>] [...]\n"
	"                   [exclude <exclude1> [<exclude2>] [...]]",
	"yes|no",
	"off|dhcp|manual <address> <prefixlength> <gateway>",
	"                 Remove service",
	NULL
};

static struct option monitor_options[] = {
	{"services", no_argument, 0, 's'},
	{"tech", no_argument, 0, 'c'},
	{"manager", no_argument, 0, 'm'},
	{ NULL, }
};

static const char *monitor_desc[] = {
	"                 Monitor only services",
	"                 Monitor only technologies",
	"                 Monitor only manager interface",
	NULL
};

static const struct {
        const char *cmd;
	const char *argument;
        struct option *options;
	const char **options_desc;
        int (*func) (char *args[], int num, struct option *options);
        const char *desc;
} cmd_table[] = {
	{ "enable",       "<technology>|offline", NULL,    NULL,
	  cmd_enable, "Enables given technology or offline mode" },
	{ "disable",      "<technology>|offline", NULL,    NULL,
	  cmd_disable, "Disables given technology or offline mode"},
	{ "state",        NULL,           NULL,            NULL,
	  cmd_state, "Shows if the system is online or offline" },
	{ "services",     "[<service>]",  service_options, &service_desc[0],
	  cmd_services, "Display services" },
	{ "technologies", NULL,           NULL,            NULL,
	  cmd_technologies, "Display technologies" },
	{ "scan",         "<technology>", NULL,            NULL,
	  cmd_scan, "Scans for new services for given technology" },
	{ "connect",      "<service>",    NULL,            NULL,
	  cmd_connect, "Connect a given service" },
	{ "disconnect",   "<service>",    NULL,            NULL,
	  cmd_disconnect, "Disconnect a given service" },
	{ "config",       "<service>",    config_options,  &config_desc[0],
	  cmd_config, "Set service configuration options" },
	{ "monitor",      NULL,           monitor_options, &monitor_desc[0],
	  cmd_monitor, "Monitor signals from interfaces" },
	{ "help",         NULL,           NULL,            NULL,
	  cmd_help, "Show help" },
	{ "exit",         NULL,           NULL,            NULL,
	  cmd_exit,       "Exit" },
	{ "quit",         NULL,           NULL,            NULL,
	  cmd_exit,       "Quit" },
	{  NULL, },
};

static int cmd_help(char *args[], int num, struct option *options)
{
	int i, j;

	for (i = 0; cmd_table[i].cmd != NULL; i++) {
		const char *cmd = cmd_table[i].cmd;
		const char *argument = cmd_table[i].argument;
		const char *desc = cmd_table[i].desc;

		printf("%-12s%-22s%s\n", cmd != NULL? cmd: "",
				argument != NULL? argument: "",
				desc != NULL? desc: "");

		if (cmd_table[i].options != NULL) {
			for (j = 0; cmd_table[i].options[j].name != NULL;
			     j++) {
				const char *options_desc =
					cmd_table[i].options_desc != NULL ?
					cmd_table[i].options_desc[j]: "";

				printf("   --%-12s%s\n",
						cmd_table[i].options[j].name,
						options_desc);
			}
		}
	}

	return 0;
}

int commands(DBusConnection *connection, char *argv[], int argc)
{
	int i, result;

	for (i = 0; cmd_table[i].cmd != NULL; i++) {
		if (g_strcmp0(cmd_table[i].cmd, argv[0]) == 0 &&
				cmd_table[i].func != NULL) {
			result = cmd_table[i].func(argv, argc,
					cmd_table[i].options);
			if (result < 0)
				printf("Error '%s': %s\n", argv[0],
						strerror(-result));
			return result;
		}
	}

	return -1;
}
