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

int monitor_switch(int argc, char *argv[], int c, DBusConnection *conn)
{
	int error;

	switch (c) {
	case 's':
		error = monitor_connman(conn, "Service", "PropertyChanged");
		if (error != 0)
			return error;
		if (dbus_connection_add_filter(conn, service_property_changed,
							NULL, NULL) == FALSE)
			return -ENOMEM;
		printf("Now monitoring the service interface.\n");
		break;
	case 'c':
		error = monitor_connman(conn, "Technology", "PropertyChanged");
		if (error != 0)
			return error;
		if (dbus_connection_add_filter(conn, tech_property_changed,
							NULL, NULL) == FALSE)
			return -ENOMEM;
		printf("Now monitoring the technology interface.\n");
		break;
	case 'm':
		error = monitor_connman(conn, "Manager", "PropertyChanged");
		if (error != 0)
			return error;
		error = monitor_connman(conn, "Manager", "TechnologyAdded");
		if (error != 0)
			return error;
		error = monitor_connman(conn, "Manager", "TechnologyRemoved");
		if (error != 0)
			return error;
		error = monitor_connman(conn, "Manager", "ServicesChanged");
		if (error != 0)
			return error;
		if (dbus_connection_add_filter(conn, manager_property_changed,
							NULL, NULL) == FALSE)
			return -ENOMEM;
		if (dbus_connection_add_filter(conn, tech_added_removed,
							NULL, NULL) == FALSE)
			return -ENOMEM;
		if (dbus_connection_add_filter(conn, manager_services_changed,
							NULL, NULL) == FALSE)
			return -ENOMEM;
		printf("Now monitoring the manager interface.\n");
		break;
	default:
		fprintf(stderr, "Command not recognized, please check help\n");
		return -EINVAL;
		break;
	}
	return 0;
}

static int cmd_enable(char *args[], int num, struct option *options)
{
	return -1;
}

static int cmd_disable(char *args[], int num, struct option *options)
{
	return -1;
}

static int cmd_state(char *args[], int num, struct option *options)
{
	return -1;
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
	return -1;
}

static int cmd_scan(char *args[], int num, struct option *options)
{
	return -1;
}

static int cmd_connect(char *args[], int num, struct option *options)
{
	return -1;
}

static int cmd_disconnect(char *args[], int num, struct option *options)
{
	return -1;
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
	return -1;
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
			return 0;
		}
	}

	return -1;
}

int commands_no_options(DBusConnection *connection, char *argv[], int argc)
{
	DBusMessage *message = NULL;
	int error = 0;

	if (strcmp(argv[0], "--help") == 0 || strcmp(argv[0], "help") == 0  ||
						strcmp(argv[0], "h") == 0) {
		printf("Usage: connmanctl [[command] [args]]\n");
		cmd_help(NULL, 0, NULL);
		printf("\nNote: arguments and output are considered "
				"EXPERIMENTAL for now.\n\n");
	} else if (strcmp(argv[0], "state") == 0) {
		if (argc != 1) {
			fprintf(stderr, "State cannot accept an argument, "
								"see help\n");
			error = -EINVAL;
		} else
			error = list_properties(connection,
						"GetProperties", NULL);
	} else if (strcmp(argv[0], "technologies") == 0) {
		if (argc != 1) {
			fprintf(stderr, "Tech cannot accept an argument, "
								"see help\n");
			error = -EINVAL;
		} else
			error = list_properties(connection,
						"GetTechnologies", NULL);
	} else if (strcmp(argv[0], "connect") == 0) {
		if (argc != 2) {
			fprintf(stderr, "Connect requires a service name or "
							"path, see help\n");
			error = -EINVAL;
		} else
			error = connect_service(connection,
						strip_service_path(argv[1]));
		if (error == 0)
			printf("Connected to: %s\n",
						strip_service_path(argv[1]));
	} else if (strcmp(argv[0], "disconnect") == 0) {
		if (argc != 2) {
			fprintf(stderr, "Disconnect requires a service name or "
							"path, see help\n");
			error = -EINVAL;
		} else
			error = disconnect_service(connection,
						strip_service_path(argv[1]));
		if (error == 0)
			printf("Disconnected from: %s\n",
						strip_service_path(argv[1]));
	} else if (strcmp(argv[0], "scan") == 0) {
		if (argc != 2) {
			fprintf(stderr, "Scan requires a service name or path, "
								"see help\n");
			error = -EINVAL;
		}
		message = get_message(connection, "GetTechnologies");
		if (message == NULL)
			error = -ENOMEM;
		else
			error = scan_technology(connection, message, argv[1]);
	} else if (strcmp(argv[0], "enable") == 0) {
		if (argc != 2) {
			fprintf(stderr, "Enable requires a technology name or "
				"the argument 'offlinemode', see help\n");
			error = -EINVAL;
		} else if (strcmp(argv[1], "offlinemode") == 0) {
			error = set_manager(connection, "OfflineMode", TRUE);
			if (error == 0)
				printf("OfflineMode is now enabled\n");
		} else {
			message = get_message(connection, "GetTechnologies");
			if (message == NULL)
				error = -ENOMEM;
			else
				error = set_technology(connection, message,
						"Powered", argv[1], TRUE);
			if (error == 0)
				printf("Enabled %s technology\n", argv[1]);
		}
	} else if (strcmp(argv[0], "disable") == 0) {
		if (argc != 2) {
			fprintf(stderr, "Disable requires a technology name or "
				"the argument 'offlinemode' see help\n");
			error = -EINVAL;
		} else if (strcmp(argv[1], "offlinemode") == 0) {
			error = set_manager(connection, "OfflineMode", FALSE);
			if (error == 0)
				printf("OfflineMode is now disabled\n");
		} else {
			message = get_message(connection, "GetTechnologies");
			if (message == NULL)
				error = -ENOMEM;
			else
				error = set_technology(connection, message,
						"Powered", argv[1], FALSE);
			if (error == 0)
				printf("Disabled %s technology\n", argv[1]);
		}
	} else
		return -1;

	if (message != NULL)
		dbus_message_unref(message);

	return error;
}

int commands_options(DBusConnection *connection, char *argv[], int argc)
{
	int error, c;
	int option_index = 0;

	if (strcmp(argv[0], "monitor") == 0) {
		if (argc > 2) {
			fprintf(stderr, "Too many arguments for monitor, "
								"see help\n");
			return -EINVAL;
		}
		if (argc < 2) {
			error = monitor_connman(connection, "Service",
							"PropertyChanged");
			if (error != 0)
				return error;
			error = monitor_connman(connection, "Technology",
							"PropertyChanged");
			if (error != 0)
				return error;
			error = monitor_connman(connection, "Manager",
							"PropertyChanged");
			if (error != 0)
				return error;
			error = monitor_connman(connection, "Manager",
							"TechnologyAdded");
			if (error != 0)
				return error;
			error = monitor_connman(connection, "Manager",
							"TechnologyRemoved");
			if (error != 0)
				return error;
			error = monitor_connman(connection, "Manager",
							"ServicesChanged");
			if (error != 0)
				return error;
			if (dbus_connection_add_filter(connection,
					service_property_changed, NULL, NULL)
								== FALSE)
				return -ENOMEM;
			if (dbus_connection_add_filter(connection,
					tech_property_changed, NULL, NULL)
								== FALSE)
				return -ENOMEM;
			if (dbus_connection_add_filter(connection,
					tech_added_removed, NULL, NULL)
								== FALSE)
				return -ENOMEM;
			if (dbus_connection_add_filter(connection,
					manager_property_changed, NULL, NULL)
								== FALSE)
				return -ENOMEM;
			if (dbus_connection_add_filter(connection,
					manager_services_changed, NULL, NULL)
								== FALSE)
				return -ENOMEM;
			printf("Now monitoring all interfaces.\n");
		} else
			while ((c = getopt_long(argc, argv, "", monitor_options,
							&option_index))) {
				if (c == -1) {
					if (option_index == 0) {
						printf("Monitor takes an "
							"option, see help\n");
						return -EINVAL;
					}
					break;
				}
				error = monitor_switch(argc, argv, c, connection);
				if (error != 0)
					return error;
				option_index++;
			}
	} else
		return -1;
	return 0;
}
