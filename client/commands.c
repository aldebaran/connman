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

void show_help(void)
{
	printf("Usage: connmanctl <command> [args]\n"
	"  enable                             Enables given technology\n"
	"        <technology>\n"
	"        offlinemode                  Enables OfflineMode\n"
	"  disable                            Disables given technology\n"
	"        <technology>\n"
	"        offlinemode                  Disables OfflineMode\n"
	"  state                              Shows if the system is online or offline\n"
	"  services                           Display list of all services\n"
	"        --properties <service name>  Show properties of service\n"
	"  technologies                       Current technology on the system\n"
	"  scan <technology>                  Scans for new services on the given technology\n"
	"  connect <service>                  Connect to a given service\n"
	"  disconnect <service>               Disconnect from service\n"
	"  config <service> [arg]             Set certain config options\n"
	"        --autoconnect=y/n            Set autoconnect to service\n"
	"        --nameservers <names>        Set manual name servers\n"
	"        --timeservers <names>        Set manual time servers\n"
	"        --domains <domains>          Set manual domains\n"
	"        --ipv4                       Set ipv4 configuration\n"
	"          [METHOD|DHCP|AUTO|MANUAL] [IP] [NETMASK] [GATEWAY]\n"
	"        --ipv6                       Set ipv6 configuration\n"
	"          [METHOD|AUTO|MANUAL|OFF] [IP] [PREFIXLENGTH] [GATEWAY]\n"
	"          [PRIVACY|DISABLED|ENABLED|PREFERED]\n"
	"        --proxy                      Set proxy configuration\n"
	"          [METHOD|URL|SERVERS|EXCLUDES]\n"
	"          if METHOD = manual, enter 'servers' then the list of servers\n"
	"                         then enter 'excludes' then the list of excludes\n"
	"        --remove                     Remove the service from favorite\n"
	"  monitor                            Monitor signals from all Connman interfaces\n"
	"        --services                   Monitor signals from the Service interface\n"
	"        --tech                       Monitor signals from the Technology interface\n"
	"        --manager                    Monitor signals from the Manager interface\n"
	"  help, --help, (no arguments)       Show this dialogue\n"
	"  exit, quit, q                      Quit interactive mode\n"
	"\nNote: arguments and output are considered EXPERIMENTAL for now.\n\n");
}

int service_switch(int argc, char *argv[], int c, DBusConnection *conn,
						struct service_data *service)
{
	const char *name;
	DBusMessage *message;
	int error = 0;

	message = get_message(conn, "GetServices");
	if (message == NULL)
		return -ENOMEM;

	switch (c) {
	case 'p':
		name = find_service(conn, message, argv[2], service);
		if (name == NULL) {
			error = -ENXIO;
			break;
		}

		error = list_properties(conn, "GetServices", (char *) name);
		break;
	default:
		fprintf(stderr, "Command not recognized, please check help\n");
		error = -EINVAL;
		break;
	}

	dbus_message_unref(message);

	return error;
}

int config_switch(int argc, char *argv[], int c, DBusConnection *conn)
{
	DBusMessage *message;
	int num_args = argc - MANDATORY_ARGS;
	int error = 0;
	dbus_bool_t val;

	message = get_message(conn, "GetServices");
	if (message == NULL)
		return -ENOMEM;

	switch (c) {
	case 'a':
		switch (*optarg) {
		case 'y':
		case '1':
		case 't':
			val = TRUE;
			break;
		case 'n':
		case '0':
		case 'f':
			val = FALSE;
			break;
		default:
			return -EINVAL;
		}
		error = set_service_property(conn, message, argv[1],
						"AutoConnect", NULL,
						&val, 0);
		break;
	case 'i':
		error = set_service_property(conn, message, argv[1],
					"IPv4.Configuration", ipv4,
					argv + MANDATORY_ARGS, num_args);
		break;
	case 'v':
		error = set_service_property(conn, message, argv[1],
					"IPv6.Configuration", ipv6,
					argv + MANDATORY_ARGS, num_args);
		break;
	case 'n':
		error = set_service_property(conn, message, argv[1],
					"Nameservers.Configuration", NULL,
					argv + MANDATORY_ARGS, num_args);
		break;
	case 't':
		error = set_service_property(conn, message, argv[1],
					"Timeservers.Configuration", NULL,
					argv + MANDATORY_ARGS, num_args);
		break;
	case 'd':
		error = set_service_property(conn, message, argv[1],
					"Domains.Configuration", NULL,
					argv + MANDATORY_ARGS, num_args);
		break;
	case 'x':
		if ((strcmp(argv[3], "direct") == 0 && argc < 5) ||
			(strcmp(argv[3], "auto") == 0 && argc < 6)) {
			error = set_service_property(conn, message, argv[1],
					"Proxy.Configuration", proxy_simple,
					argv + MANDATORY_ARGS, num_args);
		} else if (strcmp(argv[3], "manual") == 0
				  && strcmp(argv[4], "servers") == 0
				  && argc > 5) {
			argc -= 5;
			error = store_proxy_input(conn, message, argv[1],
								argc, &argv[5]);
		} else {
			fprintf(stderr, "Incorrect arguments\n");
			error = -EINVAL;
		}
		break;
	case 'r':
		error = remove_service(conn, message, argv[1]);
		break;
	default:
		fprintf(stderr, "Command not recognized, please check help\n");
		error = -EINVAL;
		break;
	}

	dbus_message_unref(message);

	return error;
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

int commands_no_options(DBusConnection *connection, char *argv[], int argc)
{
	DBusMessage *message = NULL;
	int error = 0;


	if (strcmp(argv[0], "--help") == 0 || strcmp(argv[0], "help") == 0  ||
						strcmp(argv[0], "h") == 0) {
		show_help();
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
	struct service_data service;

	static struct option service_options[] = {
		{"properties", required_argument, 0, 'p'},
		{0, 0, 0, 0}
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
		{0, 0, 0, 0}
	};

	static struct option monitor_options[] = {
		{"services", no_argument, 0, 's'},
		{"tech", no_argument, 0, 'c'},
		{"manager", no_argument, 0, 'm'},
		{0, 0, 0, 0}
	};

	if (strcmp(argv[0], "services") == 0) {
		if (argc > 3) {
			fprintf(stderr, "Too many arguments for services, "
								"see help\n");
			return -EINVAL;
		}
		if (argc < 2) {
			printf("List of all services:\n");
			error = list_properties(connection, "GetServices", NULL);
			if (error != 0)
				return error;
		} else {
			while ((c = getopt_long(argc, argv, "", service_options,
						&option_index))) {
				if (c == -1) {
					if (option_index == 0) {
						printf("Services takes an "
							"option, see help.\n");
						return -EINVAL;
					}
					break;
				}
				error = service_switch(argc, argv, c,
								connection,
								&service);
				if (error != 0)
					return error;
				option_index++;
			}
		}
	} else if (strcmp(argv[0], "config") == 0) {
		if (argc < 3) {
			fprintf(stderr, "Config requires an option, "
								"see help\n");
			return -EINVAL;
		}
		while ((c = getopt_long(argc, argv, "", config_options,
							&option_index))) {
			if (c == -1) {
				if (option_index == 0) {
					printf("Config requires an option, "
							"see help\n");
					return -EINVAL;
				}
				break;
			}
			error = config_switch(argc, argv, c, connection);
			if (error != 0)
				return error;
			option_index++;
		}
	} else if (strcmp(argv[0], "monitor") == 0) {
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
