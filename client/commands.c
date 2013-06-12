/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2012-2013  Intel Corporation. All rights reserved.
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
#include <stdbool.h>

#include <glib.h>
#include <gdbus.h>

#include "dbus_helpers.h"
#include "input.h"
#include "services.h"
#include "commands.h"
#include "agent.h"
#include "vpnconnections.h"

static DBusConnection *connection;

struct connman_option {
	const char *name;
	const char val;
	const char *desc;
};

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
	NULL
};

static int cmd_help(char *args[], int num, struct connman_option *options);

static bool check_dbus_name(const char *name)
{
	/*
	 * Valid dbus chars should be [A-Z][a-z][0-9]_
	 * and should not start with number.
	 */
	unsigned int i;

	if (name == NULL || name[0] == '\0')
		return false;

	for (i = 0; name[i] != '\0'; i++)
		if (!((name[i] >= 'A' && name[i] <= 'Z') ||
				(name[i] >= 'a' && name[i] <= 'z') ||
				(name[i] >= '0' && name[i] <= '9') ||
				name[i] == '_'))
			return false;

	return true;
}

static int parse_boolean(char *arg)
{
	if (arg == NULL)
		return -1;

	if (strcasecmp(arg, "no") == 0 ||
			strcasecmp(arg, "false") == 0 ||
			strcasecmp(arg, "off" ) == 0 ||
			strcasecmp(arg, "disable" ) == 0 ||
			strcasecmp(arg, "n") == 0 ||
			strcasecmp(arg, "f") == 0 ||
			strcasecmp(arg, "0") == 0)
		return 0;

	if (strcasecmp(arg, "yes") == 0 ||
			strcasecmp(arg, "true") == 0 ||
			strcasecmp(arg, "on") == 0 ||
			strcasecmp(arg, "enable" ) == 0 ||
			strcasecmp(arg, "y") == 0 ||
			strcasecmp(arg, "t") == 0 ||
			strcasecmp(arg, "1") == 0)
		return 1;

	return -1;
}

static int parse_args(char *arg, struct connman_option *options)
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

static int enable_return(DBusMessageIter *iter, const char *error,
		void *user_data)
{
	char *tech = user_data;
	char *str;

	str = strrchr(tech, '/');
	if (str != NULL)
		str++;
	else
		str = tech;

	if (error == NULL) {
		fprintf(stdout, "Enabled %s\n", str);
	} else
		fprintf(stderr, "Error %s: %s\n", str, error);

	g_free(user_data);

	return 0;
}

static int cmd_enable(char *args[], int num, struct connman_option *options)
{
	char *tech;
	dbus_bool_t b = TRUE;

	if (num > 2)
		return -E2BIG;

	if (num < 2)
		return -EINVAL;

	if (check_dbus_name(args[1]) == false)
		return -EINVAL;

	if (strcmp(args[1], "offlinemode") == 0) {
		tech = g_strdup(args[1]);
		return __connmanctl_dbus_set_property(connection, "/",
				"net.connman.Manager", enable_return, tech,
				"OfflineMode", DBUS_TYPE_BOOLEAN, &b);
	}

	tech = g_strdup_printf("/net/connman/technology/%s", args[1]);
	return __connmanctl_dbus_set_property(connection, tech,
				"net.connman.Technology", enable_return, tech,
				"Powered", DBUS_TYPE_BOOLEAN, &b);
}

static int disable_return(DBusMessageIter *iter, const char *error,
		void *user_data)
{
	char *tech = user_data;
	char *str;

	str = strrchr(tech, '/');
	if (str != NULL)
		str++;
	else
		str = tech;

	if (error == NULL) {
		fprintf(stdout, "Disabled %s\n", str);
	} else
		fprintf(stderr, "Error %s: %s\n", str, error);

	g_free(user_data);

	return 0;
}

static int cmd_disable(char *args[], int num, struct connman_option *options)
{
	char *tech;
	dbus_bool_t b = FALSE;

	if (num > 2)
		return -E2BIG;

	if (num < 2)
		return -EINVAL;

	if (check_dbus_name(args[1]) == false)
		return -EINVAL;

	if (strcmp(args[1], "offlinemode") == 0) {
		tech = g_strdup(args[1]);
		return __connmanctl_dbus_set_property(connection, "/",
				"net.connman.Manager", disable_return, tech,
				"OfflineMode", DBUS_TYPE_BOOLEAN, &b);
	}

	tech = g_strdup_printf("/net/connman/technology/%s", args[1]);
	return __connmanctl_dbus_set_property(connection, tech,
				"net.connman.Technology", disable_return, tech,
				"Powered", DBUS_TYPE_BOOLEAN, &b);
}

static int state_print(DBusMessageIter *iter, const char *error,
		void *user_data)
{
	DBusMessageIter entry;

	if (error != NULL) {
		fprintf(stderr, "Error: %s", error);
		return 0;
	}

	dbus_message_iter_recurse(iter, &entry);
	__connmanctl_dbus_print(&entry, "  ", " = ", "\n");
	fprintf(stdout, "\n");

	return 0;
}

static int cmd_state(char *args[], int num, struct connman_option *options)
{
	if (num > 1)
		return -E2BIG;

	return __connmanctl_dbus_method_call(connection, CONNMAN_SERVICE,
			CONNMAN_PATH, "net.connman.Manager", "GetProperties",
			state_print, NULL, DBUS_TYPE_INVALID);
}

static int services_list(DBusMessageIter *iter, const char *error,
		void *user_data)
{
	if (error == NULL) {
		__connmanctl_services_list(iter);
		fprintf(stdout, "\n");
	} else {
		fprintf(stderr, "Error: %s\n", error);
	}

	return 0;
}

static int services_properties(DBusMessageIter *iter, const char *error,
		void *user_data)
{
	char *path = user_data;
	char *str;
	DBusMessageIter dict;

	if (error == NULL) {
		fprintf(stdout, "%s\n", path);

		dbus_message_iter_recurse(iter, &dict);
		__connmanctl_dbus_print(&dict, "  ", " = ", "\n");

		fprintf(stdout, "\n");

	} else {
		str = strrchr(path, '/');
		if (str != NULL)
			str++;
		else
			str = path;

		fprintf(stderr, "Error %s: %s\n", str, error);
	}

	g_free(user_data);

	return 0;
}

static int cmd_services(char *args[], int num, struct connman_option *options)
{
	char *service_name = NULL;
	char *path;
	int c;

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

	if (service_name == NULL) {
		return __connmanctl_dbus_method_call(connection,
				CONNMAN_SERVICE, CONNMAN_PATH,
				"net.connman.Manager", "GetServices",
				services_list, NULL, DBUS_TYPE_INVALID);
	}

	if (check_dbus_name(service_name) == false)
		return -EINVAL;

	path = g_strdup_printf("/net/connman/service/%s", service_name);
	return __connmanctl_dbus_method_call(connection, CONNMAN_SERVICE, path,
			"net.connman.Service", "GetProperties",
			services_properties, path, DBUS_TYPE_INVALID);
}

static int technology_print(DBusMessageIter *iter, const char *error,
		void *user_data)
{
	DBusMessageIter array;

	if (error != NULL) {
		fprintf(stderr, "Error: %s\n", error);
		return 0;
	}

	dbus_message_iter_recurse(iter, &array);
	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_STRUCT) {
		DBusMessageIter entry, dict;
		const char *path;

		dbus_message_iter_recurse(&array, &entry);
		dbus_message_iter_get_basic(&entry, &path);
		fprintf(stdout, "%s\n", path);

		dbus_message_iter_next(&entry);

		dbus_message_iter_recurse(&entry, &dict);
		__connmanctl_dbus_print(&dict, "  ", " = ", "\n");
		fprintf(stdout, "\n");

		dbus_message_iter_next(&array);
	}

	return 0;
}

static int cmd_technologies(char *args[], int num,
		struct connman_option *options)
{
	if (num > 1)
		return -E2BIG;

	return __connmanctl_dbus_method_call(connection, CONNMAN_SERVICE,
			CONNMAN_PATH, "net.connman.Manager", "GetTechnologies",
			technology_print, NULL,	DBUS_TYPE_INVALID);
}

struct tether_enable {
	char *path;
	dbus_bool_t enable;
};

static int tether_set_return(DBusMessageIter *iter, const char *error,
		void *user_data)
{
	struct tether_enable *tether = user_data;
	char *str;

	str = strrchr(tether->path, '/');
	if (str != NULL)
		str++;
	else
		str = tether->path;

	if (error == NULL) {
		fprintf(stdout, "%s tethering for %s\n",
				tether->enable == TRUE ? "Enabled": "Disabled",
				str);
	} else
		fprintf(stderr, "Error %s %s tethering: %s\n",
				tether->enable == TRUE ?
				"enabling": "disabling", str, error);

	g_free(tether->path);
	g_free(user_data);

	return 0;
}

static int tether_set(char *technology, int set_tethering)
{
	struct tether_enable *tether = g_new(struct tether_enable, 1);

	switch(set_tethering) {
	case 1:
		tether->enable = TRUE;
		break;
	case 0:
		tether->enable = FALSE;
		break;
	default:
		g_free(tether);
		return 0;
	}

	tether->path = g_strdup_printf("/net/connman/technology/%s",
			technology);

	return __connmanctl_dbus_set_property(connection, tether->path,
			"net.connman.Technology", tether_set_return,
			tether, "Tethering", DBUS_TYPE_BOOLEAN,
			&tether->enable);
}

struct tether_properties {
	int ssid_result;
	int passphrase_result;
	int set_tethering;
};

static int tether_update(struct tether_properties *tether)
{
	printf("%d %d %d\n", tether->ssid_result, tether->passphrase_result,
		tether->set_tethering);

	if (tether->ssid_result == 0 && tether->passphrase_result == 0)
		return tether_set("wifi", tether->set_tethering);

	if (tether->ssid_result != -EINPROGRESS &&
			tether->passphrase_result != -EINPROGRESS) {
		g_free(tether);
		return 0;
	}

	return -EINPROGRESS;
}

static int tether_set_ssid_return(DBusMessageIter *iter, const char *error,
		void *user_data)
{
	struct tether_properties *tether = user_data;

	if (error == NULL) {
		fprintf(stdout, "Wifi SSID set\n");
		tether->ssid_result = 0;
	} else {
		fprintf(stderr, "Error setting wifi SSID: %s\n", error);
		tether->ssid_result = -EINVAL;
	}

	return tether_update(tether);
}

static int tether_set_passphrase_return(DBusMessageIter *iter,
		const char *error, void *user_data)
{
	struct tether_properties *tether = user_data;

	if (error == NULL) {
		fprintf(stdout, "Wifi passphrase set\n");
		tether->passphrase_result = 0;
	} else {
		fprintf(stderr, "Error setting wifi passphrase: %s\n", error);
		tether->passphrase_result = -EINVAL;
	}

	return tether_update(tether);
}

static int tether_set_ssid(char *ssid, char *passphrase, int set_tethering)
{
	struct tether_properties *tether = g_new(struct tether_properties, 1);

	tether->set_tethering = set_tethering;

	tether->ssid_result = __connmanctl_dbus_set_property(connection,
			"/net/connman/technology/wifi",
			"net.connman.Technology",
			tether_set_ssid_return, tether,
			"TetheringIdentifier", DBUS_TYPE_STRING, &ssid);

	tether->passphrase_result =__connmanctl_dbus_set_property(connection,
			"/net/connman/technology/wifi",
			"net.connman.Technology",
			tether_set_passphrase_return, tether,
			"TetheringPassphrase", DBUS_TYPE_STRING, &passphrase);

	if (tether->ssid_result != -EINPROGRESS &&
			tether->passphrase_result != -EINPROGRESS) {
		g_free(tether);
		return -ENXIO;
	}

	return -EINPROGRESS;
}

static int cmd_tether(char *args[], int num, struct connman_option *options)
{
	char *ssid, *passphrase;
	int set_tethering;

	if (num < 3)
		return -EINVAL;

	passphrase = args[num - 1];
	ssid = args[num - 2];

	set_tethering = parse_boolean(args[2]);

	if (strcmp(args[1], "wifi") == 0) {

		if (num > 5)
			return -E2BIG;

		if (num == 5 && set_tethering == -1)
			return -EINVAL;

		if (num == 4)
			set_tethering = -1;

		if (num > 3)
			return tether_set_ssid(ssid, passphrase, set_tethering);
	}

	if (num > 3)
		return -E2BIG;

	if (set_tethering == -1)
		return -EINVAL;

	if (check_dbus_name(args[1]) == false)
		return -EINVAL;

	return tether_set(args[1], set_tethering);
}

static int scan_return(DBusMessageIter *iter, const char *error,
		void *user_data)
{
	char *path = user_data;

	if (error == NULL) {
		char *str = strrchr(path, '/');
		str++;
		fprintf(stdout, "Scan completed for %s\n", str);
	} else
		fprintf(stderr, "Error %s: %s\n", path, error);

	g_free(user_data);

	return 0;
}

static int cmd_scan(char *args[], int num, struct connman_option *options)
{
	char *path;

	if (num > 2)
		return -E2BIG;

	if (num < 2)
		return -EINVAL;

	if (check_dbus_name(args[1]) == false)
		return -EINVAL;

	path = g_strdup_printf("/net/connman/technology/%s", args[1]);
	return __connmanctl_dbus_method_call(connection, CONNMAN_SERVICE, path,
			"net.connman.Technology", "Scan",
			scan_return, path, DBUS_TYPE_INVALID);
}

static int connect_return(DBusMessageIter *iter, const char *error,
		void *user_data)
{
	char *path = user_data;

	if (error == NULL) {
		char *str = strrchr(path, '/');
		str++;
		fprintf(stdout, "Connected %s\n", str);
	} else
		fprintf(stderr, "Error %s: %s\n", path, error);

	g_free(user_data);

	return 0;
}

static int cmd_connect(char *args[], int num, struct connman_option *options)
{
	char *path;

	if (num > 2)
		return -E2BIG;

	if (num < 2)
		return -EINVAL;

	if (check_dbus_name(args[1]) == false)
		return -EINVAL;

	path = g_strdup_printf("/net/connman/service/%s", args[1]);
	return __connmanctl_dbus_method_call(connection, CONNMAN_SERVICE, path,
			"net.connman.Service", "Connect",
			connect_return, path, DBUS_TYPE_INVALID);
}

static int disconnect_return(DBusMessageIter *iter, const char *error,
		void *user_data)
{
	char *path = user_data;

	if (error == NULL) {
		char *str = strrchr(path, '/');
		str++;
		fprintf(stdout, "Disconnected %s\n", str);
	} else
		fprintf(stderr, "Error %s: %s\n", path, error);

	g_free(user_data);

	return 0;
}

static int cmd_disconnect(char *args[], int num, struct connman_option *options)
{
	char *path;

	if (num > 2)
		return -E2BIG;

	if (num < 2)
		return -EINVAL;

	if (check_dbus_name(args[1]) == false)
		return -EINVAL;

	path = g_strdup_printf("/net/connman/service/%s", args[1]);
	return __connmanctl_dbus_method_call(connection, CONNMAN_SERVICE, path,
			"net.connman.Service", "Disconnect",
			disconnect_return, path, DBUS_TYPE_INVALID);
}

static int config_return(DBusMessageIter *iter, const char *error,
		void *user_data)
{
	char *service_name = user_data;

	if (error != NULL)
		fprintf(stderr, "Error %s: %s\n", service_name, error);

	g_free(user_data);

	return 0;
}

struct config_append {
	char **opts;
	int values;
};

static void config_append_ipv4(DBusMessageIter *iter,
		void *user_data)
{
	struct config_append *append = user_data;
	char **opts = append->opts;
	int i = 0;

	if (opts == NULL)
		return;

	while (opts[i] != NULL && ipv4[i] != NULL) {
		__connmanctl_dbus_append_dict_entry(iter, ipv4[i],
				DBUS_TYPE_STRING, &opts[i]);
		i++;
	}

	append->values = i;
}

static void config_append_ipv6(DBusMessageIter *iter, void *user_data)
{
	struct config_append *append = user_data;
	char **opts = append->opts;

	if (opts == NULL)
		return;

	append->values = 1;

	if (g_strcmp0(opts[0], "auto") == 0) {
		char *str;

		switch (parse_boolean(opts[1])) {
		case 0:
			append->values = 2;

			str = "disabled";
			__connmanctl_dbus_append_dict_entry(iter, "Privacy",
					DBUS_TYPE_STRING, &str);
			break;

		case 1:
			append->values = 2;

			str = "enabled";
			__connmanctl_dbus_append_dict_entry(iter, "Privacy",
					DBUS_TYPE_STRING, &str);
			break;

		default:
			if (opts[1] != NULL) {
				append->values = 2;

				if (g_strcmp0(opts[1], "prefered") != 0 &&
						g_strcmp0(opts[1],
							"preferred") != 0) {
					fprintf(stderr, "Error %s: %s\n",
							opts[1],
							strerror(EINVAL));
					return;
				}

				str = "prefered";
				__connmanctl_dbus_append_dict_entry(iter,
						"Privacy", DBUS_TYPE_STRING,
						&str);
			}
			break;
		}
	} else if (g_strcmp0(opts[0], "manual") == 0) {
		int i = 1;

		while (opts[i] != NULL && ipv6[i] != NULL) {
			if (i == 2) {
				int value = atoi(opts[i]);
				__connmanctl_dbus_append_dict_entry(iter,
						ipv6[i], DBUS_TYPE_BYTE,
						&value);
			} else {
				__connmanctl_dbus_append_dict_entry(iter,
						ipv6[i], DBUS_TYPE_STRING,
						&opts[i]);
			}
			i++;
		}

		append->values = i;

	} else if (g_strcmp0(opts[0], "off") != 0) {
		fprintf(stderr, "Error %s: %s\n", opts[0], strerror(-EINVAL));

		return;
	}

	__connmanctl_dbus_append_dict_entry(iter, "Method", DBUS_TYPE_STRING,
				&opts[0]);
}

static void config_append_str(DBusMessageIter *iter, void *user_data)
{
	struct config_append *append = user_data;
	char **opts = append->opts;
	int i = 0;

	if (opts == NULL)
		return;

	while (opts[i] != NULL) {
		dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING,
				&opts[i]);
		i++;
	}

	append->values = i;
}

static void append_servers(DBusMessageIter *iter, void *user_data)
{
	struct config_append *append = user_data;
	char **opts = append->opts;
	int i = 1;

	if (opts == NULL)
		return;

	while (opts[i] != NULL && g_strcmp0(opts[i], "--excludes") != 0) {
		dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING,
				&opts[i]);
		i++;
	}

	append->values = i;
}

static void append_excludes(DBusMessageIter *iter, void *user_data)
{
	struct config_append *append = user_data;
	char **opts = append->opts;
	int i = append->values;

	if (opts == NULL || opts[i] == NULL ||
			g_strcmp0(opts[i], "--excludes") != 0)
		return;

	i++;
	while (opts[i] != NULL) {
		dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING,
				&opts[i]);
		i++;
	}

	append->values = i;
}

static void config_append_proxy(DBusMessageIter *iter, void *user_data)
{
	struct config_append *append = user_data;
	char **opts = append->opts;

	if (opts == NULL)
		return;

	if (g_strcmp0(opts[0], "manual") == 0) {
		__connmanctl_dbus_append_dict_string_array(iter, "Servers",
				append_servers, append);

		__connmanctl_dbus_append_dict_string_array(iter, "Excludes",
				append_excludes, append);

	} else if (g_strcmp0(opts[0], "auto") == 0) {
		if (opts[1] != NULL) {
			__connmanctl_dbus_append_dict_entry(iter, "URL",
					DBUS_TYPE_STRING, &opts[1]);
			append->values++;
		}

	} else if (g_strcmp0(opts[0], "direct") != 0)
		return;

	__connmanctl_dbus_append_dict_entry(iter, "Method",DBUS_TYPE_STRING,
			&opts[0]);

	append->values++;
}

static int cmd_config(char *args[], int num, struct connman_option *options)
{
	int result = 0, res = 0, index = 2, oldindex = 0;
	int c;
	char *service_name, *path;
	char **opt_start;
	dbus_bool_t val;
	struct config_append append;

	service_name = args[1];
	if (service_name == NULL)
		return -EINVAL;

	if (check_dbus_name(service_name) == false)
		return -EINVAL;

	while (index < num && args[index] != NULL) {
		c = parse_args(args[index], options);
		opt_start = &args[index + 1];
		append.opts = opt_start;
		append.values = 0;

		res = 0;

		oldindex = index;
		path = g_strdup_printf("/net/connman/service/%s", service_name);

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

			index++;

			if (res == 0) {
				res = __connmanctl_dbus_set_property(connection,
						path, "net.connman.Service",
						config_return,
						g_strdup(service_name),
						"AutoConnect",
						DBUS_TYPE_BOOLEAN, &val);
			}
			break;
		case 'i':
			res = __connmanctl_dbus_set_property_dict(connection,
					path, "net.connman.Service",
					config_return, g_strdup(service_name),
					"IPv4.Configuration", DBUS_TYPE_STRING,
					config_append_ipv4, &append);
			index += append.values;
			break;

		case 'v':
			res = __connmanctl_dbus_set_property_dict(connection,
					path, "net.connman.Service",
					config_return, g_strdup(service_name),
					"IPv6.Configuration", DBUS_TYPE_STRING,
					config_append_ipv6, &append);
			index += append.values;
			break;

		case 'n':
			res = __connmanctl_dbus_set_property_array(connection,
					path, "net.connman.Service",
					config_return, g_strdup(service_name),
					"Nameservers.Configuration",
					DBUS_TYPE_STRING, config_append_str,
					&append);
			index += append.values;
			break;

		case 't':
			res = __connmanctl_dbus_set_property_array(connection,
					path, "net.connman.Service",
					config_return, g_strdup(service_name),
					"Timeservers.Configuration",
					DBUS_TYPE_STRING, config_append_str,
					&append);
			index += append.values;
			break;

		case 'd':
			res = __connmanctl_dbus_set_property_array(connection,
					path, "net.connman.Service",
					config_return, g_strdup(service_name),
					"Domains.Configuration",
					DBUS_TYPE_STRING, config_append_str,
					&append);
			index += append.values;
			break;

		case 'x':
			res = __connmanctl_dbus_set_property_dict(connection,
					path, "net.connman.Service",
					config_return, g_strdup(service_name),
					"Proxy.Configuration",
					DBUS_TYPE_STRING, config_append_proxy,
					&append);
			index += append.values;
			break;
		case 'r':
			res = __connmanctl_dbus_method_call(connection,
					CONNMAN_SERVICE, path,
					"net.connman.Service", "Remove",
					config_return, g_strdup(service_name),
					DBUS_TYPE_INVALID);
			break;
		default:
			res = -EINVAL;
			break;
		}

		g_free(path);

		if (res < 0) {
			if (res == -EINPROGRESS)
				result = -EINPROGRESS;
			else
				printf("Error '%s': %s\n", args[oldindex],
						strerror(-res));
		} else
			index += res;

		index++;
	}

	return result;
}

static DBusHandlerResult monitor_changed(DBusConnection *connection,
		DBusMessage *message, void *user_data)
{
	DBusMessageIter iter;
	const char *interface, *path;

	interface = dbus_message_get_interface(message);
	if (strncmp(interface, "net.connman.", 12) != 0)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (strncmp(interface, "net.connman.Agent", 17) == 0 ||
			strncmp(interface, "net.connman.vpn.Agent", 21) == 0)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	interface = strrchr(interface, '.');
	if (interface != NULL && *interface != '\0')
		interface++;

	path = strrchr(dbus_message_get_path(message), '/');
	if (path != NULL && *path != '\0')
		path++;

	__connmanctl_save_rl();

	if (dbus_message_is_signal(message, "net.connman.Manager",
					"ServicesChanged") == TRUE) {

		fprintf(stdout, "%-12s %-20s = {\n", interface,
				"ServicesChanged");
		dbus_message_iter_init(message, &iter);
		__connmanctl_services_list(&iter);
		fprintf(stdout, "\n}\n");

		__connmanctl_redraw_rl();

		return DBUS_HANDLER_RESULT_HANDLED;
	}


	if (dbus_message_is_signal(message, "net.connman.vpn.Manager",
					"ConnectionAdded") == TRUE ||
			dbus_message_is_signal(message,
					"net.connman.vpn.Manager",
					"ConnectionRemoved") == TRUE) {
		interface = "vpn.Manager";
		path = dbus_message_get_member(message);

	} else if (dbus_message_is_signal(message, "net.connman.Manager",
					"TechnologyAdded") == TRUE ||
			dbus_message_is_signal(message, "net.connman.Manager",
					"TechnologyRemoved") == TRUE)
		path = dbus_message_get_member(message);

	fprintf(stdout, "%-12s %-20s ", interface, path);
	dbus_message_iter_init(message, &iter);

	__connmanctl_dbus_print(&iter, "", " = ", " = ");
	fprintf(stdout, "\n");

	__connmanctl_redraw_rl();

	return DBUS_HANDLER_RESULT_HANDLED;
}

static struct {
	char *interface;
	bool enabled;
} monitor[] = {
	{ "Service", false },
	{ "Technology", false },
	{ "Manager", false },
	{ "vpn.Manager", false },
	{ "vpn.Connection", false },
	{ NULL, },
};

static void monitor_add(char *interface)
{
	bool add_filter = true, found = false;
	int i;
	char *rule;
	DBusError err;

	for (i = 0; monitor[i].interface != NULL; i++) {
		if (monitor[i].enabled == true)
			add_filter = false;

		if (g_strcmp0(interface, monitor[i].interface) == 0) {
			if (monitor[i].enabled == true)
				return;

			monitor[i].enabled = true;
			found = true;
		}
	}

	if (found == false)
		return;

	if (add_filter == true)
		dbus_connection_add_filter(connection, monitor_changed,
				NULL, NULL);

	dbus_error_init(&err);
	rule  = g_strdup_printf("type='signal',interface='net.connman.%s'",
			interface);
	dbus_bus_add_match(connection, rule, &err);
	g_free(rule);

	if (dbus_error_is_set(&err))
		fprintf(stderr, "Error: %s\n", err.message);
}

static void monitor_del(char *interface)
{
	bool del_filter = true, found = false;
	int i;
	char *rule;


	for (i = 0; monitor[i].interface != NULL; i++) {
		if (g_strcmp0(interface, monitor[i].interface) == 0) {
			if (monitor[i].enabled == false)
				return;

			monitor[i].enabled = false;
			found = true;
		}

		if (monitor[i].enabled == true)
			del_filter = false;
	}

	if (found == false)
		return;

	rule  = g_strdup_printf("type='signal',interface='net.connman.%s'",
			interface);
	dbus_bus_remove_match(connection, rule, NULL);
	g_free(rule);

	if (del_filter == true)
		dbus_connection_remove_filter(connection, monitor_changed,
				NULL);
}

static int cmd_monitor(char *args[], int num, struct connman_option *options)
{
	bool add = true;
	int c;

	if (num > 3)
		return -E2BIG;

	if (num == 3) {
		switch (parse_boolean(args[2])) {
		case 0:
			add = false;
			break;

		default:
			break;
		}
	}

	c = parse_args(args[1], options);
	switch (c) {
	case -1:
		monitor_add("Service");
		monitor_add("Technology");
		monitor_add("Manager");
		monitor_add("vpn.Manager");
		monitor_add("vpn.Connection");
		break;

	case 's':
		if (add == true)
			monitor_add("Service");
		else
			monitor_del("Service");
		break;

	case 'c':
		if (add == true)
			monitor_add("Technology");
		else
			monitor_del("Technology");
		break;

	case 'm':
		if (add == true)
			monitor_add("Manager");
		else
			monitor_del("Manager");
		break;

	case 'M':
		if (add == true)
			monitor_add("vpn.Manager");
		else
			monitor_del("vpn.Manager");
		break;

	case 'C':
		if (add == true)
			monitor_add("vpn.Connection");
		else
			monitor_del("vpn.Connection");
		break;

	default:
		switch(parse_boolean(args[1])) {
		case 0:
			monitor_del("Service");
			monitor_del("Technology");
			monitor_del("Manager");
			monitor_del("vpn.Manager");
			monitor_del("vpn.Connection");
			break;

		case 1:
			monitor_add("Service");
			monitor_add("Technology");
			monitor_add("Manager");
			monitor_add("vpn.Manager");
			monitor_add("vpn.Connection");
			break;

		default:
			return -EINVAL;
		}
	}

	if (add == true)
		return -EINPROGRESS;

	return 0;
}

static int cmd_agent(char *args[], int num, struct connman_option *options)
{
	if (num > 2)
		return -E2BIG;

	if (num < 2)
		return -EINVAL;

	switch(parse_boolean(args[1])) {
	case 0:
		__connmanctl_agent_unregister(connection);
		break;

	case 1:
		if (__connmanctl_agent_register(connection) == -EINPROGRESS)
			return -EINPROGRESS;

		break;

	default:
		return -EINVAL;
		break;
	}

	return 0;
}

static int vpnconnections_properties(DBusMessageIter *iter, const char *error,
		void *user_data)
{
	char *path = user_data;
	char *str;
	DBusMessageIter dict;

	if (error == NULL) {
		fprintf(stdout, "%s\n", path);

		dbus_message_iter_recurse(iter, &dict);
		__connmanctl_dbus_print(&dict, "  ", " = ", "\n");

		fprintf(stdout, "\n");

	} else {
		str = strrchr(path, '/');
		if (str != NULL)
			str++;
		else
			str = path;

		fprintf(stderr, "Error %s: %s\n", str, error);
	}

	g_free(user_data);

	return 0;
}

static int vpnconnections_list(DBusMessageIter *iter, const char *error,
		void *user_data)
{
	if (error == NULL)
		__connmanctl_vpnconnections_list(iter);
        else
		fprintf(stderr, "Error: %s\n", error);

	return 0;
}

static int cmd_vpnconnections(char *args[], int num,
		struct connman_option *options)
{
	char *vpnconnection_name, *path;

	if (num > 2)
		return -E2BIG;

	vpnconnection_name = args[1];

	if (vpnconnection_name == NULL)
		return __connmanctl_dbus_method_call(connection,
				VPN_SERVICE, VPN_PATH,
				"net.connman.vpn.Manager", "GetConnections",
				vpnconnections_list, NULL,
				DBUS_TYPE_INVALID);

	if (check_dbus_name(vpnconnection_name) == false)
		return -EINVAL;

	path = g_strdup_printf("/net/connman/vpn/connection/%s",
			vpnconnection_name);
	return __connmanctl_dbus_method_call(connection, VPN_SERVICE, path,
			"net.connman.vpn.Connection", "GetProperties",
			vpnconnections_properties, path, DBUS_TYPE_INVALID);

}

static int cmd_vpnagent(char *args[], int num, struct connman_option *options)
{
	if (num > 2)
		return -E2BIG;

	if (num < 2)
		return -EINVAL;

	switch(parse_boolean(args[1])) {
	case 0:
		__connmanctl_vpn_agent_unregister(connection);
		break;

	case 1:
		if (__connmanctl_vpn_agent_register(connection) ==
				-EINPROGRESS)
			return -EINPROGRESS;

		break;

	default:
		return -EINVAL;
		break;
	}

	return 0;
}

static int cmd_exit(char *args[], int num, struct connman_option *options)
{
	return 1;
}

static struct connman_option service_options[] = {
	{"properties", 'p', "[<service>]      (obsolete)"},
	{ NULL, }
};

static struct connman_option config_options[] = {
	{"nameservers", 'n', "<dns1> [<dns2>] [<dns3>]"},
	{"timeservers", 't', "<ntp1> [<ntp2>] [...]"},
	{"domains", 'd', "<domain1> [<domain2>] [...]"},
	{"ipv6", 'v', "off|auto [enable|disable|prefered]|\n"
	              "\t\t\tmanual <address> <prefixlength> <gateway>"},
	{"proxy", 'x', "direct|auto <URL>|manual <URL1> [<URL2>] [...]\n"
	               "\t\t\t[exclude <exclude1> [<exclude2>] [...]]"},
	{"autoconnect", 'a', "yes|no"},
	{"ipv4", 'i', "off|dhcp|manual <address> <netmask> <gateway>"},
	{"remove", 'r', "                 Remove service"},
	{ NULL, }
};

static struct connman_option monitor_options[] = {
	{"services", 's', "[off]            Monitor only services"},
	{"tech", 'c', "[off]            Monitor only technologies"},
	{"manager", 'm', "[off]            Monitor only manager interface"},
	{"vpnmanager", 'M', "[off]            Monitor only VPN manager "
	 "interface"},
	{"vpnconnection", 'C', "[off]            Monitor only VPN "
	 "connections" },
	{ NULL, }
};

static const struct {
        const char *cmd;
	const char *argument;
        struct connman_option *options;
        int (*func) (char *args[], int num, struct connman_option *options);
        const char *desc;
} cmd_table[] = {
	{ "state",        NULL,           NULL,            cmd_state,
	  "Shows if the system is online or offline" },
	{ "technologies", NULL,           NULL,            cmd_technologies,
	  "Display technologies" },
	{ "enable",       "<technology>|offline", NULL,    cmd_enable,
	  "Enables given technology or offline mode" },
	{ "disable",      "<technology>|offline", NULL,    cmd_disable,
	  "Disables given technology or offline mode"},
	{ "tether", "<technology> on|off\n"
	            "            wifi [on|off] <ssid> <passphrase> ",
	                                  NULL,            cmd_tether,
	  "Enable, disable tethering, set SSID and passphrase for wifi" },
	{ "services",     "[<service>]",  service_options, cmd_services,
	  "Display services" },
	{ "scan",         "<technology>", NULL,            cmd_scan,
	  "Scans for new services for given technology" },
	{ "connect",      "<service>",    NULL,            cmd_connect,
	  "Connect a given service" },
	{ "disconnect",   "<service>",    NULL,            cmd_disconnect,
	  "Disconnect a given service" },
	{ "config",       "<service>",    config_options,  cmd_config,
	  "Set service configuration options" },
	{ "monitor",      "[off]",        monitor_options, cmd_monitor,
	  "Monitor signals from interfaces" },
	{ "agent", "on|off",              NULL,            cmd_agent,
	  "Agent mode" },
	{"vpnconnections", "[<connection>]", NULL,         cmd_vpnconnections,
	 "Display VPN connections" },
	{ "vpnagent",     "on|off",     NULL,            cmd_vpnagent,
	  "VPN Agent mode" },
	{ "help",         NULL,           NULL,            cmd_help,
	  "Show help" },
	{ "exit",         NULL,           NULL,            cmd_exit,
	  "Exit" },
	{ "quit",         NULL,           NULL,            cmd_exit,
	  "Quit" },
	{  NULL, },
};

static int cmd_help(char *args[], int num, struct connman_option *options)
{
	bool interactive = __connmanctl_is_interactive();
	int i, j;

	if (interactive == false)
		fprintf(stdout, "Usage: connmanctl [[command] [args]]\n");

	for (i = 0; cmd_table[i].cmd != NULL; i++) {
		const char *cmd = cmd_table[i].cmd;
		const char *argument = cmd_table[i].argument;
		const char *desc = cmd_table[i].desc;

		printf("%-16s%-22s%s\n", cmd != NULL? cmd: "",
				argument != NULL? argument: "",
				desc != NULL? desc: "");

		if (cmd_table[i].options != NULL) {
			for (j = 0; cmd_table[i].options[j].name != NULL;
			     j++) {
				const char *options_desc =
					cmd_table[i].options[j].desc != NULL ?
					cmd_table[i].options[j].desc: "";

				printf("   --%-16s%s\n",
						cmd_table[i].options[j].name,
						options_desc);
			}
		}
	}

	if (interactive == false)
		fprintf(stdout, "\nNote: arguments and output are considered "
				"EXPERIMENTAL for now.\n");

	return 0;
}

int __connmanctl_commands(DBusConnection *dbus_conn, char *argv[], int argc)
{
	int i, result;

	connection = dbus_conn;

	for (i = 0; cmd_table[i].cmd != NULL; i++) {
		if (g_strcmp0(cmd_table[i].cmd, argv[0]) == 0 &&
				cmd_table[i].func != NULL) {
			result = cmd_table[i].func(argv, argc,
					cmd_table[i].options);
			if (result < 0 && result != -EINPROGRESS)
				fprintf(stderr, "Error '%s': %s\n", argv[0],
						strerror(-result));
			return result;
		}
	}

	fprintf(stderr, "Error '%s': Unknown command\n", argv[0]);
	return -EINVAL;
}

char *__connmanctl_lookup_command(const char *text, int state)
{
	static int i = 0;
	static int len = 0;

	if (state == 0) {
		i = 0;
		len = strlen(text);
	}

	while (cmd_table[i].cmd != NULL) {
		const char *command = cmd_table[i].cmd;

		i++;

		if (strncmp(text, command, len) == 0)
			return strdup(command);
	}

	return NULL;
}
