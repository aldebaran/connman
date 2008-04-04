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

#include <errno.h>
#include <arpa/inet.h>

#include <glib.h>

#include "connman.h"

#define GROUP_CONFIG  "Config"

char *__connman_iface_find_passphrase(struct connman_iface *iface,
							const char *network)
{
	GKeyFile *keyfile;
	gchar *pathname, *result = NULL;
	gchar **list;
	gsize list_len;
	int i;

	if (iface->identifier == NULL)
		return NULL;

	pathname = g_strdup_printf("%s/%s.conf", STORAGEDIR,
							iface->identifier);
	if (pathname == NULL)
		return NULL;

	keyfile = g_key_file_new();

	g_key_file_set_list_separator(keyfile, ',');

	if (g_key_file_load_from_file(keyfile, pathname, 0, NULL) == FALSE)
		goto done;

	if (g_key_file_has_group(keyfile, GROUP_CONFIG) == FALSE)
		goto done;

	list = g_key_file_get_string_list(keyfile, GROUP_CONFIG,
					"KnownNetworks", &list_len, NULL);
	for (i = 0; i < list_len; i++) {
		if (g_str_equal(list[i], network) == TRUE) {
			result = g_key_file_get_string(keyfile, network,
								"PSK", NULL);
			if (result == NULL)
				result = g_strdup("");
			break;
		}
	}

	g_strfreev(list);

done:
	g_key_file_free(keyfile);

	g_free(pathname);

	return result;
}

int __connman_iface_load(struct connman_iface *iface)
{
	GKeyFile *keyfile;
	gchar *pathname, *str;
	gchar **list;
	gsize list_len;

	DBG("iface %p", iface);

	if (iface->identifier == NULL)
		return -EIO;

	pathname = g_strdup_printf("%s/%s.conf", STORAGEDIR,
							iface->identifier);
	if (pathname == NULL)
		return -ENOMEM;

	keyfile = g_key_file_new();

	g_key_file_set_list_separator(keyfile, ',');

	if (g_key_file_load_from_file(keyfile, pathname, 0, NULL) == FALSE)
		goto done;

	if (g_key_file_has_group(keyfile, GROUP_CONFIG) == FALSE)
		goto done;

	str = g_key_file_get_string(keyfile, GROUP_CONFIG, "Policy", NULL);
	if (str != NULL) {
		iface->policy = __connman_iface_string2policy(str);
		g_free(str);
	}

	list = g_key_file_get_string_list(keyfile, GROUP_CONFIG,
					"KnownNetworks", &list_len, NULL);

	g_strfreev(list);

	str = g_key_file_get_string(keyfile, GROUP_CONFIG,
						"LastNetwork", NULL);
	if (str != NULL) {
		g_free(iface->network.identifier);
		iface->network.identifier = str;

		str = g_key_file_get_string(keyfile,
				iface->network.identifier, "PSK", NULL);
		if (str != NULL) {
			g_free(iface->network.passphrase);
			iface->network.passphrase = str;
		}
	}

done:
	g_key_file_free(keyfile);

	g_free(pathname);

	return 0;
}

static void do_update(GKeyFile *keyfile, struct connman_iface *iface)
{
	const char *str;

	DBG("iface %p", iface);

	str = __connman_iface_policy2string(iface->policy);
	g_key_file_set_string(keyfile, GROUP_CONFIG, "Policy", str);

	if (iface->network.identifier != NULL) {
		g_key_file_set_string(keyfile, GROUP_CONFIG,
				"LastNetwork", iface->network.identifier);
	} else
		g_key_file_remove_key(keyfile, GROUP_CONFIG,
						"LastNetwork", NULL);

	if (iface->network.identifier != NULL)
		g_key_file_set_string(keyfile, iface->network.identifier,
					"PSK", iface->network.passphrase);
}

int __connman_iface_store(struct connman_iface *iface)
{
	GKeyFile *keyfile;
	gchar *pathname, *data = NULL;
	gsize length;

	DBG("iface %p", iface);

	if (iface->identifier == NULL)
		return -EIO;

	pathname = g_strdup_printf("%s/%s.conf", STORAGEDIR,
							iface->identifier);
	if (pathname == NULL)
		return -ENOMEM;

	keyfile = g_key_file_new();

	if (g_file_get_contents(pathname, &data, &length, NULL) == FALSE)
		goto update;

	if (length > 0) {
		if (g_key_file_load_from_data(keyfile, data, length,
				G_KEY_FILE_KEEP_COMMENTS, NULL) == FALSE)
			goto done;
	}

	g_free(data);

update:
	do_update(keyfile, iface);

	data = g_key_file_to_data(keyfile, &length, NULL);

	g_file_set_contents(pathname, data, length, NULL);

done:
	g_free(data);

	g_key_file_free(keyfile);

	g_free(pathname);

	return 0;
}

int __connman_iface_store_current_network(struct connman_iface *iface)
{
	GKeyFile *keyfile;
	gchar *pathname, *data = NULL;
	gsize length;

	DBG("iface %p", iface);

	if (iface->identifier == NULL)
		return -EIO;

	pathname = g_strdup_printf("%s/%s.conf", STORAGEDIR,
							iface->identifier);
	if (pathname == NULL)
		return -ENOMEM;

	keyfile = g_key_file_new();

	if (g_file_get_contents(pathname, &data, &length, NULL) == FALSE)
		goto update;

	if (length > 0) {
		if (g_key_file_load_from_data(keyfile, data, length,
				G_KEY_FILE_KEEP_COMMENTS, NULL) == FALSE)
			goto done;
	}

	g_free(data);

update:
	g_key_file_set_string(keyfile, GROUP_CONFIG,
				"LastNetwork", iface->network.identifier);

	data = g_key_file_to_data(keyfile, &length, NULL);

	g_file_set_contents(pathname, data, length, NULL);

done:
	g_free(data);

	g_key_file_free(keyfile);

	g_free(pathname);

	return 0;
}

int __connman_iface_load_networks(struct connman_iface *iface)
{
	GKeyFile *keyfile;
	gchar *pathname;
	gchar **list;
	gsize list_len;
	int i;

	if (iface->identifier == NULL)
		return -1;

	pathname = g_strdup_printf("%s/%s.conf", STORAGEDIR,
							iface->identifier);
	if (pathname == NULL)
		return -1;

	keyfile = g_key_file_new();

	g_key_file_set_list_separator(keyfile, ',');

	if (g_key_file_load_from_file(keyfile, pathname, 0, NULL) == FALSE)
		goto done;

	if (g_key_file_has_group(keyfile, GROUP_CONFIG) == FALSE)
		goto done;

	list = g_key_file_get_string_list(keyfile, GROUP_CONFIG,
					"KnownNetworks", &list_len, NULL);
	for (i = 0; i < list_len; i++) {
		DBG("Known network %s", list[i]);
	}

	g_strfreev(list);

done:
	g_key_file_free(keyfile);

	g_free(pathname);

	return 0;
}
