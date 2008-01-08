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

int __connman_iface_load(struct connman_iface *iface)
{
	GKeyFile *keyfile;
	gchar *pathname, *str;

	DBG("iface %p", iface);

	if (iface->identifier == NULL)
		return -EIO;

	pathname = g_strdup_printf("%s/interfaces.conf", STORAGEDIR);
	if (pathname == NULL)
		return -ENOMEM;

	keyfile = g_key_file_new();

	if (g_key_file_load_from_file(keyfile, pathname, 0, NULL) == FALSE)
		goto done;

	if (g_key_file_has_group(keyfile, iface->identifier) == FALSE)
		goto done;

	str = g_key_file_get_string(keyfile, iface->identifier,
							"Policy", NULL);
	if (str != NULL) {
		iface->policy = __connman_iface_string2policy(str);
		g_free(str);
	}

	str = g_key_file_get_string(keyfile, iface->identifier,
							"IPv4.Method", NULL);
	if (str != NULL) {
		iface->ipv4.method = __connman_ipv4_string2method(str);
		g_free(str);
	}

	str = g_key_file_get_string(keyfile, iface->identifier,
							"IPv4.Address", NULL);
	if (str != NULL) {
		iface->ipv4.address.s_addr = inet_addr(str);
		g_free(str);
	}

	str = g_key_file_get_string(keyfile, iface->identifier,
							"IPv4.Netmask", NULL);
	if (str != NULL) {
		iface->ipv4.netmask.s_addr = inet_addr(str);
		g_free(str);
	}

	str = g_key_file_get_string(keyfile, iface->identifier,
							"IPv4.Gateway", NULL);
	if (str != NULL) {
		iface->ipv4.gateway.s_addr = inet_addr(str);
		g_free(str);
	}

done:
	g_key_file_free(keyfile);

	g_free(pathname);

	return 0;
}

static void do_update(GKeyFile *keyfile, struct connman_iface *iface)
{
	const char *str;
	gchar *comment;

	DBG("iface %p", iface);

	comment = g_key_file_get_comment(keyfile,
					iface->identifier, NULL, NULL);
	if (comment == NULL || *comment == '\0') {
		if (iface->device.product != NULL)
			g_key_file_set_comment(keyfile, iface->identifier,
					NULL, iface->device.product, NULL);
	}
	g_free(comment);

	str = __connman_iface_policy2string(iface->policy);
	g_key_file_set_string(keyfile, iface->identifier, "Policy", str);

	if (iface->ipv4.method != CONNMAN_IPV4_METHOD_UNKNOWN) {
		str = __connman_ipv4_method2string(iface->ipv4.method);
		g_key_file_set_string(keyfile, iface->identifier,
							"IPv4.Method", str);
	} else
		g_key_file_remove_key(keyfile, iface->identifier,
							"IPv4.Method", NULL);

	if (iface->ipv4.address.s_addr != INADDR_ANY) {
		str = inet_ntoa(iface->ipv4.address);
		g_key_file_set_string(keyfile, iface->identifier,
							"IPv4.Address", str);
	} else
		g_key_file_remove_key(keyfile, iface->identifier,
							"IPv4.Address", NULL);

	if (iface->ipv4.netmask.s_addr != INADDR_ANY) {
		str = inet_ntoa(iface->ipv4.netmask);
		g_key_file_set_string(keyfile, iface->identifier,
							"IPv4.Netmask", str);
	} else
		g_key_file_remove_key(keyfile, iface->identifier,
							"IPv4.Netmask", NULL);

	if (iface->ipv4.gateway.s_addr != INADDR_ANY) {
		str = inet_ntoa(iface->ipv4.gateway);
		g_key_file_set_string(keyfile, iface->identifier,
							"IPv4.Gateway", str);
	} else
		g_key_file_remove_key(keyfile, iface->identifier,
							"IPv4.Gateway", NULL);
}

int __connman_iface_store(struct connman_iface *iface)
{
	GKeyFile *keyfile;
	gchar *pathname, *data = NULL;
	gsize length;

	DBG("iface %p", iface);

	if (iface->identifier == NULL)
		return -EIO;

	pathname = g_strdup_printf("%s/interfaces.conf", STORAGEDIR);
	if (pathname == NULL)
		return -ENOMEM;

	keyfile = g_key_file_new();

	if (g_file_get_contents(pathname, &data, &length, NULL) == FALSE)
		goto done;

	if (length > 0) {
		if (g_key_file_load_from_data(keyfile, data, length,
				G_KEY_FILE_KEEP_COMMENTS, NULL) == FALSE)
			goto done;
	}

	g_free(data);

	do_update(keyfile, iface);

	data = g_key_file_to_data(keyfile, &length, NULL);

	g_file_set_contents(pathname, data, length, NULL);

done:
	g_free(data);

	g_key_file_free(keyfile);

	g_free(pathname);

	return 0;
}
