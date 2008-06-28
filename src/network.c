/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2008  Intel Corporation. All rights reserved.
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

#include <gdbus.h>

#include "connman.h"

static DBusConnection *connection = NULL;
static unsigned int index = 0;

static GSList *networks = NULL;

void __connman_iface_network_list(struct connman_iface *iface,
						DBusMessageIter *iter)
{
	GSList *list;

	DBG("");

	for (list = networks; list; list = list->next) {
		struct connman_network *network = list->data;

		if (network->iface != iface)
			continue;

		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_OBJECT_PATH, &network->path);
	}
}

struct connman_network *__connman_iface_find_network(struct connman_iface *iface,
								const char *path)
{
	GSList *list;

	DBG("");

	for (list = networks; list; list = list->next) {
		struct connman_network *network = list->data;

		if (network->iface == iface &&
				g_str_equal(network->path, path) == TRUE)
			return network;
	}

	return NULL;
}

int __connman_iface_remove_network(struct connman_iface *iface, const char *path)
{
	g_dbus_unregister_interface(connection, path,
					CONNMAN_NETWORK_INTERFACE);

	return 0;
}

static DBusMessage *get_identifier(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_network *network = data;
	DBusMessage *reply;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &network->identifier,
							DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *get_passphrase(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_network *network = data;
	DBusMessage *reply;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &network->passphrase,
							DBUS_TYPE_INVALID);

	return reply;
}

static GDBusMethodTable network_methods[] = {
	{ "GetIdentifier", "", "s", get_identifier },
	{ "GetPassphrase", "", "s", get_passphrase },
	{ },
};

static void network_free(void *data)
{
	struct connman_network *network = data;

	DBG("");

	networks = g_slist_remove(networks, network);

	g_free(network->path);
	g_free(network->identifier);
	g_free(network->passphrase);
	g_free(network);
}

const char *__connman_iface_add_network(struct connman_iface *iface,
				const char *identifier, const char *passphrase)
{
	struct connman_network *network;
	gchar *path;

	DBG("iface %p", iface);

	network = g_try_new0(struct connman_network, 1);
	if (network == NULL)
		return NULL;

	path = g_strdup_printf("%s/net_%d", iface->path, index++);
	if (path == NULL) {
		g_free(network);
		return NULL;
	}

	network->iface = iface;

	network->path = path;
	network->identifier = g_strdup(identifier);
	network->passphrase = g_strdup(passphrase ? passphrase : "");

	networks = g_slist_append(networks, network);

	g_dbus_register_interface(connection, path, CONNMAN_NETWORK_INTERFACE,
						network_methods, NULL, NULL,
							network, network_free);

	return path;
}

int __connman_network_init(DBusConnection *conn)
{
	DBG("conn %p", conn);

	connection = dbus_connection_ref(conn);
	if (connection == NULL)
		return -1;

	return 0;
}

void __connman_network_cleanup(void)
{
	DBG("conn %p", connection);

	dbus_connection_unref(connection);
}
