/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2014  Intel Corporation. All rights reserved.
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
#include <gdbus.h>

#include "connman.h"

static DBusConnection *connection = NULL;

static GHashTable *peers_table = NULL;

struct connman_peer {
	char *identifier;
	char *name;
	char *path;
};

static void peer_free(gpointer data)
{
	struct connman_peer *peer = data;
	connman_peer_destroy(peer);
}

static void append_properties(DBusMessageIter *iter, struct connman_peer *peer)
{
	const char *state = "disconnected";
	DBusMessageIter dict;

	connman_dbus_dict_open(iter, &dict);

	connman_dbus_dict_append_basic(&dict, "State",
					DBUS_TYPE_STRING, &state);
	connman_dbus_dict_append_basic(&dict, "Name",
					DBUS_TYPE_STRING, &peer->name);
	connman_dbus_dict_append_dict(&dict, "IPv4", NULL, NULL);

	connman_dbus_dict_close(iter, &dict);
}

static void append_peer_struct(gpointer key, gpointer value,
						gpointer user_data)
{
	DBusMessageIter *array = user_data;
	struct connman_peer *peer = value;
	DBusMessageIter entry;

	dbus_message_iter_open_container(array, DBUS_TYPE_STRUCT,
							NULL, &entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_OBJECT_PATH,
							&peer->path);
	append_properties(&entry, peer);
	dbus_message_iter_close_container(array, &entry);
}

struct connman_peer *connman_peer_create(const char *identifier)
{
	struct connman_peer *peer;

	peer = g_malloc0(sizeof(struct connman_peer));
	peer->identifier = g_strdup_printf("peer_%s", identifier);

	return peer;
}

void connman_peer_destroy(struct connman_peer *peer)
{
	if (!peer)
		return;

	if (peer->path) {
		g_dbus_unregister_interface(connection, peer->path,
						CONNMAN_PEER_INTERFACE);
		g_free(peer->path);
	}

	g_free(peer->identifier);
	g_free(peer->name);

	g_free(peer);
}

void connman_peer_set_name(struct connman_peer *peer, const char *name)
{
	g_free(peer->name);
	peer->name = g_strdup(name);
}

static const GDBusMethodTable peer_methods[] = {
	{ GDBUS_ASYNC_METHOD("Connect", NULL, NULL, NULL) },
	{ GDBUS_METHOD("Disconnect", NULL, NULL, NULL) },
	{ },
};

static const GDBusSignalTable peer_signals[] = {
	{ GDBUS_SIGNAL("PropertyChanged",
			GDBUS_ARGS({ "name", "s" }, { "value", "v" })) },
	{ },
};

int connman_peer_register(struct connman_peer *peer)
{
	DBG("peer %p", peer);

	if (peer->path)
		return -EALREADY;

	peer->path = g_strdup_printf("%s/peer/%s", CONNMAN_PATH,
						peer->identifier);
	DBG("path %s", peer->path);

	g_hash_table_insert(peers_table, peer->identifier, peer);

	g_dbus_register_interface(connection, peer->path,
					CONNMAN_PEER_INTERFACE,
					peer_methods, peer_signals,
					NULL, peer, NULL);
	return 0;
}

void connman_peer_unregister(struct connman_peer *peer)
{
	DBG("peer %p", peer);

	if (peer->path)
		g_hash_table_remove(peers_table, peer->identifier);
	else
		connman_peer_destroy(peer);
}

struct connman_peer *connman_peer_get(const char *identifier)
{
	char *ident = g_strdup_printf("peer_%s", identifier);
	struct connman_peer *peer;

	peer = g_hash_table_lookup(peers_table, ident);
	g_free(ident);

	return peer;
}

void __connman_peer_list_struct(DBusMessageIter *array)
{
	g_hash_table_foreach(peers_table, append_peer_struct, array);
}

int __connman_peer_init(void)
{
	DBG("");

	connection = connman_dbus_get_connection();

	peers_table = g_hash_table_new_full(g_str_hash, g_str_equal,
							NULL, peer_free);
	return 0;
}

void __connman_peer_cleanup(void)
{
	DBG("");

	g_hash_table_destroy(peers_table);
	dbus_connection_unref(connection);
}
