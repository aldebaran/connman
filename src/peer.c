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

static DBusMessage *get_peer_properties(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct connman_peer *peer = data;
	DBusMessageIter dict;
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &dict);
	append_properties(&dict, peer);

	return reply;
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

struct _peers_notify {
	int id;
	GHashTable *add;
	GHashTable *remove;
} *peers_notify;

static void append_existing_and_new_peers(gpointer key,
					gpointer value, gpointer user_data)
{
	struct connman_peer *peer = value;
	DBusMessageIter *iter = user_data;
	DBusMessageIter entry;

	if (g_hash_table_lookup(peers_notify->add, peer->path)) {
		DBG("new %s", peer->path);

		append_peer_struct(key, value, user_data);
		g_hash_table_remove(peers_notify->add, peer->path);
	} else {
		DBG("existing %s", peer->path);

		dbus_message_iter_open_container(iter, DBUS_TYPE_STRUCT,
								NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_OBJECT_PATH,
								&peer->path);
		dbus_message_iter_close_container(iter, &entry);
	}
}

static void peer_append_all(DBusMessageIter *iter, void *user_data)
{
	g_hash_table_foreach(peers_table, append_existing_and_new_peers, iter);
}

static void append_removed(gpointer key, gpointer value, gpointer user_data)
{
	DBusMessageIter *iter = user_data;
	char *objpath = key;

	DBG("removed %s", objpath);
	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &objpath);
}

static void peer_append_removed(DBusMessageIter *iter, void *user_data)
{
	g_hash_table_foreach(peers_notify->remove, append_removed, iter);
}

static gboolean peer_send_changed(gpointer data)
{
	DBusMessage *signal;

	DBG("");

	peers_notify->id = 0;

	signal = dbus_message_new_signal(CONNMAN_MANAGER_PATH,
				CONNMAN_MANAGER_INTERFACE, "PeersChanged");
	if (!signal)
		return FALSE;

	__connman_dbus_append_objpath_dict_array(signal,
						peer_append_all, NULL);
	__connman_dbus_append_objpath_array(signal,
						peer_append_removed, NULL);

	dbus_connection_send(connection, signal, NULL);
	dbus_message_unref(signal);

	g_hash_table_remove_all(peers_notify->remove);
	g_hash_table_remove_all(peers_notify->add);

	return FALSE;
}

static void peer_schedule_changed(void)
{
	if (peers_notify->id != 0)
		return;

	peers_notify->id = g_timeout_add(100, peer_send_changed, NULL);
}

static void peer_added(struct connman_peer *peer)
{
	DBG("peer %p", peer);

	g_hash_table_remove(peers_notify->remove, peer->path);
	g_hash_table_replace(peers_notify->add, peer->path, peer);

	peer_schedule_changed();
}

static void peer_removed(struct connman_peer *peer)
{
	DBG("peer %p", peer);

	g_hash_table_remove(peers_notify->add, peer->path);
	g_hash_table_replace(peers_notify->remove, g_strdup(peer->path), NULL);

	peer_schedule_changed();
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
		peer_removed(peer);
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
	{ GDBUS_METHOD("GetProperties",
			NULL, GDBUS_ARGS({ "properties", "a{sv}" }),
			get_peer_properties) },
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
	peer_added(peer);

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

	peers_notify = g_new0(struct _peers_notify, 1);
	peers_notify->add = g_hash_table_new(g_str_hash, g_str_equal);
	peers_notify->remove = g_hash_table_new_full(g_str_hash, g_str_equal,
								g_free, NULL);
	return 0;
}

void __connman_peer_cleanup(void)
{
	DBG("");

	g_hash_table_destroy(peers_table);
	dbus_connection_unref(connection);
}
