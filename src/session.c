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

#include <string.h>

#include <gdbus.h>

#include "connman.h"

static DBusConnection *connection;
static GHashTable *session_hash;
static GHashTable *bearer_hash;

struct connman_bearer {
	gint refcount;
	char *name;
};

struct connman_session {
	gint refcount;
	char *owner;
	guint watch;
	struct connman_bearer *bearer;
	struct connman_service *service;
};

static enum connman_service_type bearer2service(const char *bearer)
{
	if (bearer == NULL)
		return CONNMAN_SERVICE_TYPE_UNKNOWN;

	DBG("%s", bearer);

	if (g_strcmp0(bearer, "ethernet") == 0)
		return CONNMAN_SERVICE_TYPE_ETHERNET;
	else if (g_strcmp0(bearer, "wifi") == 0)
		return CONNMAN_SERVICE_TYPE_WIFI;
	else if (g_strcmp0(bearer, "wimax") == 0)
		return CONNMAN_SERVICE_TYPE_WIMAX;
	else if (g_strcmp0(bearer, "bluetooth") == 0)
		return CONNMAN_SERVICE_TYPE_BLUETOOTH;
	else if (g_strcmp0(bearer, "3g") == 0)
		return CONNMAN_SERVICE_TYPE_CELLULAR;
	else
		return CONNMAN_SERVICE_TYPE_UNKNOWN;
}

static char *service2bearer(enum connman_service_type type)
{
	DBG("%d", type);

	switch (type) {
	case CONNMAN_SERVICE_TYPE_ETHERNET:
		return "ethernet";
	case CONNMAN_SERVICE_TYPE_WIFI:
		return "wifi";
	case CONNMAN_SERVICE_TYPE_WIMAX:
		return "wimax";
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
		return "bluetooth";
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		return "3g";
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_VPN:
	case CONNMAN_SERVICE_TYPE_GADGET:
		return NULL;
	}

	return NULL;
}

static void remove_bearer(gpointer user_data)
{
	struct connman_bearer *bearer = user_data;

	g_free(bearer->name);
	g_free(bearer);
}

static void remove_session(gpointer user_data)
{
	struct connman_session *session = user_data;

	session->bearer = NULL;
	if (session->service)
		connman_service_unref(session->service);
	g_free(session->owner);
	g_free(session);
}

static int session_disconnect(struct connman_session *session)
{
	struct connman_bearer *bearer = session->bearer;

	DBG("%s", session->owner);

	if (session == NULL)
		return -EINVAL;

	/*
	 * Once a bearer is no longer referenced we actually disconnect
	 * the corresponding service.
	 */
	if (bearer == NULL || g_atomic_int_dec_and_test(&bearer->refcount)) {
		struct connman_network *network;
		struct connman_device *device;

		/*
		 * We toggle the reconnect flag to false when releasing a
		 * session. This way a previously connected service will
		 * not autoconnect once we've completely release a session.
		 */
		network = __connman_service_get_network(session->service);
		if (network == NULL)
			return -EINVAL;

		device = connman_network_get_device(network);
		if (device == NULL)
			return -EINVAL;

		__connman_device_set_reconnect(device, FALSE);

		__connman_service_disconnect(session->service);
		connman_service_unref(session->service);

		g_hash_table_remove(bearer_hash, bearer);
	}

	if (session->watch > 0)
		g_dbus_remove_watch(connection, session->watch);

	g_hash_table_remove(session_hash, session);

	return 0;
}

static void owner_disconnect(DBusConnection *connection, void *user_data)
{
	struct connman_session *session;
	char *owner = user_data;

	DBG("%s died", owner);

	session = g_hash_table_lookup(session_hash, owner);
	if (session == NULL) {
		connman_error("No session");
		return;
	}

	session_disconnect(session);
}

int __connman_session_release(const char *owner)
{
	struct connman_session *session;

	DBG("owner %s", owner);

	session = g_hash_table_lookup(session_hash, owner);
	if (session == NULL)
		return -EINVAL;

	if (g_atomic_int_dec_and_test(&session->refcount))
		return session_disconnect(session);

	return 0;
}

struct connman_service *__connman_session_request(const char *bearer_name,
							const char *owner)
{
	struct connman_session *session;
	struct connman_bearer *bearer;
	enum connman_service_type service_type;
	const char *bearer_name_new;
	size_t bearer_name_len;

	if (bearer_name == NULL)
		return NULL;

	DBG("owner %s bearer %s", owner, bearer_name);

	bearer_name_len = strlen(bearer_name);

	session = g_hash_table_lookup(session_hash, owner);
	if (session) {
		/* we only support one bearer per process */
		if (bearer_name_len &&
			g_strcmp0(session->bearer->name, bearer_name))
				return NULL;

		g_atomic_int_inc(&session->refcount);

		return session->service;
	}

	session = g_try_new0(struct connman_session, 1);
	if (session == NULL)
		return NULL;

	session->refcount = 1;
	session->owner = g_strdup(owner);
	session->service = NULL;
	g_hash_table_replace(session_hash, session->owner, session);

	/* Find and connect service */
	service_type = bearer2service(bearer_name);

	session->service = __connman_service_connect_type(service_type);
	if (session->service == NULL)
		goto failed_connect;

	connman_service_ref(session->service);

	service_type = connman_service_get_type(session->service);

	/* We might get a different bearer from the one we requested */
	bearer_name_new = service2bearer(service_type);

	/* Refcount the exisiting bearer, or create one */
	bearer = g_hash_table_lookup(bearer_hash, bearer_name_new);
	if (bearer == NULL) {
		bearer = g_try_new0(struct connman_bearer, 1);
		if (bearer == NULL)
			goto failed_bearer;

		bearer->refcount = 0;
		bearer->name = g_strdup(bearer_name_new);
		g_hash_table_replace(bearer_hash, bearer->name, bearer);
	}

	g_atomic_int_inc(&bearer->refcount);
	session->bearer = bearer;

	session->watch = g_dbus_add_disconnect_watch(connection, session->owner,
					owner_disconnect, session->owner, NULL);
	return session->service;

failed_bearer:
	session_disconnect(session);

failed_connect:
	g_hash_table_remove(session_hash, session);

	return NULL;
}

int __connman_session_init(void)
{
	DBG("");

	connection = connman_dbus_get_connection();
	if (connection == NULL)
		return -1;

	session_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						NULL, remove_session);

	bearer_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						NULL, remove_bearer);

	return 0;
}

void __connman_session_cleanup(void)
{
	DBG("");

	if (connection == NULL)
		return;

	g_hash_table_destroy(bearer_hash);
	g_hash_table_destroy(session_hash);
	dbus_connection_unref(connection);
}
