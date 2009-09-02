/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2009  Intel Corporation. All rights reserved.
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

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/dbus.h>
#include <connman/log.h>

#define OFONO_SERVICE			"org.ofono"

static DBusConnection *connection;

static GHashTable *ofono_modems = NULL;

static void unregister_modem(gpointer data)
{
	DBG("");
}

static void ofono_connect(DBusConnection *connection, void *user_data)
{
	DBG("connection %p", connection);

	ofono_modems = g_hash_table_new_full(g_str_hash, g_str_equal,
						g_free, unregister_modem);
}

static void ofono_disconnect(DBusConnection *connection, void *user_data)
{
	DBG("connection %p", connection);

	if (ofono_modems == NULL)
		return;

	g_hash_table_destroy(ofono_modems);
	ofono_modems = NULL;
}

static guint watch;

static int ofono_init(void)
{
	int err;

	connection = connman_dbus_get_connection();
	if (connection == NULL)
		return -EIO;

	watch = g_dbus_add_service_watch(connection, OFONO_SERVICE,
			ofono_connect, ofono_disconnect, NULL, NULL);
	if (watch == 0) {
		err = -EIO;
		goto unref;
	}

	return 0;

unref:
	dbus_connection_unref(connection);

	return err;
}

static void ofono_exit(void)
{
	g_dbus_remove_watch(connection, watch);

	ofono_disconnect(connection, NULL);

	dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE(ofono, "oFono telephony plugin", VERSION,
		CONNMAN_PLUGIN_PRIORITY_DEFAULT, ofono_init, ofono_exit)
