/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2010  Intel Corporation. All rights reserved.
 *  Copyright (C) 2010 Nokia Corporation and/or its subsidiary(-ies).
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
#include <stdlib.h>

#include <gdbus.h>
#include <string.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/device.h>
#include <connman/network.h>
#include <connman/dbus.h>
#include <connman/log.h>

#define OFONO_SERVICE			"org.ofono"

#define OFONO_MANAGER_INTERFACE		OFONO_SERVICE ".Manager"
#define OFONO_MODEM_INTERFACE		OFONO_SERVICE ".Modem"
#define OFONO_SIM_INTERFACE		OFONO_SERVICE ".SimManager"
#define OFONO_NETREG_INTERFACE		OFONO_SERVICE ".NetworkRegistration"
#define OFONO_CM_INTERFACE		OFONO_SERVICE ".ConnectionManager"
#define OFONO_CONTEXT_INTERFACE		OFONO_SERVICE ".ConnectionContext"

#define MODEM_ADDED			"ModemAdded"
#define MODEM_REMOVED			"ModemRemoved"
#define PROPERTY_CHANGED		"PropertyChanged"
#define CONTEXT_ADDED			"ContextAdded"
#define CONTEXT_REMOVED			"ContextRemoved"

static DBusConnection *connection;

static gboolean context_changed(DBusConnection *connection,
				DBusMessage *message,
				void *user_data)
{
	return TRUE;
}

static gboolean cm_context_added(DBusConnection *connection,
					DBusMessage *message,
					void *user_data)
{
	return TRUE;
}

static gboolean cm_context_removed(DBusConnection *connection,
					DBusMessage *message,
					void *user_data)
{
	return TRUE;
}

static gboolean netreg_changed(DBusConnection *connection, DBusMessage *message,
				void *user_data)
{
	return TRUE;
}

static gboolean cm_changed(DBusConnection *connection, DBusMessage *message,
				void *user_data)
{
	return TRUE;
}

static gboolean sim_changed(DBusConnection *connection, DBusMessage *message,
				void *user_data)
{
	return TRUE;
}

static gboolean modem_changed(DBusConnection *connection, DBusMessage *message,
				void *user_data)
{
	return TRUE;
}

static gboolean modem_added(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	return TRUE;
}

static gboolean modem_removed(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	return TRUE;
}

static void ofono_connect(DBusConnection *conn, void *user_data)
{
}

static void ofono_disconnect(DBusConnection *conn, void *user_data)
{
}

static int network_probe(struct connman_network *network)
{
	DBG("network %p", network);

	return 0;
}

static void network_remove(struct connman_network *network)
{
	DBG("network %p", network);
}

static int network_connect(struct connman_network *network)
{
	DBG("network %p", network);

	return 0;
}

static int network_disconnect(struct connman_network *network)
{
	DBG("network %p", network);

	return 0;
}

static struct connman_network_driver network_driver = {
	.name		= "network",
	.type		= CONNMAN_NETWORK_TYPE_CELLULAR,
	.probe		= network_probe,
	.remove		= network_remove,
	.connect	= network_connect,
	.disconnect	= network_disconnect,
};

static int modem_probe(struct connman_device *device)
{
	DBG("device %p", device);

	return 0;
}

static void modem_remove(struct connman_device *device)
{
	DBG("device %p", device);
}

static int modem_enable(struct connman_device *device)
{
	DBG("device %p", device);

	return 0;
}

static int modem_disable(struct connman_device *device)
{
	DBG("device %p", device);

	return 0;
}

static struct connman_device_driver modem_driver = {
	.name		= "modem",
	.type		= CONNMAN_DEVICE_TYPE_CELLULAR,
	.probe		= modem_probe,
	.remove		= modem_remove,
	.enable		= modem_enable,
	.disable	= modem_disable,
};

static guint watch;
static guint modem_added_watch;
static guint modem_removed_watch;
static guint modem_watch;
static guint cm_watch;
static guint sim_watch;
static guint context_added_watch;
static guint context_removed_watch;
static guint netreg_watch;
static guint context_watch;

static int ofono_init(void)
{
	int err;

	DBG("");

	connection = connman_dbus_get_connection();
	if (connection == NULL)
		return -EIO;

	watch = g_dbus_add_service_watch(connection,
					OFONO_SERVICE, ofono_connect,
					ofono_disconnect, NULL, NULL);

	modem_added_watch = g_dbus_add_signal_watch(connection, NULL, NULL,
						OFONO_MANAGER_INTERFACE,
						MODEM_ADDED,
						modem_added,
						NULL, NULL);

	modem_removed_watch = g_dbus_add_signal_watch(connection, NULL, NULL,
						OFONO_MANAGER_INTERFACE,
						MODEM_REMOVED,
						modem_removed,
						NULL, NULL);

	modem_watch = g_dbus_add_signal_watch(connection, NULL, NULL,
						OFONO_MODEM_INTERFACE,
						PROPERTY_CHANGED,
						modem_changed,
						NULL, NULL);

	cm_watch = g_dbus_add_signal_watch(connection, NULL, NULL,
						OFONO_CM_INTERFACE,
						PROPERTY_CHANGED,
						cm_changed,
						NULL, NULL);

	sim_watch = g_dbus_add_signal_watch(connection, NULL, NULL,
						OFONO_SIM_INTERFACE,
						PROPERTY_CHANGED,
						sim_changed,
						NULL, NULL);

	context_added_watch = g_dbus_add_signal_watch(connection, NULL, NULL,
						OFONO_CM_INTERFACE,
						CONTEXT_ADDED,
						cm_context_added,
						NULL, NULL);

	context_removed_watch = g_dbus_add_signal_watch(connection, NULL, NULL,
						OFONO_CM_INTERFACE,
						CONTEXT_REMOVED,
						cm_context_removed,
						NULL, NULL);

	context_watch = g_dbus_add_signal_watch(connection, NULL, NULL,
						OFONO_CONTEXT_INTERFACE,
						PROPERTY_CHANGED,
						context_changed,
						NULL, NULL);

	netreg_watch = g_dbus_add_signal_watch(connection, NULL, NULL,
						OFONO_NETREG_INTERFACE,
						PROPERTY_CHANGED,
						netreg_changed,
						NULL, NULL);


	if (watch == 0 || modem_added_watch == 0 || modem_removed_watch == 0 ||
			modem_watch == 0 || cm_watch == 0 || sim_watch == 0 ||
			context_added_watch == 0 ||
			context_removed_watch == 0 ||
			context_watch == 0 || netreg_watch == 0) {
		err = -EIO;
		goto remove;
	}

	err = connman_network_driver_register(&network_driver);
	if (err < 0)
		goto remove;

	err = connman_device_driver_register(&modem_driver);
	if (err < 0) {
		connman_network_driver_unregister(&network_driver);
		goto remove;
	}

	return 0;

remove:
	g_dbus_remove_watch(connection, netreg_watch);
	g_dbus_remove_watch(connection, context_watch);
	g_dbus_remove_watch(connection, context_removed_watch);
	g_dbus_remove_watch(connection, context_added_watch);
	g_dbus_remove_watch(connection, sim_watch);
	g_dbus_remove_watch(connection, cm_watch);
	g_dbus_remove_watch(connection, modem_watch);
	g_dbus_remove_watch(connection, modem_removed_watch);
	g_dbus_remove_watch(connection, modem_added_watch);
	g_dbus_remove_watch(connection, watch);
	dbus_connection_unref(connection);

	return err;
}

static void ofono_exit(void)
{
	DBG("");

	connman_device_driver_unregister(&modem_driver);
	connman_network_driver_unregister(&network_driver);

	g_dbus_remove_watch(connection, netreg_watch);
	g_dbus_remove_watch(connection, context_watch);
	g_dbus_remove_watch(connection, context_removed_watch);
	g_dbus_remove_watch(connection, context_added_watch);
	g_dbus_remove_watch(connection, sim_watch);
	g_dbus_remove_watch(connection, cm_watch);
	g_dbus_remove_watch(connection, modem_watch);
	g_dbus_remove_watch(connection, modem_added_watch);
	g_dbus_remove_watch(connection, modem_removed_watch);
	g_dbus_remove_watch(connection, watch);

	dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE(ofono, "oFono telephony plugin", VERSION,
		CONNMAN_PLUGIN_PRIORITY_DEFAULT, ofono_init, ofono_exit)
