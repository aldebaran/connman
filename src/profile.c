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

#include <glib.h>
#include <gdbus.h>

#include "connman.h"

#define PROFILE_DEFAULT_IDENT  "default"

static DBusConnection *connection = NULL;

const char *__connman_profile_active_ident(void)
{
	DBG("");

	return PROFILE_DEFAULT_IDENT;
}

const char *__connman_profile_active_path(void)
{
	DBG("");

	return "/profile/" PROFILE_DEFAULT_IDENT;
}

static void append_services(DBusMessageIter *entry)
{
	DBusMessageIter value, iter;
	const char *key = "Services";

	dbus_message_iter_append_basic(entry, DBUS_TYPE_STRING, &key);

	dbus_message_iter_open_container(entry, DBUS_TYPE_VARIANT,
		DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_OBJECT_PATH_AS_STRING,
								&value);

	dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY,
				DBUS_TYPE_OBJECT_PATH_AS_STRING, &iter);
	__connman_service_list(&iter);
	dbus_message_iter_close_container(&value, &iter);

	dbus_message_iter_close_container(entry, &value);
}

static guint changed_timeout = 0;

static gboolean services_changed(gpointer user_data)
{
	const char *path = __connman_profile_active_path();
	DBusMessage *signal;
	DBusMessageIter entry;

	changed_timeout = 0;

	signal = dbus_message_new_signal(path,
				CONNMAN_PROFILE_INTERFACE, "PropertyChanged");
	if (signal == NULL)
		return FALSE;

	dbus_message_iter_init_append(signal, &entry);
	append_services(&entry);
	g_dbus_send_message(connection, signal);

	signal = dbus_message_new_signal(CONNMAN_MANAGER_PATH,
				CONNMAN_MANAGER_INTERFACE, "PropertyChanged");
	if (signal == NULL)
		return FALSE;

	dbus_message_iter_init_append(signal, &entry);
	append_services(&entry);
	g_dbus_send_message(connection, signal);

	return FALSE;
}

void __connman_profile_changed(gboolean delayed)
{
	DBG("");

	if (changed_timeout > 0) {
		g_source_remove(changed_timeout);
		changed_timeout = 0;
	}

	if (__connman_connection_update_gateway() == TRUE) {
		services_changed(NULL);
		return;
	}

	if (delayed == FALSE) {
		services_changed(NULL);
		return;
	}

	changed_timeout = g_timeout_add_seconds(2, services_changed, NULL);
}

int __connman_profile_add_device(struct connman_device *device)
{
	struct connman_service *service;

	DBG("device %p", device);

	service = __connman_service_create_from_device(device);
	if (service == NULL)
		return -EINVAL;

	return 0;
}

int __connman_profile_remove_device(struct connman_device *device)
{
	struct connman_service *service;

	DBG("device %p", device);

	service = __connman_service_lookup_from_device(device);
	if (service == NULL)
		return -EINVAL;

	__connman_service_put(service);

	return 0;
}

int __connman_profile_add_network(struct connman_network *network)
{
	struct connman_service *service;

	DBG("network %p", network);

	service = __connman_service_create_from_network(network);
	if (service == NULL)
		return -EINVAL;

	return 0;
}

int __connman_profile_remove_network(struct connman_network *network)
{
	struct connman_service *service;

	DBG("network %p", network);

	service = __connman_service_lookup_from_network(network);
	if (service == NULL)
		return -EINVAL;

	__connman_service_put(service);

	return 0;
}

void __connman_profile_list(DBusMessageIter *iter)
{
	const char *path = __connman_profile_active_path();

	DBG("");

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &path);
}

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *name = "Default";
	DBusMessage *reply;
	DBusMessageIter array, dict, entry;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &array);

	dbus_message_iter_open_container(&array, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	connman_dbus_dict_append_variant(&dict, "Name",
						DBUS_TYPE_STRING, &name);

	dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY,
								NULL, &entry);
	append_services(&entry);
	dbus_message_iter_close_container(&dict, &entry);

	dbus_message_iter_close_container(&array, &dict);

	return reply;
}

static GDBusMethodTable profile_methods[] = {
	{ "GetProperties", "", "a{sv}", get_properties },
	{ },
};

static GDBusSignalTable profile_signals[] = {
	{ "PropertyChanged", "sv" },
	{ },
};

int __connman_profile_init(DBusConnection *conn)
{
	const char *path = __connman_profile_active_path();

	DBG("conn %p", conn);

	connection = dbus_connection_ref(conn);
	if (connection == NULL)
		return -1;

	g_dbus_register_interface(connection, path,
					CONNMAN_PROFILE_INTERFACE,
					profile_methods, profile_signals,
							NULL, NULL, NULL);

	return 0;
}

void __connman_profile_cleanup(void)
{
	const char *path = __connman_profile_active_path();

	DBG("conn %p", connection);

	g_dbus_unregister_interface(connection, path,
						CONNMAN_PROFILE_INTERFACE);

	if (connection == NULL)
		return;

	dbus_connection_unref(connection);
}
