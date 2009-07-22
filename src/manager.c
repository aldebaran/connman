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

#include <gdbus.h>

#include "connman.h"

static connman_bool_t global_offlinemode = FALSE;

connman_bool_t __connman_manager_get_offlinemode(void)
{
	return global_offlinemode;
}

static void append_profiles(DBusMessageIter *dict)
{
	DBusMessageIter entry, value, iter;
	const char *key = "Profiles";

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
								NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
		DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_OBJECT_PATH_AS_STRING,
								&value);

	dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY,
				DBUS_TYPE_OBJECT_PATH_AS_STRING, &iter);
	__connman_profile_list(&iter);
	dbus_message_iter_close_container(&value, &iter);

	dbus_message_iter_close_container(&entry, &value);

	dbus_message_iter_close_container(dict, &entry);
}

static void append_services(DBusMessageIter *dict)
{
	DBusMessageIter entry, value, iter;
	const char *key = "Services";

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
								NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
		DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_OBJECT_PATH_AS_STRING,
								&value);

	dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY,
				DBUS_TYPE_OBJECT_PATH_AS_STRING, &iter);
	__connman_service_list(&iter);
	dbus_message_iter_close_container(&value, &iter);

	dbus_message_iter_close_container(&entry, &value);

	dbus_message_iter_close_container(dict, &entry);
}

static void append_devices(DBusMessageIter *dict)
{
	DBusMessageIter entry, value, iter;
	const char *key = "Devices";

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
								NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
		DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_OBJECT_PATH_AS_STRING,
								&value);

	dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY,
				DBUS_TYPE_OBJECT_PATH_AS_STRING, &iter);
	__connman_element_list(NULL, CONNMAN_ELEMENT_TYPE_DEVICE, &iter);
	dbus_message_iter_close_container(&value, &iter);

	dbus_message_iter_close_container(&entry, &value);

	dbus_message_iter_close_container(dict, &entry);
}

static void append_connections(DBusMessageIter *dict)
{
	DBusMessageIter entry, value, iter;
	const char *key = "Connections";

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
								NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
		DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_OBJECT_PATH_AS_STRING,
								&value);

	dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY,
				DBUS_TYPE_OBJECT_PATH_AS_STRING, &iter);
	__connman_element_list(NULL, CONNMAN_ELEMENT_TYPE_CONNECTION, &iter);
	dbus_message_iter_close_container(&value, &iter);

	dbus_message_iter_close_container(&entry, &value);

	dbus_message_iter_close_container(dict, &entry);
}

static void append_available_technologies(DBusMessageIter *dict)
{
	DBusMessageIter entry, value, iter;
	const char *key = "AvailableTechnologies";

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
								NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
			DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_STRING_AS_STRING,
								&value);

	dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY,
					DBUS_TYPE_STRING_AS_STRING, &iter);
	__connman_notifier_list_registered(&iter);
	dbus_message_iter_close_container(&value, &iter);

	dbus_message_iter_close_container(&entry, &value);

	dbus_message_iter_close_container(dict, &entry);
}

static void append_enabled_technologies(DBusMessageIter *dict)
{
	DBusMessageIter entry, value, iter;
	const char *key = "EnabledTechnologies";

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
								NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
			DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_STRING_AS_STRING,
								&value);

	dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY,
					DBUS_TYPE_STRING_AS_STRING, &iter);
	__connman_notifier_list_enabled(&iter);
	dbus_message_iter_close_container(&value, &iter);

	dbus_message_iter_close_container(&entry, &value);

	dbus_message_iter_close_container(dict, &entry);
}

static void append_connected_technologies(DBusMessageIter *dict)
{
	DBusMessageIter entry, value, iter;
	const char *key = "ConnectedTechnologies";

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
								NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
			DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_STRING_AS_STRING,
								&value);

	dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY,
					DBUS_TYPE_STRING_AS_STRING, &iter);
	__connman_notifier_list_connected(&iter);
	dbus_message_iter_close_container(&value, &iter);

	dbus_message_iter_close_container(&entry, &value);

	dbus_message_iter_close_container(dict, &entry);
}

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	DBusMessageIter array, dict;
	const char *str;

	DBG("conn %p", conn);

	if (__connman_security_check_privilege(msg,
					CONNMAN_SECURITY_PRIVILEGE_PUBLIC) < 0)
		return __connman_error_permission_denied(msg);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &array);

	dbus_message_iter_open_container(&array, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	str = __connman_profile_active_path();
	if (str != NULL)
		connman_dbus_dict_append_variant(&dict, "ActiveProfile",
						DBUS_TYPE_OBJECT_PATH, &str);

	append_profiles(&dict);
	append_services(&dict);

	append_devices(&dict);
	append_connections(&dict);

	if (__connman_element_count(NULL, CONNMAN_ELEMENT_TYPE_CONNECTION) > 0)
		str = "online";
	else
		str = "offline";

	connman_dbus_dict_append_variant(&dict, "State",
						DBUS_TYPE_STRING, &str);

	connman_dbus_dict_append_variant(&dict, "OfflineMode",
				DBUS_TYPE_BOOLEAN, &global_offlinemode);

	append_available_technologies(&dict);
	append_enabled_technologies(&dict);
	append_connected_technologies(&dict);

	str = __connman_service_default();
	if (str != NULL)
		connman_dbus_dict_append_variant(&dict, "DefaultTechnology",
						DBUS_TYPE_STRING, &str);

	dbus_message_iter_close_container(&array, &dict);

	return reply;
}

static DBusMessage *set_property(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessageIter iter, value;
	const char *name;

	DBG("conn %p", conn);

	if (dbus_message_iter_init(msg, &iter) == FALSE)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &name);
	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &value);

	if (__connman_security_check_privilege(msg,
					CONNMAN_SECURITY_PRIVILEGE_MODIFY) < 0)
		return __connman_error_permission_denied(msg);

	if (g_str_equal(name, "OfflineMode") == TRUE) {
		connman_bool_t offlinemode;

		dbus_message_iter_get_basic(&value, &offlinemode);

		if (global_offlinemode == offlinemode)
			return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);

		global_offlinemode = offlinemode;

		__connman_storage_save_global();

		__connman_device_set_offlinemode(offlinemode);
	} else if (g_str_equal(name, "ActiveProfile") == TRUE) {
		const char *str;

		dbus_message_iter_get_basic(&value, &str);

		return __connman_error_not_supported(msg);
	} else
		return __connman_error_invalid_property(msg);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *get_state(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *str;

	DBG("conn %p", conn);

	if (__connman_security_check_privilege(msg,
					CONNMAN_SECURITY_PRIVILEGE_PUBLIC) < 0)
		return __connman_error_permission_denied(msg);

	if (__connman_element_count(NULL, CONNMAN_ELEMENT_TYPE_CONNECTION) > 0)
		str = "online";
	else
		str = "offline";

	return g_dbus_create_reply(msg, DBUS_TYPE_STRING, &str,
						DBUS_TYPE_INVALID);
}

static DBusMessage *add_profile(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *name;

	DBG("conn %p", conn);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &name,
							DBUS_TYPE_INVALID);

	return __connman_error_not_supported(msg);
}

static DBusMessage *remove_profile(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *path;

	DBG("conn %p", conn);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID);

	return __connman_error_not_supported(msg);
}

static DBusMessage *request_scan(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	enum connman_device_type type;
	const char *str;
	int err;

	DBG("conn %p", conn);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &str,
							DBUS_TYPE_INVALID);

	if (g_strcmp0(str, "") == 0)
		type = CONNMAN_DEVICE_TYPE_UNKNOWN;
	else if (g_strcmp0(str, "wifi") == 0)
		type = CONNMAN_DEVICE_TYPE_WIFI;
	else if (g_strcmp0(str, "wimax") == 0)
		type = CONNMAN_DEVICE_TYPE_WIMAX;
	else
		return __connman_error_invalid_arguments(msg);

	err = __connman_element_request_scan(type);
	if (err < 0) {
		if (err == -EINPROGRESS) {
			connman_error("Invalid return code from scan");
			err = -EINVAL;
		}

		return __connman_error_failed(msg, -err);
	}

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *enable_technology(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	enum connman_device_type type;
	const char *str;
	int err;

	DBG("conn %p", conn);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &str,
							DBUS_TYPE_INVALID);

	if (g_strcmp0(str, "ethernet") == 0)
		type = CONNMAN_DEVICE_TYPE_ETHERNET;
	else if (g_strcmp0(str, "wifi") == 0)
		type = CONNMAN_DEVICE_TYPE_WIFI;
	else if (g_strcmp0(str, "wimax") == 0)
		type = CONNMAN_DEVICE_TYPE_WIMAX;
	else if (g_strcmp0(str, "bluetooth") == 0)
		type = CONNMAN_DEVICE_TYPE_BLUETOOTH;
	else if (g_strcmp0(str, "gps") == 0)
		type = CONNMAN_DEVICE_TYPE_GPS;
	else
		return __connman_error_invalid_arguments(msg);

	err = __connman_element_enable_technology(type);
	if (err < 0) {
		if (err == -EINPROGRESS) {
			connman_error("Invalid return code from enable");
			err = -EINVAL;
		}

		return __connman_error_failed(msg, -err);
	}

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *disable_technology(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	enum connman_device_type type;
	const char *str;
	int err;

	DBG("conn %p", conn);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &str,
							DBUS_TYPE_INVALID);

	if (g_strcmp0(str, "ethernet") == 0)
		type = CONNMAN_DEVICE_TYPE_ETHERNET;
	else if (g_strcmp0(str, "wifi") == 0)
		type = CONNMAN_DEVICE_TYPE_WIFI;
	else if (g_strcmp0(str, "wimax") == 0)
		type = CONNMAN_DEVICE_TYPE_WIMAX;
	else if (g_strcmp0(str, "bluetooth") == 0)
		type = CONNMAN_DEVICE_TYPE_BLUETOOTH;
	else if (g_strcmp0(str, "gps") == 0)
		type = CONNMAN_DEVICE_TYPE_GPS;
	else
		return __connman_error_invalid_arguments(msg);

	err = __connman_element_disable_technology(type);
	if (err < 0) {
		if (err == -EINPROGRESS) {
			connman_error("Invalid return code from disable");
			err = -EINVAL;
		}

		return __connman_error_failed(msg, -err);
	}

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *connect_service(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	int err;

	DBG("conn %p", conn);

	if (__connman_security_check_privilege(msg,
					CONNMAN_SECURITY_PRIVILEGE_MODIFY) < 0)
		return __connman_error_permission_denied(msg);

	err = __connman_service_create_and_connect(msg);
	if (err < 0) {
		if (err == -EINPROGRESS) {
			connman_error("Invalid return code from connect");
			err = -EINVAL;
		}

		return __connman_error_failed(msg, -err);
	}

	return NULL;
}

static DBusMessage *register_agent(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	const char *sender, *path;

	DBG("conn %p", conn);

	sender = dbus_message_get_sender(msg);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_INVALID);

	__connman_agent_register(sender, path);

	return reply;
}

static DBusMessage *unregister_agent(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	const char *sender, *path;

	DBG("conn %p", conn);

	sender = dbus_message_get_sender(msg);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_INVALID);

	__connman_agent_unregister(sender, path);

	return reply;
}

static GDBusMethodTable manager_methods[] = {
	{ "GetProperties",     "",      "a{sv}", get_properties     },
	{ "SetProperty",       "sv",    "",      set_property       },
	{ "GetState",          "",      "s",     get_state          },
	{ "AddProfile",        "s",     "o",     add_profile        },
	{ "RemoveProfile",     "o",     "",      remove_profile     },
	{ "RequestScan",       "s",     "",      request_scan       },
	{ "EnableTechnology",  "s",     "",      enable_technology  },
	{ "DisableTechnology", "s",     "",      disable_technology },
	{ "ConnectService",    "a{sv}", "o",     connect_service,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ "RegisterAgent",     "o",     "",      register_agent     },
	{ "UnregisterAgent",   "o",     "",      unregister_agent   },
	{ },
};

static GDBusSignalTable manager_signals[] = {
	{ "PropertyChanged", "sv" },
	{ "StateChanged",    "s"  },
	{ },
};

static DBusMessage *nm_sleep(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *nm_wake(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_INVALID);

	return reply;
}

enum {
	NM_STATE_UNKNOWN = 0,
	NM_STATE_ASLEEP,
	NM_STATE_CONNECTING,
	NM_STATE_CONNECTED,
	NM_STATE_DISCONNECTED
};

static DBusMessage *nm_state(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	dbus_uint32_t state;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	state = NM_STATE_DISCONNECTED;

	dbus_message_append_args(reply, DBUS_TYPE_UINT32, &state,
							DBUS_TYPE_INVALID);

	return reply;
}

static GDBusMethodTable nm_methods[] = {
	{ "sleep", "",  "",   nm_sleep        },
	{ "wake",  "",  "",   nm_wake         },
	{ "state", "",  "u",  nm_state        },
	{ },
};

static int manager_load(void)
{
	GKeyFile *keyfile;
	GError *error = NULL;
	connman_bool_t offlinemode;

	DBG("");

	keyfile = __connman_storage_open();
	if (keyfile == NULL)
		return -EIO;

	offlinemode = g_key_file_get_boolean(keyfile, "global",
						"OfflineMode", &error);
	if (error == NULL) {
		global_offlinemode = offlinemode;

		__connman_device_set_offlinemode(offlinemode);
	}
	g_clear_error(&error);

	__connman_storage_close(keyfile, FALSE);

	return 0;
}

static int manager_save(void)
{
	GKeyFile *keyfile;

	DBG("");

	keyfile = __connman_storage_open();
	if (keyfile == NULL)
		return -EIO;

	g_key_file_set_boolean(keyfile, "global",
					"OfflineMode", global_offlinemode);

	__connman_storage_close(keyfile, TRUE);

	return 0;
}

static struct connman_storage manager_storage = {
	.name		= "manager",
	.priority	= CONNMAN_STORAGE_PRIORITY_LOW,
	.global_load	= manager_load,
	.global_save	= manager_save,
};

static DBusConnection *connection = NULL;
static gboolean nm_compat = FALSE;

int __connman_manager_init(DBusConnection *conn, gboolean compat)
{
	DBG("conn %p", conn);

	connection = dbus_connection_ref(conn);
	if (connection == NULL)
		return -1;

	if (connman_storage_register(&manager_storage) < 0)
		connman_error("Failed to register manager storage");

	g_dbus_register_interface(connection, CONNMAN_MANAGER_PATH,
					CONNMAN_MANAGER_INTERFACE,
					manager_methods,
					manager_signals, NULL, NULL, NULL);

	if (compat == TRUE) {
		g_dbus_register_interface(connection, NM_PATH, NM_INTERFACE,
					nm_methods, NULL, NULL, NULL, NULL);

		nm_compat = TRUE;
	}

	return 0;
}

void __connman_manager_cleanup(void)
{
	DBG("conn %p", connection);

	connman_storage_unregister(&manager_storage);

	if (nm_compat == TRUE) {
		g_dbus_unregister_interface(connection, NM_PATH, NM_INTERFACE);
	}

	g_dbus_unregister_interface(connection, CONNMAN_MANAGER_PATH,
						CONNMAN_MANAGER_INTERFACE);

	dbus_connection_unref(connection);
}
