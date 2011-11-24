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
#include <stdint.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/device.h>
#include <connman/network.h>
#include <connman/dbus.h>
#include <connman/log.h>

#define uninitialized_var(x) x = x

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

#define GET_PROPERTIES			"GetProperties"
#define SET_PROPERTY			"SetProperty"
#define GET_MODEMS			"GetModems"

#define TIMEOUT 40000

enum ofono_api {
	OFONO_API_SIM =		0x1,
	OFONO_API_NETREG =	0x2,
	OFONO_API_CM =		0x4,
};

static DBusConnection *connection;

static GHashTable *modem_hash;

struct modem_data {
	char *path;

	struct connman_device *device;

	/* Modem Interface */
	char *serial;
	connman_bool_t powered;
	connman_bool_t online;
	uint8_t interfaces;

	connman_bool_t set_powered;
	connman_bool_t set_online;

	/* ConnectionManager Interface */
	connman_bool_t attached;
	connman_bool_t cm_powered;

	connman_bool_t set_cm_powered;

	/* SimManager Interface */
	char *imsi;

	/* pending calls */
	DBusPendingCall	*call_set_property;
	DBusPendingCall	*call_get_properties;
};

typedef void (*set_property_cb)(struct modem_data *data,
				connman_bool_t success);
typedef void (*get_properties_cb)(struct modem_data *data,
				DBusMessageIter *dict);

struct property_info {
	struct modem_data *modem;
	const char *path;
	const char *interface;
	const char *property;
	set_property_cb set_property_cb;
	get_properties_cb get_properties_cb;
};

static void set_property_reply(DBusPendingCall *call, void *user_data)
{
	struct property_info *info = user_data;
	DBusMessage *reply;
	DBusError error;
	connman_bool_t success = TRUE;

	DBG("%s path %s %s.%s", info->modem->path,
		info->path, info->interface, info->property);

	info->modem->call_set_property = NULL;

	dbus_error_init(&error);

	reply = dbus_pending_call_steal_reply(call);

	if (dbus_set_error_from_message(&error, reply)) {
		connman_error("Failed to change property: %s %s.%s: %s %s",
				info->path, info->interface, info->property,
				error.name, error.message);
		dbus_error_free(&error);
		success = FALSE;
	}

	if (info->set_property_cb != NULL)
		(*info->set_property_cb)(info->modem, success);

	dbus_message_unref(reply);

	dbus_pending_call_unref(call);
}

static int set_property(struct modem_data *modem,
			const char *path, const char *interface,
			const char *property, int type, void *value,
			set_property_cb notify)
{
	DBusMessage *message;
	DBusMessageIter iter;
	struct property_info *info;

	DBG("%s path %s %s.%s", modem->path, path, interface, property);

	if (modem->call_set_property != NULL) {
		connman_error("Pending SetProperty");
		return -EBUSY;
	}

	message = dbus_message_new_method_call(OFONO_SERVICE, path,
					interface, SET_PROPERTY);
	if (message == NULL)
		return -ENOMEM;

	dbus_message_iter_init_append(message, &iter);
	connman_dbus_property_append_basic(&iter, property, type, value);

	if (dbus_connection_send_with_reply(connection, message,
			&modem->call_set_property, TIMEOUT) == FALSE) {
		connman_error("Failed to change property: %s %s.%s",
				path, interface, property);
		dbus_message_unref(message);
		return -EINVAL;
	}

	if (modem->call_set_property == NULL) {
		connman_error("D-Bus connection not available");
		dbus_message_unref(message);
		return -EINVAL;
	}

	info = g_try_new0(struct property_info, 1);
	if (info == NULL) {
		dbus_message_unref(message);
		return -ENOMEM;
	}

	info->modem = modem;
	info->path = path;
	info->interface = interface;
	info->property = property;
	info->set_property_cb = notify;

	dbus_pending_call_set_notify(modem->call_set_property,
					set_property_reply, info, g_free);

	dbus_message_unref(message);

	return -EINPROGRESS;
}

static void get_properties_reply(DBusPendingCall *call, void *user_data)
{
	struct property_info *info = user_data;
	DBusMessageIter array, dict;
	DBusMessage *reply;
	DBusError error;

	DBG("%s path %s %s", info->modem->path, info->path, info->interface);

	info->modem->call_get_properties = NULL;

	dbus_error_init(&error);

	reply = dbus_pending_call_steal_reply(call);

	if (dbus_set_error_from_message(&error, reply)) {
		connman_error("Failed to get properties: %s %s: %s %s",
				info->path, info->interface,
				error.name, error.message);
		dbus_error_free(&error);

		goto done;
	}

	if (dbus_message_iter_init(reply, &array) == FALSE)
		goto done;

	if (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_ARRAY)
		goto done;

	dbus_message_iter_recurse(&array, &dict);

	if (info->get_properties_cb != NULL)
		(*info->get_properties_cb)(info->modem, &dict);

done:

	dbus_message_unref(reply);

	dbus_pending_call_unref(call);
}

static int get_properties(const char *path, const char *interface,
				get_properties_cb notify,
				struct modem_data *modem)
{
	DBusMessage *message;
	struct property_info *info;

	DBG("%s path %s %s", modem->path, path, interface);

	if (modem->call_get_properties != NULL) {
		connman_error("Pending GetProperties");
		return -EBUSY;
	}

	message = dbus_message_new_method_call(OFONO_SERVICE, path,
					interface, GET_PROPERTIES);
	if (message == NULL)
		return -ENOMEM;

	if (dbus_connection_send_with_reply(connection, message,
			&modem->call_get_properties, TIMEOUT) == FALSE) {
		connman_error("Failed to call %s.GetProperties()", interface);
		dbus_message_unref(message);
		return -EINVAL;
	}

	if (modem->call_get_properties == NULL) {
		connman_error("D-Bus connection not available");
		dbus_message_unref(message);
		return -EINVAL;
	}

	info = g_try_new0(struct property_info, 1);
	if (info == NULL) {
		dbus_message_unref(message);
		return -ENOMEM;
	}

	info->modem = modem;
	info->path = path;
	info->interface = interface;
	info->get_properties_cb = notify;

	dbus_pending_call_set_notify(modem->call_get_properties,
					get_properties_reply, info, g_free);

	dbus_message_unref(message);

	return -EINPROGRESS;
}

static void modem_set_online_reply(struct modem_data *modem,
					connman_bool_t success)
{
	DBG("%s", modem->path);

	if (success == TRUE) {
		/*
		 * Don't handle do anything on success here. oFono will send
		 * the change via PropertyChanged singal.
		 */
		return;
	}

	modem->set_online = FALSE;
}

static int modem_set_online(struct modem_data *modem)
{
	DBG("%s", modem->path);

	modem->set_online = TRUE;

	return set_property(modem, modem->path,
				OFONO_MODEM_INTERFACE,
				"Online", DBUS_TYPE_BOOLEAN,
				&modem->set_online,
				modem_set_online_reply);
}

static void cm_set_powered_reply(struct modem_data *modem,
					connman_bool_t success)
{
	DBG("%s", modem->path);

	if (success == TRUE) {
		/*
		 * Don't handle do anything on success here. oFono will send
		 * the change via PropertyChanged singal.
		 */
		return;
	}

	modem->set_cm_powered = FALSE;
}

static int cm_set_powered(struct modem_data *modem)
{
	DBG("%s", modem->path);

	modem->set_cm_powered = TRUE;

	return set_property(modem, modem->path,
				OFONO_CM_INTERFACE,
				"Powered", DBUS_TYPE_BOOLEAN,
				&modem->set_cm_powered,
				cm_set_powered_reply);
}

static int modem_set_powered(struct modem_data *modem)
{
	DBG("%s", modem->path);

	modem->set_powered = TRUE;

	return set_property(modem, modem->path,
				OFONO_MODEM_INTERFACE,
				"Powered", DBUS_TYPE_BOOLEAN,
				&modem->set_powered,
				NULL);
}

static connman_bool_t has_interface(uint8_t interfaces,
					enum ofono_api api)
{
	if ((interfaces & api) == api)
		return TRUE;

	return FALSE;
}

static uint8_t extract_interfaces(DBusMessageIter *array)
{
	DBusMessageIter entry;
	uint8_t interfaces = 0;

	dbus_message_iter_recurse(array, &entry);

	while (dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_STRING) {
		const char *name;

		dbus_message_iter_get_basic(&entry, &name);

		if (g_str_equal(name, OFONO_SIM_INTERFACE) == TRUE)
			interfaces |= OFONO_API_SIM;
		else if (g_str_equal(name, OFONO_NETREG_INTERFACE) == TRUE)
			interfaces |= OFONO_API_NETREG;
		else if (g_str_equal(name, OFONO_CM_INTERFACE) == TRUE)
			interfaces |= OFONO_API_CM;

		dbus_message_iter_next(&entry);
	}

	return interfaces;
}

static connman_bool_t ready_to_create_device(struct modem_data *modem)
{
	/*
	 * There are three different modem types which behave slightly
	 * different:
	 * - GSM modems will expose the SIM interface then the
	 *   CM interface.
	 * - DUN modems will expose first a unique serial number (BDADDR)
	 *   and then the CM interface.
	 * - CDMA modems will expose CM first and sometime later
	 *   a unique serial number.
	 *
	 * This functions tests if we have the necessary information gathered
	 * before we are able to create a device.
	 */

	if (modem->device != NULL)
		return FALSE;

	if (modem->imsi != NULL || modem->serial != NULL)
		return TRUE;

	return FALSE;
}

static void create_device(struct modem_data *modem)
{
	struct connman_device *device;
	char *uninitialized_var(ident);

	DBG("%s", modem->path);

	if (modem->imsi != NULL)
		ident = modem->imsi;
	else if (modem->serial != NULL)
		ident = modem->serial;

	if (connman_dbus_validate_ident(ident) == FALSE)
		ident = connman_dbus_encode_string(ident);
	else
		ident = g_strdup(ident);

	device = connman_device_create(ident, CONNMAN_DEVICE_TYPE_CELLULAR);
	if (device == NULL)
		goto out;

	DBG("device %p", device);

	connman_device_set_ident(device, ident);

	connman_device_set_string(device, "Path", modem->path);

	connman_device_set_data(device, modem);

	if (connman_device_register(device) < 0) {
		connman_error("Failed to register cellular device");
		connman_device_unref(device);
		goto out;
	}

	modem->device = device;

out:
	g_free(ident);
}

static void destroy_device(struct modem_data *modem)
{
	DBG("%s", modem->path);

	connman_device_set_powered(modem->device, FALSE);

	connman_device_unregister(modem->device);
	connman_device_unref(modem->device);

	modem->device = NULL;
}

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
	const char *path = dbus_message_get_path(message);
	struct modem_data *modem;
	DBusMessageIter iter, value;
	const char *key;

	modem = g_hash_table_lookup(modem_hash, path);
	if (modem == NULL)
		return TRUE;

	if (dbus_message_iter_init(message, &iter) == FALSE)
		return TRUE;

	dbus_message_iter_get_basic(&iter, &key);

	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &value);

	if (g_str_equal(key, "Attached") == TRUE) {
		dbus_message_iter_get_basic(&value, &modem->attached);

		DBG("%s Attached %d", modem->path, modem->attached);
	} else if (g_str_equal(key, "Powered") == TRUE) {
		dbus_message_iter_get_basic(&value, &modem->cm_powered);

		DBG("%s ConnnectionManager Powered %d", modem->path,
			modem->cm_powered);

		if (modem->cm_powered == FALSE)
			cm_set_powered(modem);
	}

	return TRUE;
}

static void cm_properties_reply(struct modem_data *modem, DBusMessageIter *dict)
{
	DBG("%s", modem->path);

	while (dbus_message_iter_get_arg_type(dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;

		dbus_message_iter_recurse(dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		if (g_str_equal(key, "Attached") == TRUE) {
			dbus_message_iter_get_basic(&value, &modem->attached);

			DBG("%s Attached %d", modem->path,
				modem->attached);
		} else if (g_str_equal(key, "Powered") == TRUE) {
			dbus_message_iter_get_basic(&value, &modem->cm_powered);

			DBG("%s ConnnectionManager Powered %d", modem->path,
				modem->cm_powered);

			if (modem->cm_powered == FALSE)
				cm_set_powered(modem);
		}

		dbus_message_iter_next(dict);
	}
}

static int cm_get_properties(struct modem_data *modem)
{
	return get_properties(modem->path, OFONO_CM_INTERFACE,
				cm_properties_reply, modem);
}

static void update_sim_imsi(struct modem_data *modem,
				const char *imsi)
{
	DBG("%s imsi %s", modem->path, imsi);

	if (g_strcmp0(modem->imsi, imsi) == 0)
		return;

	g_free(modem->imsi);
	modem->imsi = g_strdup(imsi);
}

static gboolean sim_changed(DBusConnection *connection, DBusMessage *message,
				void *user_data)
{
	const char *path = dbus_message_get_path(message);
	struct modem_data *modem;
	DBusMessageIter iter, value;
	const char *key;

	modem = g_hash_table_lookup(modem_hash, path);
	if (modem == NULL)
		return TRUE;

	if (dbus_message_iter_init(message, &iter) == FALSE)
		return TRUE;

	dbus_message_iter_get_basic(&iter, &key);

	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &value);

	if (g_str_equal(key, "SubscriberIdentity") == TRUE) {
		char *imsi;

		dbus_message_iter_get_basic(&value, &imsi);

		update_sim_imsi(modem, imsi);

		if (modem->online == FALSE) {
			modem_set_online(modem);
		} else if (has_interface(modem->interfaces,
						OFONO_API_CM) == TRUE) {
			if (ready_to_create_device(modem) == TRUE)
				create_device(modem);
		}
	}

	return TRUE;
}

static void sim_properties_reply(struct modem_data *modem,
					DBusMessageIter *dict)
{
	DBG("%s", modem->path);

	while (dbus_message_iter_get_arg_type(dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;

		dbus_message_iter_recurse(dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		if (g_str_equal(key, "SubscriberIdentity") == TRUE) {
			char *imsi;

			dbus_message_iter_get_basic(&value, &imsi);

			update_sim_imsi(modem, imsi);

			if (modem->online == FALSE) {
				modem_set_online(modem);
				break;
			}

			if (has_interface(modem->interfaces, OFONO_API_CM) == TRUE) {
				if (ready_to_create_device(modem) == TRUE)
					create_device(modem);
				if (modem->device != NULL)
					cm_get_properties(modem);
			}
			return;
		}

		dbus_message_iter_next(dict);
	}
}

static int sim_get_properties(struct modem_data *modem)
{
	return get_properties(modem->path, OFONO_SIM_INTERFACE,
			sim_properties_reply, modem);
}

static gboolean modem_changed(DBusConnection *connection, DBusMessage *message,
				void *user_data)
{
	const char *path = dbus_message_get_path(message);
	struct modem_data *modem;
	DBusMessageIter iter, value;
	const char *key;

	modem = g_hash_table_lookup(modem_hash, path);
	if (modem == NULL)
		return TRUE;

	if (dbus_message_iter_init(message, &iter) == FALSE)
		return TRUE;

	dbus_message_iter_get_basic(&iter, &key);

	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &value);

	if (g_str_equal(key, "Powered") == TRUE) {
		dbus_message_iter_get_basic(&value, &modem->powered);

		DBG("%s Powered %d", modem->path, modem->powered);

		if (modem->powered == FALSE)
			modem_set_powered(modem);
	} else if (g_str_equal(key, "Online") == TRUE) {
		dbus_message_iter_get_basic(&value, &modem->online);

		DBG("%s Online %d", modem->path, modem->online);

		if (modem->online == FALSE)
			return TRUE;

		if (has_interface(modem->interfaces, OFONO_API_CM) == FALSE)
			return TRUE;
		if (ready_to_create_device(modem) == TRUE)
			create_device(modem);
		if (modem->device != NULL)
			cm_get_properties(modem);
	} else if (g_str_equal(key, "Interfaces") == TRUE) {
		modem->interfaces = extract_interfaces(&value);

		DBG("%s Interfaces 0x%02x", modem->path,
			modem->interfaces);

		if (has_interface(modem->interfaces, OFONO_API_SIM) == TRUE) {
			if (modem->imsi == NULL &&
					modem->set_powered == FALSE) {
				/*
				 * Only use do GetProperties() when
				 * device has not been powered up.
				 */
				sim_get_properties(modem);
				return TRUE;
			}
		}

		if (has_interface(modem->interfaces, OFONO_API_CM) == TRUE) {
			if (ready_to_create_device(modem) == TRUE)
				create_device(modem);
			if (modem->device != NULL)
				cm_get_properties(modem);
		} else {
			if (modem->device != NULL)
				destroy_device(modem);
		}
	} else if (g_str_equal(key, "Serial") == TRUE) {
		char *serial;

		dbus_message_iter_get_basic(&value, &serial);

		g_free(modem->serial);
		modem->serial = g_strdup(serial);

		DBG("%s Serial %s", modem->path, modem->serial);

		if (has_interface(modem->interfaces, OFONO_API_CM) == TRUE) {
			if (ready_to_create_device(modem) == TRUE)
				create_device(modem);
			if (modem->device != NULL)
				cm_get_properties(modem);
		}
	}

	return TRUE;
}

static void add_modem(const char *path, DBusMessageIter *prop)
{
	struct modem_data *modem;

	DBG("%s", path);

	modem = g_hash_table_lookup(modem_hash, path);
	if (modem != NULL) {
		/*
		 * When oFono powers up we ask for the modems and oFono is
		 * reporting with modem_added signal the modems. Only
		 * handle them once.
		 */
		return;
	}

	modem = g_try_new0(struct modem_data, 1);
	if (modem == NULL)
		return;

	modem->path = g_strdup(path);

	g_hash_table_insert(modem_hash, g_strdup(path), modem);

	while (dbus_message_iter_get_arg_type(prop) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;

		dbus_message_iter_recurse(prop, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		if (g_str_equal(key, "Powered") == TRUE) {
			dbus_message_iter_get_basic(&value, &modem->powered);

			DBG("%s Powered %d", modem->path, modem->powered);
		} else if (g_str_equal(key, "Online") == TRUE) {
			dbus_message_iter_get_basic(&value, &modem->online);

			DBG("%s Online %d", modem->path, modem->online);
		} else if (g_str_equal(key, "Interfaces") == TRUE) {
			modem->interfaces = extract_interfaces(&value);

			DBG("%s Interfaces 0x%02x", modem->path,
				modem->interfaces);
		} else if (g_str_equal(key, "Serial") == TRUE) {
			char *serial;

			dbus_message_iter_get_basic(&value, &serial);
			modem->serial = g_strdup(serial);

			DBG("%s Serial %s", modem->path, modem->serial);
		}

		dbus_message_iter_next(prop);
	}

	if (modem->powered == FALSE) {
		modem_set_powered(modem);
	} else if (has_interface(modem->interfaces, OFONO_API_SIM) == TRUE) {
		sim_get_properties(modem);
	} else if (has_interface(modem->interfaces, OFONO_API_CM) == TRUE) {
		if (ready_to_create_device(modem) == TRUE)
			create_device(modem);
		if (modem->device != NULL)
			cm_get_properties(modem);
	}
}

static void remove_modem(gpointer data)
{
	struct modem_data *modem = data;

	DBG("%s", modem->path);

	if (modem->call_set_property != NULL)
		dbus_pending_call_cancel(modem->call_set_property);

	if (modem->call_get_properties != NULL)
		dbus_pending_call_cancel(modem->call_get_properties);

	if (modem->device != NULL)
		destroy_device(modem);

	g_free(modem->serial);
	g_free(modem->imsi);
	g_free(modem->path);

	g_free(modem);
}

static gboolean modem_added(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	DBusMessageIter iter, properties;
	const char *path;

	DBG("");

	if (dbus_message_iter_init(message, &iter) == FALSE)
		return TRUE;

	dbus_message_iter_get_basic(&iter, &path);

	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &properties);

	add_modem(path, &properties);

	return TRUE;
}

static gboolean modem_removed(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	DBusMessageIter iter;
	const char *path;

	DBG("");

	if (dbus_message_iter_init(message, &iter) == FALSE)
		return TRUE;

	dbus_message_iter_get_basic(&iter, &path);

	g_hash_table_remove(modem_hash, path);

	return TRUE;
}

static void manager_get_modems_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply;
	DBusError error;
	DBusMessageIter array, dict;

	DBG("");

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, reply) == TRUE) {
		connman_error("%s", error.message);
		dbus_error_free(&error);
		goto done;
	}

	if (dbus_message_iter_init(reply, &array) == FALSE)
		goto done;

	dbus_message_iter_recurse(&array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_STRUCT) {
		DBusMessageIter value, properties;
		const char *path;

		dbus_message_iter_recurse(&dict, &value);
		dbus_message_iter_get_basic(&value, &path);

		dbus_message_iter_next(&value);
		dbus_message_iter_recurse(&value, &properties);

		add_modem(path, &properties);

		dbus_message_iter_next(&dict);
	}

done:
	dbus_message_unref(reply);

	dbus_pending_call_unref(call);
}

static int manager_get_modems(void)
{
	DBusMessage *message;
	DBusPendingCall *call;

	DBG("");

	message = dbus_message_new_method_call(OFONO_SERVICE, "/",
					OFONO_MANAGER_INTERFACE, GET_MODEMS);
	if (message == NULL)
		return -ENOMEM;

	if (dbus_connection_send_with_reply(connection, message,
					       &call, TIMEOUT) == FALSE) {
		connman_error("Failed to call GetModems()");
		dbus_message_unref(message);
		return -EINVAL;
	}

	if (call == NULL) {
		connman_error("D-Bus connection not available");
		dbus_message_unref(message);
		return -EINVAL;
	}

	dbus_pending_call_set_notify(call, manager_get_modems_reply,
					NULL, NULL);

	dbus_message_unref(message);

	return -EINPROGRESS;
}

static void ofono_connect(DBusConnection *conn, void *user_data)
{
	DBG("");

	modem_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						g_free, remove_modem);
	if (modem_hash == NULL)
		return;

	manager_get_modems();
}

static void ofono_disconnect(DBusConnection *conn, void *user_data)
{
	DBG("");

	if (modem_hash == NULL)
		return;

	g_hash_table_destroy(modem_hash);
	modem_hash = NULL;
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
	struct modem_data *modem = connman_device_get_data(device);

	DBG("%s device %p", modem->path, device);

	return 0;
}

static void modem_remove(struct connman_device *device)
{
	struct modem_data *modem = connman_device_get_data(device);

	DBG("%s device %p", modem->path, device);
}

static int modem_enable(struct connman_device *device)
{
	struct modem_data *modem = connman_device_get_data(device);

	DBG("%s device %p", modem->path, device);

	return 0;
}

static int modem_disable(struct connman_device *device)
{
	struct modem_data *modem = connman_device_get_data(device);

	DBG("%s device %p", modem->path, device);

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

	if (modem_hash != NULL) {
		g_hash_table_destroy(modem_hash);
		modem_hash = NULL;
	}

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
