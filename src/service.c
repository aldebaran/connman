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

#include <stdio.h>
#include <string.h>
#include <gdbus.h>

#include "connman.h"

static DBusConnection *connection = NULL;

static GSequence *service_list = NULL;
static GHashTable *service_hash = NULL;

struct connman_service {
	gint refcount;
	char *identifier;
	char *path;
	enum connman_service_type type;
	enum connman_service_mode mode;
	enum connman_service_security security;
	enum connman_service_state state;
	enum connman_service_error error;
	connman_uint8_t strength;
	connman_bool_t favorite;
	connman_bool_t hidden;
	connman_bool_t ignore;
	GTimeVal modified;
	unsigned int order;
	char *name;
	char *passphrase;
	char *profile;
	struct connman_ipconfig *ipconfig;
	struct connman_device *device;
	struct connman_network *network;
	DBusMessage *pending;
	guint timeout;
};

static void append_path(gpointer value, gpointer user_data)
{
	struct connman_service *service = value;
	DBusMessageIter *iter = user_data;

	if (service->path == NULL)
		return;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH,
							&service->path);
}

void __connman_service_list(DBusMessageIter *iter)
{
	DBG("");

	g_sequence_foreach(service_list, append_path, iter);
}

struct find_data {
	const char *path;
	struct connman_service *service;
};

static void compare_path(gpointer value, gpointer user_data)
{
	struct connman_service *service = value;
	struct find_data *data = user_data;

	if (data->service != NULL)
		return;

	if (g_strcmp0(service->path, data->path) == 0)
		data->service = service;
}

static struct connman_service *find_service(const char *path)
{
	struct find_data data = { .path = path, .service = NULL };

	DBG("path %s", path);

	g_sequence_foreach(service_list, compare_path, &data);

	return data.service;
}

static const char *type2string(enum connman_service_type type)
{
	switch (type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
		break;
	case CONNMAN_SERVICE_TYPE_ETHERNET:
		return "ethernet";
	case CONNMAN_SERVICE_TYPE_WIFI:
		return "wifi";
	case CONNMAN_SERVICE_TYPE_WIMAX:
		return "wimax";
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
		return "bluetooth";
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		return "cellular";
	}

	return NULL;
}

static const char *mode2string(enum connman_service_mode mode)
{
	switch (mode) {
	case CONNMAN_SERVICE_MODE_UNKNOWN:
		break;
	case CONNMAN_SERVICE_MODE_MANAGED:
		return "managed";
	case CONNMAN_SERVICE_MODE_ADHOC:
		return "adhoc";
	}

	return NULL;
}

static const char *security2string(enum connman_service_security security)
{
	switch (security) {
	case CONNMAN_SERVICE_SECURITY_UNKNOWN:
		break;
	case CONNMAN_SERVICE_SECURITY_NONE:
		return "none";
	case CONNMAN_SERVICE_SECURITY_WEP:
		return "wep";
	case CONNMAN_SERVICE_SECURITY_WPA:
		return "wpa";
	case CONNMAN_SERVICE_SECURITY_RSN:
		return "rsn";
	}

	return NULL;
}

static const char *state2string(enum connman_service_state state)
{
	switch (state) {
	case CONNMAN_SERVICE_STATE_UNKNOWN:
		break;
	case CONNMAN_SERVICE_STATE_IDLE:
		return "idle";
	case CONNMAN_SERVICE_STATE_CARRIER:
		return "carrier";
	case CONNMAN_SERVICE_STATE_ASSOCIATION:
		return "association";
	case CONNMAN_SERVICE_STATE_CONFIGURATION:
		return "configuration";
	case CONNMAN_SERVICE_STATE_READY:
		return "ready";
	case CONNMAN_SERVICE_STATE_DISCONNECT:
		return "disconnect";
	case CONNMAN_SERVICE_STATE_FAILURE:
		return "failure";
	}

	return NULL;
}

static const char *error2string(enum connman_service_error error)
{
	switch (error) {
	case CONNMAN_SERVICE_ERROR_UNKNOWN:
		break;
	case CONNMAN_SERVICE_ERROR_OUT_OF_RANGE:
		return "out-of-range";
	case CONNMAN_SERVICE_ERROR_PIN_MISSING:
		return "pin-missing";
	case CONNMAN_SERVICE_ERROR_DHCP_FAILED:
		return "dhcp-failed";
	case CONNMAN_SERVICE_ERROR_CONNECT_FAILED:
		return "connect-failed";
	}

	return NULL;
}

static enum connman_service_error string2error(const char *error)
{
	if (g_strcmp0(error, "dhcp-failed") == 0)
		return CONNMAN_SERVICE_ERROR_DHCP_FAILED;
	else if (g_strcmp0(error, "pin-missing") == 0)
		return CONNMAN_SERVICE_ERROR_PIN_MISSING;

	return CONNMAN_SERVICE_ERROR_UNKNOWN;
}

static void state_changed(struct connman_service *service)
{
	DBusMessage *signal;
	DBusMessageIter entry, value;
	const char *str, *key = "State";

	if (service->path == NULL)
		return;

	str = state2string(service->state);
	if (str == NULL)
		return;

	signal = dbus_message_new_signal(service->path,
				CONNMAN_SERVICE_INTERFACE, "PropertyChanged");
	if (signal == NULL)
		return;

	dbus_message_iter_init_append(signal, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
					DBUS_TYPE_STRING_AS_STRING, &value);
	dbus_message_iter_append_basic(&value, DBUS_TYPE_STRING, &str);
	dbus_message_iter_close_container(&entry, &value);

	g_dbus_send_message(connection, signal);
}

static void strength_changed(struct connman_service *service)
{
	DBusMessage *signal;
	DBusMessageIter entry, value;
	const char *key = "Strength";

	if (service->path == NULL)
		return;

	if (service->strength == 0)
		return;

	signal = dbus_message_new_signal(service->path,
				CONNMAN_SERVICE_INTERFACE, "PropertyChanged");
	if (signal == NULL)
		return;

	dbus_message_iter_init_append(signal, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
					DBUS_TYPE_BYTE_AS_STRING, &value);
	dbus_message_iter_append_basic(&value, DBUS_TYPE_BYTE,
							&service->strength);
	dbus_message_iter_close_container(&entry, &value);

	g_dbus_send_message(connection, signal);
}

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_service *service = user_data;
	DBusMessage *reply;
	DBusMessageIter array, dict;
	const char *str;

	DBG("service %p", service);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &array);

	dbus_message_iter_open_container(&array, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	str = type2string(service->type);
	if (str != NULL)
		connman_dbus_dict_append_variant(&dict, "Type",
						DBUS_TYPE_STRING, &str);

	str = mode2string(service->mode);
	if (str != NULL)
		connman_dbus_dict_append_variant(&dict, "Mode",
						DBUS_TYPE_STRING, &str);

	str = security2string(service->security);
	if (str != NULL)
		connman_dbus_dict_append_variant(&dict, "Security",
						DBUS_TYPE_STRING, &str);

	str = state2string(service->state);
	if (str != NULL)
		connman_dbus_dict_append_variant(&dict, "State",
						DBUS_TYPE_STRING, &str);

	str = error2string(service->error);
	if (str != NULL)
		connman_dbus_dict_append_variant(&dict, "Error",
						DBUS_TYPE_STRING, &str);

	if (service->strength > 0)
		connman_dbus_dict_append_variant(&dict, "Strength",
					DBUS_TYPE_BYTE, &service->strength);

	connman_dbus_dict_append_variant(&dict, "Favorite",
					DBUS_TYPE_BOOLEAN, &service->favorite);

	if (service->name != NULL)
		connman_dbus_dict_append_variant(&dict, "Name",
					DBUS_TYPE_STRING, &service->name);

	if (service->passphrase != NULL &&
			__connman_security_check_privilege(msg,
				CONNMAN_SECURITY_PRIVILEGE_SECRET) == 0)
		connman_dbus_dict_append_variant(&dict, "Passphrase",
				DBUS_TYPE_STRING, &service->passphrase);

	__connman_ipconfig_append_ipv4(service->ipconfig, &dict, "IPv4.");

	dbus_message_iter_close_container(&array, &dict);

	return reply;
}

static DBusMessage *set_property(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_service *service = user_data;
	DBusMessageIter iter, value;
	const char *name;
	int type;

	DBG("service %p", service);

	if (dbus_message_iter_init(msg, &iter) == FALSE)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &name);
	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &value);

	if (__connman_security_check_privilege(msg,
					CONNMAN_SECURITY_PRIVILEGE_MODIFY) < 0)
		return __connman_error_permission_denied(msg);

	type = dbus_message_iter_get_arg_type(&value);

	if (g_str_equal(name, "Passphrase") == TRUE) {
		const char *passphrase;

		if (type != DBUS_TYPE_STRING)
			return __connman_error_invalid_arguments(msg);

		if (__connman_security_check_privilege(msg,
					CONNMAN_SECURITY_PRIVILEGE_SECRET) < 0)
			return __connman_error_permission_denied(msg);

		dbus_message_iter_get_basic(&value, &passphrase);

		g_free(service->passphrase);
		service->passphrase = g_strdup(passphrase);

		if (service->network != NULL)
			connman_network_set_string(service->network,
				"WiFi.Passphrase", service->passphrase);

		__connman_storage_save_service(service);
	} else if (g_str_has_prefix(name, "IPv4.") == TRUE) {
		int err;

		err = __connman_ipconfig_set_ipv4(service->ipconfig,
							name + 5, &value);
		if (err < 0)
			return __connman_error_failed(msg, -err);
	} else
		return __connman_error_invalid_property(msg);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static void set_idle(struct connman_service *service)
{
	service->state = CONNMAN_SERVICE_STATE_IDLE;
	service->error = CONNMAN_SERVICE_ERROR_UNKNOWN;
	state_changed(service);
}

static DBusMessage *clear_property(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_service *service = user_data;
	const char *name;

	DBG("service %p", service);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &name,
							DBUS_TYPE_INVALID);

	if (__connman_security_check_privilege(msg,
					CONNMAN_SECURITY_PRIVILEGE_MODIFY) < 0)
		return __connman_error_permission_denied(msg);

	if (g_str_equal(name, "Error") == TRUE) {
		set_idle(service);

		g_get_current_time(&service->modified);
		__connman_storage_save_service(service);
	} else
		return __connman_error_invalid_property(msg);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static connman_bool_t is_connecting(struct connman_service *service)
{
	switch (service->state) {
	case CONNMAN_SERVICE_STATE_UNKNOWN:
	case CONNMAN_SERVICE_STATE_IDLE:
	case CONNMAN_SERVICE_STATE_CARRIER:
	case CONNMAN_SERVICE_STATE_FAILURE:
	case CONNMAN_SERVICE_STATE_DISCONNECT:
	case CONNMAN_SERVICE_STATE_READY:
		break;
	case CONNMAN_SERVICE_STATE_ASSOCIATION:
	case CONNMAN_SERVICE_STATE_CONFIGURATION:
		return TRUE;
	}

	return FALSE;
}

static connman_bool_t is_ignore(struct connman_service *service)
{
	if (service->ignore == TRUE)
		return TRUE;

	if (service->state == CONNMAN_SERVICE_STATE_FAILURE)
		return TRUE;

	return FALSE;
}

void __connman_service_auto_connect(void)
{
	struct connman_service *service = NULL;
	GSequenceIter *iter;

	DBG("");

	iter = g_sequence_get_begin_iter(service_list);

	while (g_sequence_iter_is_end(iter) == FALSE) {
		service = g_sequence_get(iter);

		if (service->pending != NULL)
			return;

		if (is_connecting(service) == TRUE)
			return;

		if (service->favorite == FALSE)
			return;

		if (service->state == CONNMAN_SERVICE_STATE_READY)
			return;

		if (is_ignore(service) == FALSE &&
				service->state == CONNMAN_SERVICE_STATE_IDLE)
			break;

		service = NULL;

		iter = g_sequence_iter_next(iter);
	}

	if (service != NULL)
		__connman_service_connect(service);
}

static void reply_pending(struct connman_service *service, int error)
{
	if (service->timeout > 0) {
		g_source_remove(service->timeout);
		service->timeout = 0;
	}

	if (service->pending != NULL) {
		if (error > 0) {
			DBusMessage *reply;

			reply = __connman_error_failed(service->pending,
								error);
			if (reply != NULL)
				g_dbus_send_message(connection, reply);
		} else
			g_dbus_send_reply(connection, service->pending,
							DBUS_TYPE_INVALID);

		dbus_message_unref(service->pending);
		service->pending = NULL;
	}
}

static gboolean connect_timeout(gpointer user_data)
{
	struct connman_service *service = user_data;
	connman_bool_t auto_connect = FALSE;

	DBG("service %p", service);

	service->timeout = 0;

	if (service->network != NULL) {
		connman_bool_t connected;

		connected = connman_network_get_connected(service->network);
		if (connected == TRUE) {
			__connman_service_indicate_state(service,
						CONNMAN_SERVICE_STATE_READY);
			return FALSE;
		}

		__connman_network_disconnect(service->network);
	} else if (service->device != NULL) {
		connman_bool_t disconnected;

		disconnected = connman_device_get_disconnected(service->device);
		if (disconnected == FALSE) {
			__connman_service_indicate_state(service,
						CONNMAN_SERVICE_STATE_READY);
			return FALSE;
		}

		__connman_device_disconnect(service->device);
	}

	if (service->pending != NULL) {
		DBusMessage *reply;

		reply = __connman_error_operation_timeout(service->pending);
		if (reply != NULL)
			g_dbus_send_message(connection, reply);

		dbus_message_unref(service->pending);
		service->pending = NULL;
	} else
		auto_connect = TRUE;

	__connman_service_indicate_state(service,
					CONNMAN_SERVICE_STATE_FAILURE);

	if (auto_connect == TRUE)
		__connman_service_auto_connect();

	return FALSE;
}

static DBusMessage *connect_service(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_service *service = user_data;
	GSequenceIter *iter;
	int err;

	DBG("service %p", service);

	if (service->pending != NULL)
		return __connman_error_in_progress(msg);

	iter = g_sequence_get_begin_iter(service_list);

	while (g_sequence_iter_is_end(iter) == FALSE) {
		struct connman_service *service = g_sequence_get(iter);

		if (is_connecting(service) == TRUE)
			return __connman_error_in_progress(msg);

		iter = g_sequence_iter_next(iter);
	}

	service->ignore = FALSE;

	service->pending = dbus_message_ref(msg);

	err = __connman_service_connect(service);
	if (err < 0) {
		if (err != -EINPROGRESS) {
			dbus_message_unref(service->pending);
			service->pending = NULL;

			return __connman_error_failed(msg, -err);
		}

		return NULL;
	}

	dbus_message_unref(service->pending);
	service->pending = NULL;

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *disconnect_service(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_service *service = user_data;
	int err;

	DBG("service %p", service);

	service->ignore = TRUE;

	err = __connman_service_disconnect(service);
	if (err < 0) {
		if (err != -EINPROGRESS)
			return __connman_error_failed(msg, -err);

		return NULL;
	}

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *remove_service(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_service *service = user_data;

	DBG("service %p", service);

	if (service->type == CONNMAN_SERVICE_TYPE_ETHERNET)
		return __connman_error_not_supported(msg);

	if (service->favorite == FALSE)
		return __connman_error_not_supported(msg);

	if (service->network != NULL)
		__connman_network_disconnect(service->network);

	g_free(service->passphrase);
	service->passphrase = NULL;

	connman_service_set_favorite(service, FALSE);
	__connman_storage_save_service(service);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *move_before(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_service *service = user_data;
	struct connman_service *target;
	const char *path;
	GSequenceIter *src, *dst;

	DBG("service %p", service);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID);

	if (service->favorite == FALSE)
		return __connman_error_not_supported(msg);

	target = find_service(path);
	if (target == NULL || target->favorite == FALSE || target == service)
		return __connman_error_invalid_service(msg);

	DBG("target %s", target->identifier);

	g_get_current_time(&service->modified);
	__connman_storage_save_service(service);

	src = g_hash_table_lookup(service_hash, service->identifier);
	dst = g_hash_table_lookup(service_hash, target->identifier);

	g_sequence_move(src, dst);

	__connman_profile_changed(FALSE);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *move_after(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_service *service = user_data;
	struct connman_service *target;
	const char *path;

	DBG("service %p", service);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID);

	if (service->favorite == FALSE)
		return __connman_error_not_supported(msg);

	target = find_service(path);
	if (target == NULL || target->favorite == FALSE || target == service)
		return __connman_error_invalid_service(msg);

	DBG("target %s", target->identifier);

	g_get_current_time(&service->modified);
	__connman_storage_save_service(service);

	return __connman_error_not_implemented(msg);
}

static GDBusMethodTable service_methods[] = {
	{ "GetProperties", "",   "a{sv}", get_properties     },
	{ "SetProperty",   "sv", "",      set_property       },
	{ "ClearProperty", "s",  "",      clear_property     },
	{ "Connect",       "",   "",      connect_service,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ "Disconnect",    "",   "",      disconnect_service },
	{ "Remove",        "",   "",      remove_service     },
	{ "MoveBefore",    "o",  "",      move_before        },
	{ "MoveAfter",     "o",  "",      move_after         },
	{ },
};

static GDBusSignalTable service_signals[] = {
	{ "PropertyChanged", "sv" },
	{ },
};

static void service_free(gpointer user_data)
{
	struct connman_service *service = user_data;
	char *path = service->path;

	DBG("service %p", service);

	reply_pending(service, ENOENT);

	g_hash_table_remove(service_hash, service->identifier);

	service->path = NULL;

	if (path != NULL) {
		__connman_profile_changed(FALSE);

		g_dbus_unregister_interface(connection, path,
						CONNMAN_SERVICE_INTERFACE);
		g_free(path);
	}

	if (service->network != NULL)
		connman_network_unref(service->network);

	connman_ipconfig_unref(service->ipconfig);

	g_free(service->profile);
	g_free(service->name);
	g_free(service->passphrase);
	g_free(service->identifier);
	g_free(service);
}

/**
 * __connman_service_put:
 * @service: service structure
 *
 * Release service if no longer needed
 */
void __connman_service_put(struct connman_service *service)
{
	DBG("service %p", service);

	if (g_atomic_int_dec_and_test(&service->refcount) == TRUE) {
		GSequenceIter *iter;

		iter = g_hash_table_lookup(service_hash, service->identifier);
		if (iter != NULL) {
			__connman_service_disconnect(service);

			service->state = CONNMAN_SERVICE_STATE_FAILURE;
			service->error = CONNMAN_SERVICE_ERROR_OUT_OF_RANGE;
			state_changed(service);

			g_sequence_remove(iter);
		} else
			service_free(service);
	}
}

static void __connman_service_initialize(struct connman_service *service)
{
	DBG("service %p", service);

	service->refcount = 1;

	service->type     = CONNMAN_SERVICE_TYPE_UNKNOWN;
	service->mode     = CONNMAN_SERVICE_MODE_UNKNOWN;
	service->security = CONNMAN_SERVICE_SECURITY_UNKNOWN;
	service->state    = CONNMAN_SERVICE_STATE_UNKNOWN;

	service->favorite = FALSE;
	service->hidden = FALSE;

	service->ignore = FALSE;

	service->order = 0;
}

/**
 * connman_service_create:
 *
 * Allocate a new service.
 *
 * Returns: a newly-allocated #connman_service structure
 */
struct connman_service *connman_service_create(void)
{
	struct connman_service *service;

	service = g_try_new0(struct connman_service, 1);
	if (service == NULL)
		return NULL;

	DBG("service %p", service);

	__connman_service_initialize(service);

	service->ipconfig = connman_ipconfig_create();
	if (service->ipconfig == NULL) {
		g_free(service);
		return NULL;
	}

	connman_ipconfig_set_method(service->ipconfig,
					CONNMAN_IPCONFIG_METHOD_DHCP);

	return service;
}

/**
 * connman_service_ref:
 * @service: service structure
 *
 * Increase reference counter of service
 */
struct connman_service *connman_service_ref(struct connman_service *service)
{
	g_atomic_int_inc(&service->refcount);

	return service;
}

/**
 * connman_service_unref:
 * @service: service structure
 *
 * Decrease reference counter of service
 */
void connman_service_unref(struct connman_service *service)
{
	__connman_service_put(service);
}

static gint service_compare(gconstpointer a, gconstpointer b,
							gpointer user_data)
{
	struct connman_service *service_a = (void *) a;
	struct connman_service *service_b = (void *) b;

	if (service_a->state != service_b->state) {
		if (service_a->state == CONNMAN_SERVICE_STATE_READY)
			return -1;
		if (service_b->state == CONNMAN_SERVICE_STATE_READY)
			return 1;
	}

	if (service_a->order > service_b->order)
		return -1;

	if (service_a->order < service_b->order)
		return 1;

	if (service_a->favorite == TRUE && service_b->favorite == FALSE)
		return -1;

	if (service_a->favorite == FALSE && service_b->favorite == TRUE)
		return 1;

	return (gint) service_b->strength - (gint) service_a->strength;
}

/**
 * connman_service_set_favorite:
 * @service: service structure
 * @favorite: favorite value
 *
 * Change the favorite setting of service
 */
int connman_service_set_favorite(struct connman_service *service,
						connman_bool_t favorite)
{
	GSequenceIter *iter;

	iter = g_hash_table_lookup(service_hash, service->identifier);
	if (iter == NULL)
		return -ENOENT;

	if (service->favorite == favorite)
		return -EALREADY;

	service->favorite = favorite;

	g_sequence_sort_changed(iter, service_compare, NULL);

	__connman_profile_changed(FALSE);

	return 0;
}

int __connman_service_set_carrier(struct connman_service *service,
						connman_bool_t carrier)
{
	DBG("service %p carrier %d", service, carrier);

	if (service == NULL)
		return -EINVAL;

	switch (service->type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_WIFI:
	case CONNMAN_SERVICE_TYPE_WIMAX:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		return -EINVAL;
	case CONNMAN_SERVICE_TYPE_ETHERNET:
		break;
	}

	if (carrier == FALSE) {
		service->state = CONNMAN_SERVICE_STATE_DISCONNECT;
		state_changed(service);

		service->state = CONNMAN_SERVICE_STATE_IDLE;
		state_changed(service);
	} else {
		service->state = CONNMAN_SERVICE_STATE_CARRIER;
		state_changed(service);
	}

	return connman_service_set_favorite(service, carrier);
}

int __connman_service_indicate_state(struct connman_service *service,
					enum connman_service_state state)
{
	GSequenceIter *iter;

	DBG("service %p state %d", service, state);

	if (service == NULL)
		return -EINVAL;

	if (state == CONNMAN_SERVICE_STATE_CARRIER)
		return __connman_service_set_carrier(service, TRUE);

	if (service->state == state)
		return -EALREADY;

	if (service->state == CONNMAN_SERVICE_STATE_FAILURE &&
				state == CONNMAN_SERVICE_STATE_IDLE)
		return -EINVAL;

	if (service->state == CONNMAN_SERVICE_STATE_IDLE &&
				state == CONNMAN_SERVICE_STATE_DISCONNECT)
		return -EINVAL;

	if (state == CONNMAN_SERVICE_STATE_IDLE &&
			service->state != CONNMAN_SERVICE_STATE_DISCONNECT) {
		service->state = CONNMAN_SERVICE_STATE_DISCONNECT;
		state_changed(service);

		__connman_service_disconnect(service);
	}

	service->state = state;
	state_changed(service);

	if (state == CONNMAN_SERVICE_STATE_READY) {
		connman_service_set_favorite(service, TRUE);

		reply_pending(service, 0);

		g_get_current_time(&service->modified);
		__connman_storage_save_service(service);
	}

	if (state == CONNMAN_SERVICE_STATE_FAILURE) {
		reply_pending(service, EIO);

		g_get_current_time(&service->modified);
		__connman_storage_save_service(service);
	} else
		service->error = CONNMAN_SERVICE_ERROR_UNKNOWN;

	iter = g_hash_table_lookup(service_hash, service->identifier);
	if (iter != NULL)
		g_sequence_sort_changed(iter, service_compare, NULL);

	__connman_profile_changed(FALSE);

	if (service->state == CONNMAN_SERVICE_STATE_IDLE ||
			service->state == CONNMAN_SERVICE_STATE_FAILURE)
		__connman_element_request_scan(CONNMAN_ELEMENT_TYPE_UNKNOWN);

	return 0;
}

int __connman_service_indicate_error(struct connman_service *service,
					enum connman_service_error error)
{
	DBG("service %p error %d", service, error);

	if (service == NULL)
		return -EINVAL;

	service->error = error;

	return __connman_service_indicate_state(service,
					CONNMAN_SERVICE_STATE_FAILURE);
}

int __connman_service_indicate_default(struct connman_service *service)
{
	DBG("service %p", service);

	return 0;
}

int __connman_service_connect(struct connman_service *service)
{
	int err;

	DBG("service %p", service);

	if (service->state == CONNMAN_SERVICE_STATE_READY)
		return -EISCONN;

	if (is_connecting(service) == TRUE)
		return -EALREADY;

	if (service->network != NULL) {
		unsigned int ssid_len;

		if (connman_network_get_blob(service->network, "WiFi.SSID",
						     &ssid_len) == NULL)
			return -EINVAL;

		connman_network_set_string(service->network,
				"WiFi.Passphrase", service->passphrase);

		err = __connman_network_connect(service->network);
	} else if (service->device != NULL) {
		if (service->favorite == FALSE)
			return -ENOLINK;

		err = __connman_device_connect(service->device);
	} else
		return -EOPNOTSUPP;

	if (err < 0) {
		if (err != -EINPROGRESS)
			return err;

		service->timeout = g_timeout_add_seconds(45,
						connect_timeout, service);

		return -EINPROGRESS;
	}

	return 0;
}

int __connman_service_disconnect(struct connman_service *service)
{
	int err;

	DBG("service %p", service);

	reply_pending(service, ECONNABORTED);

	if (service->network != NULL) {
		err = __connman_network_disconnect(service->network);
	} else if (service->device != NULL) {
		if (service->favorite == FALSE)
			return -ENOLINK;
		err = __connman_device_disconnect(service->device);
	} else
		return -EOPNOTSUPP;

	if (err < 0) {
		if (err != -EINPROGRESS)
			return err;

		return -EINPROGRESS;
	}

	return 0;
}

/**
 * __connman_service_lookup:
 * @identifier: service identifier
 *
 * Look up a service by identifier (reference count will not be increased)
 */
static struct connman_service *__connman_service_lookup(const char *identifier)
{
	GSequenceIter *iter;

	iter = g_hash_table_lookup(service_hash, identifier);
	if (iter != NULL)
		return g_sequence_get(iter);

	return NULL;
}

static struct connman_network *create_hidden_wifi(struct connman_device *device,
		const char *ssid, const char *mode, const char *security)
{
	struct connman_network *network;
	char *name;
	int index;
	unsigned int i, ssid_len;

	ssid_len = strlen(ssid);
	if (ssid_len < 1)
		return NULL;

	network = connman_network_create(NULL, CONNMAN_NETWORK_TYPE_WIFI);
	if (network == NULL)
		return NULL;

	connman_network_set_blob(network, "WiFi.SSID",
					(unsigned char *) ssid, ssid_len);

	connman_network_set_string(network, "WiFi.Mode", mode);
	connman_network_set_string(network, "WiFi.Security", security);

	name = g_try_malloc0(ssid_len + 1);
	if (name == NULL) {
		connman_network_unref(network);
		return NULL;
	}

	for (i = 0; i < ssid_len; i++) {
		if (g_ascii_isprint(ssid[i]))
			name[i] = ssid[i];
		else
			name[i] = ' ';
	}

	connman_network_set_name(network, name);

	g_free(name);

	index = connman_device_get_index(device);
	connman_network_set_index(network, index);

	connman_network_set_protocol(network, CONNMAN_NETWORK_PROTOCOL_IP);

	if (connman_device_add_network(device, network) < 0) {
		connman_network_unref(network);
		return NULL;
	}

	connman_network_set_available(network, TRUE);

	return network;
}

int __connman_service_create_and_connect(DBusMessage *msg)
{
	struct connman_service *service;
	struct connman_network *network;
	struct connman_device *device;
	DBusMessageIter iter, array;
	const char *mode = "managed", *security = "none";
	const char *type = NULL, *ssid = NULL, *passphrase = NULL;
	unsigned int ssid_len = 0;
	const char *ident;
	char *name, *group;
	gboolean created = FALSE;
	int err;

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_recurse(&iter, &array);

	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;

		dbus_message_iter_recurse(&array, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		switch (dbus_message_iter_get_arg_type(&value)) {
		case DBUS_TYPE_STRING:
			if (g_str_equal(key, "Type") == TRUE)
				dbus_message_iter_get_basic(&value, &type);
			else if (g_str_equal(key, "WiFi.Mode") == TRUE ||
					g_str_equal(key, "Mode") == TRUE)
				dbus_message_iter_get_basic(&value, &mode);
			else if (g_str_equal(key, "WiFi.Security") == TRUE ||
					g_str_equal(key, "Security") == TRUE)
				dbus_message_iter_get_basic(&value, &security);
			else if (g_str_equal(key, "WiFi.Passphrase") == TRUE ||
					g_str_equal(key, "Passphrase") == TRUE)
				dbus_message_iter_get_basic(&value, &passphrase);
			else if (g_str_equal(key, "WiFi.SSID") == TRUE ||
					g_str_equal(key, "SSID") == TRUE)
				dbus_message_iter_get_basic(&value, &ssid);
		}

		dbus_message_iter_next(&array);
	}

	if (type == NULL)
		return -EINVAL;

	if (g_strcmp0(type, "wifi") != 0 || g_strcmp0(mode, "managed") != 0)
		return -EOPNOTSUPP;

	if (ssid == NULL)
		return -EINVAL;

	ssid_len = strlen(ssid);
	if (ssid_len < 1)
		return -EINVAL;

	device = __connman_element_find_device(CONNMAN_DEVICE_TYPE_WIFI);
	if (device == NULL)
		return -EOPNOTSUPP;

	ident = __connman_device_get_ident(device);
	if (ident == NULL)
		return -EOPNOTSUPP;

	group = connman_wifi_build_group_name((unsigned char *) ssid,
						ssid_len, mode, security);
	if (group == NULL)
		return -EINVAL;

	name = g_strdup_printf("%s_%s_%s", type, ident, group);

	service = __connman_service_lookup(name);

	if (service != NULL)
		goto done;

	network = create_hidden_wifi(device, ssid, mode, security);
	if (network != NULL) {
		connman_network_set_group(network, group);
		created = TRUE;
	}

	service = __connman_service_lookup(name);

done:
	g_free(name);
	g_free(group);

	if (service == NULL) {
		err = -EOPNOTSUPP;
		goto failed;
	}

	__connman_device_disconnect(device);

	if (passphrase != NULL) {
		g_free(service->passphrase);
		service->passphrase = g_strdup(passphrase);
	}

	err = __connman_service_connect(service);
	if (err < 0 && err != -EINPROGRESS)
		goto failed;

	g_dbus_send_reply(connection, msg,
				DBUS_TYPE_OBJECT_PATH, &service->path,
							DBUS_TYPE_INVALID);

	return 0;

failed:
	if (service != NULL && created == TRUE) {
		struct connman_network *network = service->network;

		if (network != NULL) {
			connman_network_set_available(network, FALSE);
			__connman_device_cleanup_networks(device);
		}

		__connman_service_put(service);
	}

	return err;
}

/**
 * __connman_service_get:
 * @identifier: service identifier
 *
 * Look up a service by identifier or create a new one if not found
 */
static struct connman_service *__connman_service_get(const char *identifier)
{
	struct connman_service *service;
	GSequenceIter *iter;

	iter = g_hash_table_lookup(service_hash, identifier);
	if (iter != NULL) {
		service = g_sequence_get(iter);
		if (service != NULL)
			g_atomic_int_inc(&service->refcount);
		return service;
	}

	service = connman_service_create();
	if (service == NULL)
		return NULL;

	DBG("service %p", service);

	service->identifier = g_strdup(identifier);

	service->profile = g_strdup(__connman_profile_active_ident());

	__connman_storage_load_service(service);

	iter = g_sequence_insert_sorted(service_list, service,
						service_compare, NULL);

	g_hash_table_insert(service_hash, service->identifier, iter);

	return service;
}

static int service_register(struct connman_service *service)
{
	const char *path = __connman_profile_active_path();
	GSequenceIter *iter;

	DBG("service %p", service);

	if (service->path != NULL)
		return -EALREADY;

	service->path = g_strdup_printf("%s/%s", path, service->identifier);

	DBG("path %s", service->path);

	g_dbus_register_interface(connection, service->path,
					CONNMAN_SERVICE_INTERFACE,
					service_methods, service_signals,
							NULL, service, NULL);

	__connman_storage_load_service(service);

	iter = g_hash_table_lookup(service_hash, service->identifier);
	if (iter != NULL)
		g_sequence_sort_changed(iter, service_compare, NULL);

	__connman_profile_changed(TRUE);

	return 0;
}

/**
 * __connman_service_lookup_from_device:
 * @device: device structure
 *
 * Look up a service by device (reference count will not be increased)
 */
struct connman_service *__connman_service_lookup_from_device(struct connman_device *device)
{
	struct connman_service *service;
	const char *ident;
	char *name;

	ident = __connman_device_get_ident(device);
	if (ident == NULL)
		return NULL;

	name = g_strdup_printf("%s_%s",
				__connman_device_get_type(device), ident);

	service = __connman_service_lookup(name);

	g_free(name);

	return service;
}

static enum connman_service_type convert_device_type(struct connman_device *device)
{
	enum connman_device_type type = connman_device_get_type(device);

	switch (type) {
	case CONNMAN_DEVICE_TYPE_UNKNOWN:
	case CONNMAN_DEVICE_TYPE_VENDOR:
	case CONNMAN_DEVICE_TYPE_WIFI:
	case CONNMAN_DEVICE_TYPE_WIMAX:
	case CONNMAN_DEVICE_TYPE_BLUETOOTH:
	case CONNMAN_DEVICE_TYPE_GPS:
	case CONNMAN_DEVICE_TYPE_MBM:
	case CONNMAN_DEVICE_TYPE_HSO:
	case CONNMAN_DEVICE_TYPE_NOZOMI:
	case CONNMAN_DEVICE_TYPE_HUAWEI:
	case CONNMAN_DEVICE_TYPE_NOVATEL:
		break;
	case CONNMAN_DEVICE_TYPE_ETHERNET:
		return CONNMAN_SERVICE_TYPE_ETHERNET;
	}

	return CONNMAN_SERVICE_TYPE_UNKNOWN;
}

/**
 * __connman_service_create_from_device:
 * @device: device structure
 *
 * Look up service by device and if not found, create one
 */
struct connman_service *__connman_service_create_from_device(struct connman_device *device)
{
	struct connman_service *service;
	const char *ident;
	char *name;

	ident = __connman_device_get_ident(device);
	if (ident == NULL)
		return NULL;

	name = g_strdup_printf("%s_%s",
				__connman_device_get_type(device), ident);

	service = __connman_service_get(name);
	if (service == NULL)
		goto done;

	if (service->path != NULL) {
		__connman_service_put(service);
		service = NULL;
		goto done;
	}

	service->type = convert_device_type(device);

	service->device = device;

	service_register(service);

	if (service->favorite == TRUE)
		__connman_service_auto_connect();

done:
	g_free(name);

	return service;
}

void __connman_service_remove_from_device(struct connman_device *device)
{
	struct connman_service *service;

	service = __connman_service_lookup_from_device(device);
	if (service == NULL)
		return;

	__connman_service_put(service);
}

/**
 * __connman_service_lookup_from_network:
 * @network: network structure
 *
 * Look up a service by network (reference count will not be increased)
 */
struct connman_service *__connman_service_lookup_from_network(struct connman_network *network)
{
	struct connman_service *service;
	const char *ident, *group;
	char *name;

	ident = __connman_network_get_ident(network);
	if (ident == NULL)
		return NULL;

	group = connman_network_get_group(network);
	if (group == NULL)
		return NULL;

	name = g_strdup_printf("%s_%s_%s",
			__connman_network_get_type(network), ident, group);

	service = __connman_service_lookup(name);

	g_free(name);

	return service;
}

unsigned int __connman_service_get_order(struct connman_service *service)
{
	GSequenceIter *iter;

	if (service == NULL)
		return 0;

	if (service->favorite == FALSE) {
		service->order = 0;
		goto done;
	}

	iter = g_hash_table_lookup(service_hash, service->identifier);
	if (iter != NULL) {
		if (g_sequence_iter_get_position(iter) == 0)
			service->order = 1;
		else
			service->order = 0;
	}

done:
	return service->order;
}

static enum connman_service_type convert_network_type(struct connman_network *network)
{
	enum connman_network_type type = connman_network_get_type(network);

	switch (type) {
	case CONNMAN_NETWORK_TYPE_UNKNOWN:
	case CONNMAN_NETWORK_TYPE_VENDOR:
	case CONNMAN_NETWORK_TYPE_BLUETOOTH_PAN:
	case CONNMAN_NETWORK_TYPE_BLUETOOTH_DUN:
		break;
	case CONNMAN_NETWORK_TYPE_MBM:
	case CONNMAN_NETWORK_TYPE_HSO:
		return CONNMAN_SERVICE_TYPE_CELLULAR;
	case CONNMAN_NETWORK_TYPE_WIFI:
		return CONNMAN_SERVICE_TYPE_WIFI;
	case CONNMAN_NETWORK_TYPE_WIMAX:
		return CONNMAN_SERVICE_TYPE_WIMAX;
	}

	return CONNMAN_SERVICE_TYPE_UNKNOWN;
}

static enum connman_service_mode convert_wifi_mode(const char *mode)
{
	if (mode == NULL)
		return CONNMAN_SERVICE_MODE_UNKNOWN;
	else if (g_str_equal(mode, "managed") == TRUE)
		return CONNMAN_SERVICE_MODE_MANAGED;
	else if (g_str_equal(mode, "adhoc") == TRUE)
		return CONNMAN_SERVICE_MODE_ADHOC;
	else
		return CONNMAN_SERVICE_MODE_UNKNOWN;
}

static enum connman_service_mode convert_wifi_security(const char *security)
{
	if (security == NULL)
		return CONNMAN_SERVICE_SECURITY_UNKNOWN;
	else if (g_str_equal(security, "none") == TRUE)
		return CONNMAN_SERVICE_SECURITY_NONE;
	else if (g_str_equal(security, "wep") == TRUE)
		return CONNMAN_SERVICE_SECURITY_WEP;
	else if (g_str_equal(security, "wpa") == TRUE)
		return CONNMAN_SERVICE_SECURITY_WPA;
	else if (g_str_equal(security, "rsn") == TRUE)
		return CONNMAN_SERVICE_SECURITY_RSN;
	else
		return CONNMAN_SERVICE_SECURITY_UNKNOWN;
}

static void update_from_network(struct connman_service *service,
					struct connman_network *network)
{
	connman_uint8_t strength = service->strength;
	GSequenceIter *iter;
	const char *str;

	if (service->state == CONNMAN_SERVICE_STATE_READY)
		return;

	if (is_connecting(service) == TRUE)
		return;

	str = connman_network_get_string(network, "Name");
	if (str != NULL) {
		g_free(service->name);
		service->name = g_strdup(str);
		service->hidden = FALSE;
	} else {
		g_free(service->name);
		service->name = NULL;
		service->hidden = TRUE;
	}

	service->strength = connman_network_get_uint8(network, "Strength");

	str = connman_network_get_string(network, "WiFi.Mode");
	service->mode = convert_wifi_mode(str);

	str = connman_network_get_string(network, "WiFi.Security");
	service->security = convert_wifi_security(str);

	if (service->strength > strength && service->network != NULL) {
		connman_network_unref(service->network);
		service->network = connman_network_ref(network);

		strength_changed(service);
	}

	if (service->network == NULL)
		service->network = connman_network_ref(network);

	iter = g_hash_table_lookup(service_hash, service->identifier);
	if (iter != NULL)
		g_sequence_sort_changed(iter, service_compare, NULL);
}

/**
 * __connman_service_create_from_network:
 * @network: network structure
 *
 * Look up service by network and if not found, create one
 */
struct connman_service *__connman_service_create_from_network(struct connman_network *network)
{
	struct connman_service *service;
	const char *ident, *group;
	char *name;

	service = __connman_service_lookup_from_network(network);
	if (service != NULL) {
		if (g_atomic_int_get(&service->refcount) == 0) {
			if (service->timeout > 0) {
				g_source_remove(service->timeout);
				service->timeout = 0;
			}

			set_idle(service);
		}

		connman_service_ref(service);

		update_from_network(service, network);
		return service;
	}

	ident = __connman_network_get_ident(network);
	if (ident == NULL)
		return NULL;

	group = connman_network_get_group(network);
	if (group == NULL)
		return NULL;

	if (__connman_network_get_weakness(network) == TRUE)
		return NULL;

	name = g_strdup_printf("%s_%s_%s",
			__connman_network_get_type(network), ident, group);

	service = __connman_service_get(name);
	if (service == NULL)
		goto done;

	if (service->path != NULL) {
		update_from_network(service, network);

		__connman_profile_changed(TRUE);

		__connman_service_put(service);
		service = NULL;
		goto done;
	}

	service->type = convert_network_type(network);

	service->state = CONNMAN_SERVICE_STATE_IDLE;

	update_from_network(service, network);

	service_register(service);

	if (service->favorite == TRUE)
		__connman_service_auto_connect();

done:
	g_free(name);

	return service;
}

void __connman_service_remove_from_network(struct connman_network *network)
{
	struct connman_service *service;

	service = __connman_service_lookup_from_network(network);
	if (service == NULL)
		return;

	__connman_service_put(service);
}

static int service_load(struct connman_service *service)
{
	GKeyFile *keyfile;
	gchar *pathname, *data = NULL;
	gsize length;
	gchar *str;
	unsigned int ssid_len;
	int err = 0;

	DBG("service %p", service);

	if (service->profile == NULL)
		return -EINVAL;

	pathname = g_strdup_printf("%s/%s.conf", STORAGEDIR, service->profile);
	if (pathname == NULL)
		return -ENOMEM;

	keyfile = g_key_file_new();

	if (g_file_get_contents(pathname, &data, &length, NULL) == FALSE) {
		g_free(pathname);
		return -ENOENT;
	}

	g_free(pathname);

	if (g_key_file_load_from_data(keyfile, data, length,
							0, NULL) == FALSE) {
		g_free(data);
		return -EILSEQ;
	}

	g_free(data);

	switch (service->type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_ETHERNET:
		break;
	case CONNMAN_SERVICE_TYPE_WIFI:
		if (service->name == NULL) {
			gchar *name;

			name = g_key_file_get_string(keyfile,
					service->identifier, "Name", NULL);
			if (name != NULL) {
				g_free(service->name);
				service->name = name;
			}

			if (service->network != NULL)
				connman_network_set_name(service->network,
									name);
		}

		if (service->network &&
				connman_network_get_blob(service->network,
					"WiFi.SSID", &ssid_len) == NULL) {
			gchar *hex_ssid;

			hex_ssid = g_key_file_get_string(keyfile,
							service->identifier,
								"SSID", NULL);

			if (hex_ssid != NULL) {
				gchar *ssid;
				unsigned int i, j = 0, hex;
				size_t hex_ssid_len = strlen(hex_ssid);

				ssid = g_try_malloc0(hex_ssid_len / 2);
				if (ssid == NULL) {
					g_free(hex_ssid);
					err = -ENOMEM;
					goto done;
				}

				for (i = 0; i < hex_ssid_len; i += 2) {
					sscanf(hex_ssid + i, "%02x", &hex);
					ssid[j++] = hex;
				}

				connman_network_set_blob(service->network,
					"WiFi.SSID", ssid, hex_ssid_len / 2);
			}

			g_free(hex_ssid);
		}
		/* fall through */

	case CONNMAN_SERVICE_TYPE_WIMAX:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		service->favorite = g_key_file_get_boolean(keyfile,
				service->identifier, "Favorite", NULL);

		str = g_key_file_get_string(keyfile,
				service->identifier, "Failure", NULL);
		if (str != NULL) {
			service->state = CONNMAN_SERVICE_STATE_FAILURE;
			service->error = string2error(str);
		}
		break;
	}

	str = g_key_file_get_string(keyfile,
				service->identifier, "Modified", NULL);
	if (str != NULL) {
		g_time_val_from_iso8601(str, &service->modified);
		g_free(str);
	}

	str = g_key_file_get_string(keyfile,
				service->identifier, "Passphrase", NULL);
	if (str != NULL) {
		g_free(service->passphrase);
		service->passphrase = str;
	}

	__connman_ipconfig_load(service->ipconfig, keyfile,
					service->identifier, "IPv4.");

done:
	g_key_file_free(keyfile);

	return err;
}

static int service_save(struct connman_service *service)
{
	GKeyFile *keyfile;
	gchar *pathname, *data = NULL;
	gsize length;
	gchar *str;
	int err = 0;

	DBG("service %p", service);

	if (service->profile == NULL)
		return -EINVAL;

	pathname = g_strdup_printf("%s/%s.conf", STORAGEDIR, service->profile);
	if (pathname == NULL)
		return -ENOMEM;

	keyfile = g_key_file_new();

	if (g_file_get_contents(pathname, &data, &length, NULL) == FALSE)
		goto update;

	if (length > 0) {
		if (g_key_file_load_from_data(keyfile, data, length,
							0, NULL) == FALSE)
			goto done;
	}

	g_free(data);

update:
	if (service->name != NULL)
		g_key_file_set_string(keyfile, service->identifier,
						"Name", service->name);

	switch (service->type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_ETHERNET:
		break;
	case CONNMAN_SERVICE_TYPE_WIFI:
		if (service->network) {
			const unsigned char *ssid;
			unsigned int ssid_len = 0;

			ssid = connman_network_get_blob(service->network,
							"WiFi.SSID", &ssid_len);

			if (ssid != NULL && ssid_len > 0 && ssid[0] != '\0') {
				char *identifier = service->identifier;
				GString *str;
				unsigned int i;

				str = g_string_sized_new(ssid_len * 2);
				if (str == NULL) {
					err = -ENOMEM;
					goto done;
				}

				for (i = 0; i < ssid_len; i++)
					g_string_append_printf(str,
							"%02x", ssid[i]);

				g_key_file_set_string(keyfile, identifier,
							"SSID", str->str);

				g_string_free(str, TRUE);
			}
		}
		/* fall through */

	case CONNMAN_SERVICE_TYPE_WIMAX:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		g_key_file_set_boolean(keyfile, service->identifier,
					"Favorite", service->favorite);

		if (service->state == CONNMAN_SERVICE_STATE_FAILURE) {
			const char *failure = error2string(service->error);
			if (failure != NULL)
				g_key_file_set_string(keyfile,
							service->identifier,
							"Failure", failure);
		} else {
			g_key_file_remove_key(keyfile, service->identifier,
							"Failure", NULL);
		}
		break;
	}

	str = g_time_val_to_iso8601(&service->modified);
	if (str != NULL) {
		g_key_file_set_string(keyfile, service->identifier,
							"Modified", str);
		g_free(str);
	}

	if (service->passphrase != NULL && strlen(service->passphrase) > 0)
		g_key_file_set_string(keyfile, service->identifier,
					"Passphrase", service->passphrase);
	else
		g_key_file_remove_key(keyfile, service->identifier,
							"Passphrase", NULL);

	__connman_ipconfig_save(service->ipconfig, keyfile,
					service->identifier, "IPv4.");

	data = g_key_file_to_data(keyfile, &length, NULL);

	if (g_file_set_contents(pathname, data, length, NULL) == FALSE)
		connman_error("Failed to store service information");

done:
	g_free(data);

	g_key_file_free(keyfile);

	g_free(pathname);

	return err;
}

static struct connman_storage service_storage = {
	.name		= "service",
	.priority	= CONNMAN_STORAGE_PRIORITY_LOW,
	.service_load	= service_load,
	.service_save	= service_save,
};

int __connman_service_init(void)
{
	DBG("");

	connection = connman_dbus_get_connection();

	if (connman_storage_register(&service_storage) < 0)
		connman_error("Failed to register service storage");

	service_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
								NULL, NULL);

	service_list = g_sequence_new(service_free);

	return 0;
}

void __connman_service_cleanup(void)
{
	DBG("");

	g_sequence_free(service_list);
	service_list = NULL;

	g_hash_table_destroy(service_hash);
	service_hash = NULL;

	connman_storage_unregister(&service_storage);

	dbus_connection_unref(connection);
}
