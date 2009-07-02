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
	case CONNMAN_SERVICE_ERROR_DHCP_FAILED:
		return "dhcp-failed";
	}

	return NULL;
}

static enum connman_service_error string2error(const char *error)
{
	if (g_strcmp0(error, "dhcp-failed") == 0)
		return CONNMAN_SERVICE_ERROR_DHCP_FAILED;

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
		service->state = CONNMAN_SERVICE_STATE_IDLE;
		service->error = CONNMAN_SERVICE_ERROR_UNKNOWN;
		state_changed(service);

		g_get_current_time(&service->modified);
		__connman_storage_save_service(service);
	} else
		return __connman_error_invalid_property(msg);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static gboolean connect_timeout(gpointer user_data)
{
	struct connman_service *service = user_data;

	DBG("service %p", service);

	service->timeout = 0;

	if (service->network != NULL)
		__connman_network_disconnect(service->network);

	if (service->pending != NULL) {
		DBusMessage *reply;

		reply = __connman_error_operation_timeout(service->pending);
		if (reply != NULL)
			g_dbus_send_message(connection, reply);

		dbus_message_unref(service->pending);
		service->pending = NULL;

		__connman_service_indicate_state(service,
					CONNMAN_SERVICE_STATE_FAILURE);
	}

	return FALSE;
}

static DBusMessage *connect_service(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_service *service = user_data;

	DBG("service %p", service);

	if (service->pending != NULL)
		return __connman_error_in_progress(msg);

	if (service->state == CONNMAN_SERVICE_STATE_READY)
		return __connman_error_already_connected(msg);

	if (service->network != NULL) {
		int err;

		if (service->hidden == TRUE)
			return __connman_error_invalid_service(msg);

		connman_network_set_string(service->network,
				"WiFi.Passphrase", service->passphrase);

		err = __connman_network_connect(service->network);
		if (err < 0) {
			if (err != -EINPROGRESS)
				return __connman_error_failed(msg, -err);

			service->pending = dbus_message_ref(msg);

			service->timeout = g_timeout_add_seconds(45,
						connect_timeout, service);

			return NULL;
		}
	} else if (service->device != NULL) {
		if (service->favorite == FALSE)
			return __connman_error_no_carrier(msg);

		if (__connman_device_connect(service->device) < 0)
			return __connman_error_failed(msg, EINVAL);

		service->pending = dbus_message_ref(msg);
		service->timeout = g_timeout_add_seconds(15,
						connect_timeout, service);

		return NULL;
	} else
		return __connman_error_not_supported(msg);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *disconnect_service(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_service *service = user_data;

	DBG("service %p", service);

	if (service->pending != NULL) {
		DBusMessage *reply;

		reply = __connman_error_operation_aborted(service->pending);
		if (reply != NULL)
			g_dbus_send_message(conn, reply);

		dbus_message_unref(service->pending);
		service->pending = NULL;

		return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
	}

	if (service->network != NULL) {
		int err;

		err = __connman_network_disconnect(service->network);
		if (err < 0 && err != -EINPROGRESS)
			return __connman_error_failed(msg, -err);
	} else if (service->device != NULL) {
		int err;

		if (service->favorite == FALSE)
			return __connman_error_no_carrier(msg);

		err = __connman_device_disconnect(service->device);
		if (err < 0)
			return __connman_error_failed(msg, -err);
	} else
		return __connman_error_not_supported(msg);

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

	g_free (service->passphrase);
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

#if 0
	g_sequence_move(src, dst);

	__connman_profile_changed();

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
#endif
	return __connman_error_not_implemented(msg);
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

	g_hash_table_remove(service_hash, service->identifier);

	if (service->timeout > 0) {
		g_source_remove(service->timeout);
		service->timeout = 0;
	}

	if (service->pending != NULL) {
		dbus_message_unref(service->pending);
		service->pending = NULL;
	}

	service->path = NULL;

	if (path != NULL) {
		__connman_profile_changed();

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
		if (iter != NULL)
			g_sequence_remove(iter);
		else
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

	__connman_profile_changed();

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

	if (service->state == CONNMAN_SERVICE_STATE_IDLE &&
				state == CONNMAN_SERVICE_STATE_DISCONNECT)
		return -EINVAL;

	if (state == CONNMAN_SERVICE_STATE_IDLE &&
			service->state != CONNMAN_SERVICE_STATE_DISCONNECT) {
		service->state = CONNMAN_SERVICE_STATE_DISCONNECT;
		state_changed(service);
	}

	service->state = state;
	state_changed(service);

	if (state == CONNMAN_SERVICE_STATE_READY) {
		connman_service_set_favorite(service, TRUE);

		if (service->timeout > 0) {
			g_source_remove(service->timeout);
			service->timeout = 0;
		}

		if (service->pending != NULL) {
			g_dbus_send_reply(connection, service->pending,
							DBUS_TYPE_INVALID);

			dbus_message_unref(service->pending);
			service->pending = NULL;
		}

		g_get_current_time(&service->modified);
		__connman_storage_save_service(service);
	}

	if (state == CONNMAN_SERVICE_STATE_FAILURE) {
		if (service->timeout > 0) {
			g_source_remove(service->timeout);
			service->timeout = 0;
		}

		if (service->pending != NULL) {
			DBusMessage *reply;

			reply = __connman_error_failed(service->pending, EIO);
			if (reply != NULL)
				g_dbus_send_message(connection, reply);

			dbus_message_unref(service->pending);
			service->pending = NULL;
		}

		g_get_current_time(&service->modified);
		__connman_storage_save_service(service);
	} else
		service->error = CONNMAN_SERVICE_ERROR_UNKNOWN;

	iter = g_hash_table_lookup(service_hash, service->identifier);
	if (iter != NULL)
		g_sequence_sort_changed(iter, service_compare, NULL);

	__connman_profile_changed();

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

	__connman_profile_changed();

	return 0;
}

/**
 * connman_service_lookup_from_device:
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
 * connman_service_create_from_device:
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

done:
	g_free(name);

	return service;
}

/**
 * connman_service_lookup_from_network:
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

	group = __connman_network_get_group(network);
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
	case CONNMAN_NETWORK_TYPE_HSO:
		break;
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
		service->network = NULL;

		strength_changed(service);
	}

	if (service->network == NULL) {
		service->network = connman_network_ref(network);

		str = connman_network_get_string(network, "WiFi.Passphrase");
		if (str != NULL) {
			g_free(service->passphrase);
			service->passphrase = g_strdup(str);
		}
	}

	iter = g_hash_table_lookup(service_hash, service->identifier);
	if (iter != NULL)
		g_sequence_sort_changed(iter, service_compare, NULL);
}

/**
 * connman_service_create_from_network:
 * @network: network structure
 *
 * Look up service by network and if not found, create one
 */
struct connman_service *__connman_service_create_from_network(struct connman_network *network)
{
	struct connman_service *service;
	const char *ident, *group;
	char *name;

	if (__connman_service_lookup_from_network(network) != NULL) {
		connman_error("Service already exists");
		return NULL;
	}

	ident = __connman_network_get_ident(network);
	if (ident == NULL)
		return NULL;

	group = __connman_network_get_group(network);
	if (group == NULL)
		return NULL;

	name = g_strdup_printf("%s_%s_%s",
			__connman_network_get_type(network), ident, group);

	service = __connman_service_get(name);
	if (service == NULL)
		goto done;

	if (service->path != NULL) {
		update_from_network(service, network);

		__connman_profile_changed();

		__connman_service_put(service);
		service = NULL;
		goto done;
	}

	service->type = convert_network_type(network);

	service->state = CONNMAN_SERVICE_STATE_IDLE;

	update_from_network(service, network);

	service_register(service);

done:
	g_free(name);

	return service;
}

static int service_load(struct connman_service *service)
{
	GKeyFile *keyfile;
	gchar *pathname, *data = NULL;
	gsize length;
	gchar *str;

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

	g_key_file_free(keyfile);

	return 0;
}

static int service_save(struct connman_service *service)
{
	GKeyFile *keyfile;
	gchar *pathname, *data = NULL;
	gsize length;
	gchar *str;

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

	if (service->passphrase != NULL)
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

	return 0;
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
