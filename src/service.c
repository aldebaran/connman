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
	connman_uint8_t strength;
	connman_bool_t favorite;
	unsigned int order;
	char *name;
	struct connman_device *device;
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
	case CONNMAN_SERVICE_SECURITY_WPA2:
		return "wpa2";
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

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_service *service = data;
	DBusMessage *reply;
	DBusMessageIter array, dict;
	const char *str;

	DBG("conn %p", conn);

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

	if (service->strength > 0)
		connman_dbus_dict_append_variant(&dict, "Strength",
					DBUS_TYPE_BYTE, &service->strength);

	connman_dbus_dict_append_variant(&dict, "Favorite",
					DBUS_TYPE_BOOLEAN, &service->favorite);

	if (service->name != NULL)
		connman_dbus_dict_append_variant(&dict, "Name",
					DBUS_TYPE_STRING, &service->name);

	dbus_message_iter_close_container(&array, &dict);

	return reply;
}

static DBusMessage *connect_service(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_service *service = data;

	if (service->device != NULL) {
		if (__connman_device_connect(service->device) < 0)
			return __connman_error_failed(msg);

		service->state = CONNMAN_SERVICE_STATE_READY;

		state_changed(service);
	}

	return __connman_error_not_supported(msg);
}

static DBusMessage *disconnect_service(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_service *service = data;

	if (service->device != NULL) {
		if (__connman_device_connect(service->device) < 0)
			return __connman_error_failed(msg);

		service->state = CONNMAN_SERVICE_STATE_IDLE;

		state_changed(service);
	}

	return __connman_error_not_supported(msg);
}

static DBusMessage *remove_service(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_service *service = data;

	if (service->type == CONNMAN_SERVICE_TYPE_ETHERNET)
		return __connman_error_not_supported(msg);

	connman_service_set_favorite(service, FALSE);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *move_before(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_service *service = data;

	if (service->favorite == FALSE)
		return __connman_error_not_supported(msg);

	return __connman_error_not_implemented(msg);
}

static DBusMessage *move_after(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_service *service = data;

	if (service->favorite == FALSE)
		return __connman_error_not_supported(msg);

	return __connman_error_not_implemented(msg);
}

static GDBusMethodTable service_methods[] = {
	{ "GetProperties", "",  "a{sv}", get_properties     },
	{ "Connect",       "",  "",      connect_service    },
	{ "Disconnect",    "",  "",      disconnect_service },
	{ "Remove",        "",  "",      remove_service     },
	{ "MoveBefore",    "o", "",      move_before        },
	{ "MoveAfter",     "o", "",      move_after         },
	{ },
};

static GDBusSignalTable service_signals[] = {
	{ "PropertyChanged", "sv" },
	{ },
};

static void service_free(gpointer data)
{
	struct connman_service *service = data;
	char *path = service->path;

	DBG("service %p", service);

	g_hash_table_remove(service_hash, service->identifier);

	service->path = NULL;

	if (path != NULL) {
		__connman_profile_changed();

		g_dbus_unregister_interface(connection, path,
						CONNMAN_SERVICE_INTERFACE);
		g_free(path);
	}

	g_free(service->name);
	g_free(service->identifier);
	g_free(service);
}

/**
 * connman_service_put:
 * @service: service structure
 *
 * Release service if no longer needed
 */
void connman_service_put(struct connman_service *service)
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
	connman_service_put(service);
}

static gint service_compare(gconstpointer a, gconstpointer b,
							gpointer user_data)
{
	struct connman_service *service_a = (void *) a;
	struct connman_service *service_b = (void *) b;

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

	if (service->favorite)
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
		return -EINVAL;
	case CONNMAN_SERVICE_TYPE_ETHERNET:
		break;
	}

	if (carrier == TRUE)
		service->state = CONNMAN_SERVICE_STATE_CARRIER;
	else
		service->state = CONNMAN_SERVICE_STATE_IDLE;

	state_changed(service);

	return connman_service_set_favorite(service, carrier);
}

int __connman_service_indicate_configuration(struct connman_service *service)
{
	DBG("service %p", service);

	if (service == NULL)
		return -EINVAL;

	service->state = CONNMAN_SERVICE_STATE_CONFIGURATION;

	state_changed(service);

	return 0;
}

int __connman_service_ready(struct connman_service *service)
{
	DBG("service %p", service);

	if (service == NULL)
		return -EINVAL;

	service->state = CONNMAN_SERVICE_STATE_READY;

	state_changed(service);

	return 0;
}

int __connman_service_disconnect(struct connman_service *service)
{
	DBG("service %p", service);

	if (service == NULL)
		return -EINVAL;

	service->state = CONNMAN_SERVICE_STATE_DISCONNECT;

	state_changed(service);

	return 0;
}

/**
 * connman_service_lookup:
 * @identifier: service identifier
 *
 * Look up a service by identifier (reference count will not be increased)
 */
struct connman_service *connman_service_lookup(const char *identifier)
{
	GSequenceIter *iter;

	iter = g_hash_table_lookup(service_hash, identifier);
	if (iter != NULL)
		return g_sequence_get(iter);

	return NULL;
}

/**
 * connman_service_get:
 * @identifier: service identifier
 *
 * Look up a service by identifier or create a new one if not found
 */
struct connman_service *connman_service_get(const char *identifier)
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

	service = g_try_new0(struct connman_service, 1);
	if (service == NULL)
		return NULL;

	DBG("service %p", service);

	__connman_service_initialize(service);

	service->identifier = g_strdup(identifier);

	iter = g_sequence_insert_sorted(service_list, service,
						service_compare, NULL);

	g_hash_table_insert(service_hash, service->identifier, iter);

	return service;
}

static int service_register(struct connman_service *service)
{
	const char *path = __connman_profile_active();

	DBG("service %p", service);

	if (service->path != NULL)
		return -EALREADY;

	service->path = g_strdup_printf("%s/%s", path, service->identifier);

	DBG("path %s", service->path);

	g_dbus_register_interface(connection, service->path,
					CONNMAN_SERVICE_INTERFACE,
					service_methods, service_signals,
							NULL, service, NULL);

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
	char *name;

	name = g_strdup_printf("%s_%d", __connman_device_get_type(device),
					connman_device_get_index(device));

	service = connman_service_lookup(name);

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
	char *name;

	name = g_strdup_printf("%s_%d", __connman_device_get_type(device),
					connman_device_get_index(device));

	service = connman_service_get(name);
	if (service == NULL)
		goto done;

	if (service->path != NULL) {
		connman_service_put(service);
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
 * @device: device structure
 *
 * Look up a service by network (reference count will not be increased)
 */
struct connman_service *__connman_service_lookup_from_network(struct connman_network *network)
{
	struct connman_service *service;
	const char *group;
	char *name;

	group = __connman_network_get_group(network);
	if (group == NULL)
		return NULL;

	name = g_strdup_printf("%s_%s",
				__connman_network_get_type(network), group);

	service = connman_service_lookup(name);

	g_free(name);

	return service;
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

/**
 * connman_service_create_from_network:
 * @device: device structure
 *
 * Look up service by network and if not found, create one
 */
struct connman_service *__connman_service_create_from_network(struct connman_network *network)
{
	struct connman_service *service;
	const char *group;
	char *name;

	group = __connman_network_get_group(network);
	if (group == NULL)
		return NULL;

	name = g_strdup_printf("%s_%s",
				__connman_network_get_type(network), group);

	service = connman_service_get(name);
	if (service == NULL)
		goto done;

	if (service->path != NULL) {
		connman_service_put(service);
		service = NULL;
		goto done;
	}

	service->type = convert_network_type(network);

	service_register(service);

done:
	g_free(name);

	return service;
}

int __connman_service_init(void)
{
	DBG("");

	connection = connman_dbus_get_connection();

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

	dbus_connection_unref(connection);
}
