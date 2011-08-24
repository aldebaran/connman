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

#include <errno.h>
#include <string.h>

#include <gdbus.h>

#include "connman.h"

static DBusConnection *connection;

static GSList *technology_list = NULL;

struct connman_rfkill {
	unsigned int index;
	enum connman_service_type type;
	connman_bool_t softblock;
	connman_bool_t hardblock;
};

enum connman_technology_state {
	CONNMAN_TECHNOLOGY_STATE_UNKNOWN   = 0,
	CONNMAN_TECHNOLOGY_STATE_OFFLINE   = 1,
	CONNMAN_TECHNOLOGY_STATE_ENABLED   = 2,
	CONNMAN_TECHNOLOGY_STATE_CONNECTED = 3,
};

struct connman_technology {
	gint refcount;
	enum connman_service_type type;
	enum connman_technology_state state;
	char *path;
	GHashTable *rfkill_list;
	GSList *device_list;
	gint enabled;
	gint blocked;
	char *regdom;

	connman_bool_t tethering;
	char *tethering_ident;
	char *tethering_passphrase;

	connman_bool_t enable_persistent; /* Save the tech state */

	struct connman_technology_driver *driver;
	void *driver_data;

	DBusMessage *pending_reply;
	guint pending_timeout;
};

static GSList *driver_list = NULL;

static gint compare_priority(gconstpointer a, gconstpointer b)
{
	const struct connman_technology_driver *driver1 = a;
	const struct connman_technology_driver *driver2 = b;

	return driver2->priority - driver1->priority;
}

/**
 * connman_technology_driver_register:
 * @driver: Technology driver definition
 *
 * Register a new technology driver
 *
 * Returns: %0 on success
 */
int connman_technology_driver_register(struct connman_technology_driver *driver)
{
	GSList *list;
	struct connman_technology *technology;

	DBG("driver %p name %s", driver, driver->name);

	driver_list = g_slist_insert_sorted(driver_list, driver,
							compare_priority);

	for (list = technology_list; list; list = list->next) {
		technology = list->data;

		if (technology->driver != NULL)
			continue;

		if (technology->type == driver->type)
			technology->driver = driver;
	}

	return 0;
}

/**
 * connman_technology_driver_unregister:
 * @driver: Technology driver definition
 *
 * Remove a previously registered technology driver
 */
void connman_technology_driver_unregister(struct connman_technology_driver *driver)
{
	GSList *list;
	struct connman_technology *technology;

	DBG("driver %p name %s", driver, driver->name);

	for (list = technology_list; list; list = list->next) {
		technology = list->data;

		if (technology->driver == NULL)
			continue;

		if (technology->type == driver->type) {
			technology->driver->remove(technology);
			technology->driver = NULL;
		}
	}

	driver_list = g_slist_remove(driver_list, driver);
}

static void tethering_changed(struct connman_technology *technology)
{
	connman_bool_t tethering = technology->tethering;

	connman_dbus_property_changed_basic(technology->path,
				CONNMAN_TECHNOLOGY_INTERFACE, "Tethering",
						DBUS_TYPE_BOOLEAN, &tethering);
}

void connman_technology_tethering_notify(struct connman_technology *technology,
							connman_bool_t enabled)
{
	DBG("technology %p enabled %u", technology, enabled);

	if (technology->tethering == enabled)
		return;

	technology->tethering = enabled;

	tethering_changed(technology);

	if (enabled == TRUE)
		__connman_tethering_set_enabled();
	else
		__connman_tethering_set_disabled();
}

static int set_tethering(struct connman_technology *technology,
				const char *bridge, connman_bool_t enabled)
{
	const char *ident, *passphrase;

	ident = technology->tethering_ident;
	passphrase = technology->tethering_passphrase;

	if (technology->driver == NULL ||
			technology->driver->set_tethering == NULL)
		return -EOPNOTSUPP;

	if (technology->type == CONNMAN_SERVICE_TYPE_WIFI &&
	    (ident == NULL || passphrase == NULL))
		return -EINVAL;

	return technology->driver->set_tethering(technology, ident, passphrase,
							bridge, enabled);
}

void connman_technology_regdom_notify(struct connman_technology *technology,
							const char *alpha2)
{
	DBG("");

	if (alpha2 == NULL)
		connman_error("Failed to set regulatory domain");
	else
		DBG("Regulatory domain set to %s", alpha2);

	g_free(technology->regdom);
	technology->regdom = g_strdup(alpha2);
}

int connman_technology_set_regdom(const char *alpha2)
{
	GSList *list;

	for (list = technology_list; list; list = list->next) {
		struct connman_technology *technology = list->data;

		if (technology->driver == NULL)
			continue;

		if (technology->driver->set_regdom)
			technology->driver->set_regdom(technology, alpha2);
	}

	return 0;
}

static void free_rfkill(gpointer data)
{
	struct connman_rfkill *rfkill = data;

	g_free(rfkill);
}

void __connman_technology_list(DBusMessageIter *iter, void *user_data)
{
	GSList *list;

	for (list = technology_list; list; list = list->next) {
		struct connman_technology *technology = list->data;

		if (technology->path == NULL)
			continue;

		dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH,
							&technology->path);
	}
}

static void technologies_changed(void)
{
	connman_dbus_property_changed_array(CONNMAN_MANAGER_PATH,
			CONNMAN_MANAGER_INTERFACE, "Technologies",
			DBUS_TYPE_OBJECT_PATH, __connman_technology_list, NULL);
}

static const char *state2string(enum connman_technology_state state)
{
	switch (state) {
	case CONNMAN_TECHNOLOGY_STATE_UNKNOWN:
		break;
	case CONNMAN_TECHNOLOGY_STATE_OFFLINE:
		return "offline";
	case CONNMAN_TECHNOLOGY_STATE_ENABLED:
		return "enabled";
	case CONNMAN_TECHNOLOGY_STATE_CONNECTED:
		return "connected";
	}

	return NULL;
}

static void state_changed(struct connman_technology *technology)
{
	const char *str;

	str = state2string(technology->state);
	if (str == NULL)
		return;

	connman_dbus_property_changed_basic(technology->path,
				CONNMAN_TECHNOLOGY_INTERFACE, "State",
						DBUS_TYPE_STRING, &str);
}

static const char *get_name(enum connman_service_type type)
{
	switch (type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_VPN:
	case CONNMAN_SERVICE_TYPE_GADGET:
		break;
	case CONNMAN_SERVICE_TYPE_ETHERNET:
		return "Wired";
	case CONNMAN_SERVICE_TYPE_WIFI:
		return "WiFi";
	case CONNMAN_SERVICE_TYPE_WIMAX:
		return "WiMAX";
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
		return "Bluetooth";
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		return "3G";
	}

	return NULL;
}

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *message, void *user_data)
{
	struct connman_technology *technology = user_data;
	DBusMessage *reply;
	DBusMessageIter array, dict;
	const char *str;

	reply = dbus_message_new_method_return(message);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &array);

	connman_dbus_dict_open(&array, &dict);

	str = state2string(technology->state);
	if (str != NULL)
		connman_dbus_dict_append_basic(&dict, "State",
						DBUS_TYPE_STRING, &str);

	str = get_name(technology->type);
	if (str != NULL)
		connman_dbus_dict_append_basic(&dict, "Name",
						DBUS_TYPE_STRING, &str);

	str = __connman_service_type2string(technology->type);
	if (str != NULL)
		connman_dbus_dict_append_basic(&dict, "Type",
						DBUS_TYPE_STRING, &str);

	connman_dbus_dict_append_basic(&dict, "Tethering",
					DBUS_TYPE_BOOLEAN,
					&technology->tethering);

	if (technology->tethering_ident != NULL)
		connman_dbus_dict_append_basic(&dict, "TetheringIdentifier",
						DBUS_TYPE_STRING,
						&technology->tethering_ident);

	if (technology->tethering_passphrase != NULL)
		connman_dbus_dict_append_basic(&dict, "TetheringPassphrase",
						DBUS_TYPE_STRING,
						&technology->tethering_passphrase);

	connman_dbus_dict_close(&array, &dict);

	return reply;
}

static DBusMessage *set_property(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_technology *technology = data;
	DBusMessageIter iter, value;
	const char *name;
	int type;

	DBG("conn %p", conn);

	if (dbus_message_iter_init(msg, &iter) == FALSE)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &name);
	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &value);

	type = dbus_message_iter_get_arg_type(&value);

	DBG("property %s", name);

	if (g_str_equal(name, "Tethering") == TRUE) {
		int err;
		connman_bool_t tethering;
		const char *bridge;

		if (type != DBUS_TYPE_BOOLEAN)
			return __connman_error_invalid_arguments(msg);

		dbus_message_iter_get_basic(&value, &tethering);

		if (technology->tethering == tethering)
			return __connman_error_in_progress(msg);

		bridge = __connman_tethering_get_bridge();
		if (bridge == NULL)
			return __connman_error_not_supported(msg);

		err = set_tethering(technology, bridge, tethering);
		if (err < 0)
			return __connman_error_failed(msg, -err);

	} else if (g_str_equal(name, "TetheringIdentifier") == TRUE) {
		const char *str;

		dbus_message_iter_get_basic(&value, &str);

		if (technology->type != CONNMAN_SERVICE_TYPE_WIFI)
			return __connman_error_not_supported(msg);

		technology->tethering_ident = g_strdup(str);
	} else if (g_str_equal(name, "TetheringPassphrase") == TRUE) {
		const char *str;

		dbus_message_iter_get_basic(&value, &str);

		if (technology->type != CONNMAN_SERVICE_TYPE_WIFI)
			return __connman_error_not_supported(msg);

		if (strlen(str) < 8)
			return __connman_error_invalid_arguments(msg);

		technology->tethering_passphrase = g_strdup(str);
	} else
		return __connman_error_invalid_property(msg);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static GDBusMethodTable technology_methods[] = {
	{ "GetProperties", "",   "a{sv}", get_properties },
	{ "SetProperty",   "sv", "",      set_property   },
	{ },
};

static GDBusSignalTable technology_signals[] = {
	{ "PropertyChanged", "sv" },
	{ },
};

static struct connman_technology *technology_find(enum connman_service_type type)
{
	GSList *list;

	DBG("type %d", type);

	for (list = technology_list; list; list = list->next) {
		struct connman_technology *technology = list->data;

		if (technology->type == type)
			return technology;
	}

	return NULL;
}

static struct connman_technology *technology_get(enum connman_service_type type)
{
	struct connman_technology *technology;
	const char *str;
	GSList *list;

	DBG("type %d", type);

	technology = technology_find(type);
	if (technology != NULL) {
		g_atomic_int_inc(&technology->refcount);
		goto done;
	}

	str = __connman_service_type2string(type);
	if (str == NULL)
		return NULL;

	technology = g_try_new0(struct connman_technology, 1);
	if (technology == NULL)
		return NULL;

	technology->refcount = 1;

	technology->type = type;
	technology->path = g_strdup_printf("%s/technology/%s",
							CONNMAN_PATH, str);

	technology->rfkill_list = g_hash_table_new_full(g_int_hash, g_int_equal,
							NULL, free_rfkill);
	technology->device_list = NULL;

	technology->pending_reply = NULL;
	technology->state = CONNMAN_TECHNOLOGY_STATE_OFFLINE;

	__connman_storage_load_technology(technology);

	if (g_dbus_register_interface(connection, technology->path,
					CONNMAN_TECHNOLOGY_INTERFACE,
					technology_methods, technology_signals,
					NULL, technology, NULL) == FALSE) {
		connman_error("Failed to register %s", technology->path);
		g_free(technology);
		return NULL;
	}

	technology_list = g_slist_append(technology_list, technology);

	technologies_changed();

	if (technology->driver != NULL)
		goto done;

	for (list = driver_list; list; list = list->next) {
		struct connman_technology_driver *driver = list->data;

		DBG("driver %p name %s", driver, driver->name);

		if (driver->type != technology->type)
			continue;

		if (driver->probe(technology) == 0) {
			technology->driver = driver;
			break;
		}
	}

done:
	DBG("technology %p", technology);

	return technology;
}

static void technology_put(struct connman_technology *technology)
{
	DBG("technology %p", technology);

	if (g_atomic_int_dec_and_test(&technology->refcount) == FALSE)
		return;

	if (technology->driver) {
		technology->driver->remove(technology);
		technology->driver = NULL;
	}

	technology_list = g_slist_remove(technology_list, technology);

	technologies_changed();

	g_dbus_unregister_interface(connection, technology->path,
						CONNMAN_TECHNOLOGY_INTERFACE);

	g_slist_free(technology->device_list);
	g_hash_table_destroy(technology->rfkill_list);

	g_free(technology->path);
	g_free(technology->regdom);
	g_free(technology);
}

void __connman_technology_add_interface(enum connman_service_type type,
				int index, const char *name, const char *ident)
{
	struct connman_technology *technology;

	switch (type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
		return;
	case CONNMAN_SERVICE_TYPE_ETHERNET:
	case CONNMAN_SERVICE_TYPE_WIFI:
	case CONNMAN_SERVICE_TYPE_WIMAX:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_VPN:
	case CONNMAN_SERVICE_TYPE_GADGET:
		break;
	}

	connman_info("Create interface %s [ %s ]", name,
				__connman_service_type2string(type));

	technology = technology_get(type);

	if (technology == NULL || technology->driver == NULL
			|| technology->driver->add_interface == NULL)
		return;

	technology->driver->add_interface(technology,
					index, name, ident);
}

void __connman_technology_remove_interface(enum connman_service_type type,
				int index, const char *name, const char *ident)
{
	struct connman_technology *technology;

	switch (type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
		return;
	case CONNMAN_SERVICE_TYPE_ETHERNET:
	case CONNMAN_SERVICE_TYPE_WIFI:
	case CONNMAN_SERVICE_TYPE_WIMAX:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_VPN:
	case CONNMAN_SERVICE_TYPE_GADGET:
		break;
	}

	connman_info("Remove interface %s [ %s ]", name,
				__connman_service_type2string(type));

	technology = technology_find(type);

	if (technology == NULL || technology->driver == NULL)
		return;

	if (technology->driver->remove_interface)
		technology->driver->remove_interface(technology, index);

	technology_put(technology);
}

int __connman_technology_add_device(struct connman_device *device)
{
	struct connman_technology *technology;
	enum connman_service_type type;

	DBG("device %p", device);

	type = __connman_device_get_service_type(device);
	__connman_notifier_register(type);

	technology = technology_get(type);
	if (technology == NULL)
		return -ENXIO;

	if (g_atomic_int_get(&technology->blocked))
		goto done;

done:

	technology->device_list = g_slist_append(technology->device_list,
								device);

	return 0;
}

int __connman_technology_remove_device(struct connman_device *device)
{
	struct connman_technology *technology;
	enum connman_service_type type;

	DBG("device %p", device);

	type = __connman_device_get_service_type(device);
	__connman_notifier_unregister(type);

	technology = technology_find(type);
	if (technology == NULL)
		return -ENXIO;

	technology->device_list = g_slist_remove(technology->device_list,
								device);
	if (technology->device_list == NULL) {
		technology->state = CONNMAN_TECHNOLOGY_STATE_OFFLINE;
		state_changed(technology);
	}

	return 0;
}

static gboolean technology_pending_reply(gpointer user_data)
{
	struct connman_technology *technology = user_data;
	DBusMessage *reply;

	/* Power request timedout, send ETIMEDOUT. */
	if (technology->pending_reply != NULL) {
		reply = __connman_error_failed(technology->pending_reply, ETIMEDOUT);
		if (reply != NULL)
			g_dbus_send_message(connection, reply);

		dbus_message_unref(technology->pending_reply);
		technology->pending_reply = NULL;
		technology->pending_timeout = 0;
	}

	return FALSE;
}

int __connman_technology_enabled(enum connman_service_type type)
{
	struct connman_technology *technology;

	technology = technology_find(type);
	if (technology == NULL)
		return -ENXIO;

	if (g_atomic_int_get(&technology->blocked))
		return -ERFKILL;

	if (g_atomic_int_exchange_and_add(&technology->enabled, 1) == 0) {
		__connman_notifier_enable(type);
		technology->state = CONNMAN_TECHNOLOGY_STATE_ENABLED;
		state_changed(technology);
	}

	if (technology->pending_reply != NULL) {
		g_dbus_send_reply(connection, technology->pending_reply, DBUS_TYPE_INVALID);
		dbus_message_unref(technology->pending_reply);
		technology->pending_reply = NULL;
		technology->pending_timeout = 0;
	}

	return 0;
}

int __connman_technology_enable(enum connman_service_type type, DBusMessage *msg)
{
	struct connman_technology *technology;
	GSList *list;
	int err = 0;
	int ret = -ENODEV;
	DBusMessage *reply;

	DBG("type %d enable", type);

	technology = technology_find(type);
	if (technology == NULL) {
		err = -ENXIO;
		goto done;
	}

	if (technology->pending_reply != NULL) {
		err = -EBUSY;
		goto done;
	}

	if (msg != NULL) {
		technology->pending_reply = dbus_message_ref(msg);
		/*
		 * This is a bit of a trick. When msg is not NULL it means
		 * thats technology_enable was invoked from the manager API. Hence we save
		 * the state here.
		 */
		technology->enable_persistent = TRUE;
		__connman_storage_save_technology(technology);
	}

	for (list = technology->device_list; list; list = list->next) {
		struct connman_device *device = list->data;

		err = __connman_device_enable_persistent(device);
		/*
		 * err = 0 : Device was enabled right away.
		 * If atleast one device gets enabled, we consider
		 * the technology to be enabled.
		 */
		if (err == 0)
			ret = 0;
	}

done:
	if (ret == 0)
		return ret;

	if (msg != NULL) {
		if (err == -EINPROGRESS)
			technology->pending_timeout = g_timeout_add_seconds(10,
					technology_pending_reply, technology);
		else {
			reply = __connman_error_failed(msg, -err);
			if (reply != NULL)
				g_dbus_send_message(connection, reply);
		}
	}

	return err;
}

int __connman_technology_disabled(enum connman_service_type type)
{
	struct connman_technology *technology;
	GSList *list;

	technology = technology_find(type);
	if (technology == NULL)
		return -ENXIO;

	if (technology->pending_reply != NULL) {
		g_dbus_send_reply(connection, technology->pending_reply, DBUS_TYPE_INVALID);
		dbus_message_unref(technology->pending_reply);
		technology->pending_reply = NULL;
	}

	if (g_atomic_int_dec_and_test(&technology->enabled) == TRUE) {
		__connman_notifier_disable(type);
		technology->state = CONNMAN_TECHNOLOGY_STATE_OFFLINE;
		state_changed(technology);
	}

	for (list = technology->device_list; list; list = list->next) {
		struct connman_device *device = list->data;

		if (__connman_device_get_blocked(device) == FALSE)
			return 0;
	}

	return 0;
}

int __connman_technology_disable(enum connman_service_type type, DBusMessage *msg)
{
	struct connman_technology *technology;
	GSList *list;
	int err = 0;
	int ret = -ENODEV;
	DBusMessage *reply;

	DBG("type %d disable", type);

	technology = technology_find(type);
	if (technology == NULL) {
		err = -ENXIO;
		goto done;
	}

	if (technology->pending_reply != NULL) {
		err = -EBUSY;
		goto done;
	}

	if (msg != NULL) {
		technology->pending_reply = dbus_message_ref(msg);
		technology->enable_persistent = FALSE;
		__connman_storage_save_technology(technology);
	}

	for (list = technology->device_list; list; list = list->next) {
		struct connman_device *device = list->data;

		err = __connman_device_disable_persistent(device);
		if (err == 0)
			ret = 0;
	}

done:
	if (ret == 0)
		return ret;

	if (msg != NULL) {
		if (err == -EINPROGRESS)
			technology->pending_timeout = g_timeout_add_seconds(10,
					technology_pending_reply, technology);
		else {
			reply = __connman_error_failed(msg, -err);
			if (reply != NULL)
				g_dbus_send_message(connection, reply);
		}
	}

	return err;
}

int __connman_technology_set_offlinemode(connman_bool_t offlinemode)
{
	GSList *list;
	int err = -EINVAL;

	DBG("offlinemode %s", offlinemode ? "On" : "Off");

	/* Traverse technology list, enable/disable each technology. */
	for (list = technology_list; list; list = list->next) {
		struct connman_technology *technology = list->data;

		if (offlinemode)
			err = __connman_technology_disable(technology->type, NULL);
		if (!offlinemode && technology->enable_persistent)
			err = __connman_technology_enable(technology->type, NULL);
	}

	if (err == 0 || err == -EINPROGRESS) {
		__connman_profile_set_offlinemode(offlinemode);
		__connman_profile_save_default();

		__connman_notifier_offlinemode(offlinemode);
	}

	return err;
}

static void technology_blocked(struct connman_technology *technology,
				connman_bool_t blocked)
{
	GSList *list;

	for (list = technology->device_list; list; list = list->next) {
		struct connman_device *device = list->data;

		__connman_device_set_blocked(device, blocked);
	}
}

int __connman_technology_add_rfkill(unsigned int index,
					enum connman_service_type type,
						connman_bool_t softblock,
						connman_bool_t hardblock)
{
	struct connman_technology *technology;
	struct connman_rfkill *rfkill;
	connman_bool_t blocked;

	DBG("index %u type %d soft %u hard %u", index, type,
							softblock, hardblock);

	technology = technology_get(type);
	if (technology == NULL)
		return -ENXIO;

	rfkill = g_try_new0(struct connman_rfkill, 1);
	if (rfkill == NULL)
		return -ENOMEM;

	rfkill->index = index;
	rfkill->type = type;
	rfkill->softblock = softblock;
	rfkill->hardblock = hardblock;

	g_hash_table_replace(technology->rfkill_list, &rfkill->index, rfkill);

	blocked = (softblock || hardblock) ? TRUE : FALSE;
	if (blocked == FALSE)
		return 0;

	if (g_atomic_int_exchange_and_add(&technology->blocked, 1) == 0) {
		technology_blocked(technology, TRUE);

		technology->state = CONNMAN_TECHNOLOGY_STATE_OFFLINE;
		state_changed(technology);
	}

	return 0;
}

int __connman_technology_update_rfkill(unsigned int index,
					enum connman_service_type type,
						connman_bool_t softblock,
						connman_bool_t hardblock)
{
	struct connman_technology *technology;
	struct connman_rfkill *rfkill;
	connman_bool_t blocked, old_blocked;

	DBG("index %u soft %u hard %u", index, softblock, hardblock);

	technology = technology_find(type);
	if (technology == NULL)
		return -ENXIO;

	rfkill = g_hash_table_lookup(technology->rfkill_list, &index);
	if (rfkill == NULL)
		return -ENXIO;

	old_blocked = (rfkill->softblock || rfkill->hardblock) ? TRUE : FALSE;
	blocked = (softblock || hardblock) ? TRUE : FALSE;

	rfkill->softblock = softblock;
	rfkill->hardblock = hardblock;

	if (blocked == old_blocked)
		return 0;

	if (blocked) {
		guint n_blocked;

		n_blocked =
			g_atomic_int_exchange_and_add(&technology->blocked, 1);
		if (n_blocked != g_hash_table_size(technology->rfkill_list) - 1)
			return 0;

		technology_blocked(technology, blocked);
		technology->state = CONNMAN_TECHNOLOGY_STATE_OFFLINE;
		state_changed(technology);
	} else {
		if (g_atomic_int_dec_and_test(&technology->blocked) == FALSE)
			return 0;

		technology_blocked(technology, blocked);
		technology->state = CONNMAN_TECHNOLOGY_STATE_ENABLED;
		state_changed(technology);
	}

	return 0;
}

int __connman_technology_remove_rfkill(unsigned int index,
					enum connman_service_type type)
{
	struct connman_technology *technology;
	struct connman_rfkill *rfkill;
	connman_bool_t blocked;

	DBG("index %u", index);

	technology = technology_find(type);
	if (technology == NULL)
		return -ENXIO;

	rfkill = g_hash_table_lookup(technology->rfkill_list, &index);
	if (rfkill == NULL)
		return -ENXIO;

	blocked = (rfkill->softblock || rfkill->hardblock) ? TRUE : FALSE;

	g_hash_table_remove(technology->rfkill_list, &index);

	if (blocked &&
		g_atomic_int_dec_and_test(&technology->blocked) == TRUE) {
		technology_blocked(technology, FALSE);
		technology->state = CONNMAN_TECHNOLOGY_STATE_OFFLINE;
		state_changed(technology);
	}

	return 0;
}

connman_bool_t __connman_technology_get_blocked(enum connman_service_type type)
{
	struct connman_technology *technology;

	technology = technology_find(type);
	if (technology == NULL)
		return FALSE;

	if (g_atomic_int_get(&technology->blocked))
		return TRUE;

	return FALSE;
}

static int technology_load(struct connman_technology *technology)
{
	const char *ident = __connman_profile_active_ident();
	GKeyFile *keyfile;
	gchar *identifier;
	GError *error = NULL;
	connman_bool_t enable;

	DBG("technology %p", technology);

	keyfile = __connman_storage_open_profile(ident);
	if (keyfile == NULL)
		return 0;

	identifier = g_strdup_printf("%s", get_name(technology->type));
	if (identifier == NULL)
		goto done;

	enable = g_key_file_get_boolean(keyfile, identifier, "Enable", &error);
	if (error == NULL)
		technology->enable_persistent = enable;
	else
		technology->enable_persistent = FALSE;

	g_clear_error(&error);
done:
	g_free(identifier);

	__connman_storage_close_profile(ident, keyfile, FALSE);

	return 0;
}

static int technology_save(struct connman_technology *technology)
{
	const char *ident = __connman_profile_active_ident();
	GKeyFile *keyfile;
	gchar *identifier;

	DBG("technology %p", technology);

	keyfile = __connman_storage_open_profile(ident);
	if (keyfile == NULL)
		return 0;

	identifier = g_strdup_printf("%s", get_name(technology->type));
	if (identifier == NULL)
		goto done;

	g_key_file_set_boolean(keyfile, identifier, "Enable",
				technology->enable_persistent);

done:
	g_free(identifier);

	__connman_storage_close_profile(ident, keyfile, TRUE);

	return 0;
}

static struct connman_storage tech_storage = {
	.name		= "technology",
	.priority	= CONNMAN_STORAGE_PRIORITY_LOW,
	.tech_load	= technology_load,
	.tech_save	= technology_save,
};

int __connman_technology_init(void)
{
	DBG("");

	connection = connman_dbus_get_connection();

	return connman_storage_register(&tech_storage);
}

void __connman_technology_cleanup(void)
{
	DBG("");

	dbus_connection_unref(connection);

	connman_storage_unregister(&tech_storage);
}
