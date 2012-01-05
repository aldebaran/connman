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

static connman_bool_t global_offlinemode;

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
	int refcount;
	enum connman_service_type type;
	enum connman_technology_state state;
	char *path;
	GHashTable *rfkill_list;
	GSList *device_list;
	int enabled;
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
	GSList *list;

	DBG("technology %p enabled %u", technology, enabled);

	if (technology->tethering == enabled)
		return;

	technology->tethering = enabled;

	tethering_changed(technology);

	if (enabled == TRUE)
		__connman_tethering_set_enabled();
	else {
		for (list = technology_list; list; list = list->next) {
			struct connman_technology *other_tech = list->data;
			if (other_tech->tethering == TRUE)
				break;
		}
		if (list == NULL)
			__connman_tethering_set_disabled();
	}
}

static int set_tethering(struct connman_technology *technology,
				connman_bool_t enabled)
{
	const char *ident, *passphrase, *bridge;

	ident = technology->tethering_ident;
	passphrase = technology->tethering_passphrase;

	if (technology->driver == NULL ||
			technology->driver->set_tethering == NULL)
		return -EOPNOTSUPP;

	bridge = __connman_tethering_get_bridge();
	if (bridge == NULL)
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
		return "Cellular";
	}

	return NULL;
}

static void load_state(struct connman_technology *technology)
{
	GKeyFile *keyfile;
	gchar *identifier;
	GError *error = NULL;
	connman_bool_t enable;

	DBG("technology %p", technology);

	keyfile = __connman_storage_load_global();
	/* Fallback on disabling technology if file not found. */
	if (keyfile == NULL) {
		technology->enable_persistent = FALSE;
		return;
	}

	identifier = g_strdup_printf("%s", get_name(technology->type));
	if (identifier == NULL)
		goto done;

	enable = g_key_file_get_boolean(keyfile, identifier, "Enable", &error);
	if (error == NULL)
		technology->enable_persistent = enable;
	else {
		technology->enable_persistent = FALSE;
		g_clear_error(&error);
	}
done:
	g_free(identifier);

	g_key_file_free(keyfile);

	return;
}

static void save_state(struct connman_technology *technology)
{
	GKeyFile *keyfile;
	gchar *identifier;

	DBG("technology %p", technology);

	keyfile = __connman_storage_load_global();
	if (keyfile == NULL)
		keyfile = g_key_file_new();

	identifier = g_strdup_printf("%s", get_name(technology->type));
	if (identifier == NULL)
		goto done;

	g_key_file_set_boolean(keyfile, identifier, "Enable",
				technology->enable_persistent);

done:
	g_free(identifier);

	__connman_storage_save_global(keyfile);

	g_key_file_free(keyfile);

	return;
}

connman_bool_t __connman_technology_get_offlinemode(void)
{
	return global_offlinemode;
}

static void connman_technology_save_offlinemode()
{
	GKeyFile *keyfile;

	keyfile = __connman_storage_load_global();
	if (keyfile == NULL)
		keyfile = g_key_file_new();

	g_key_file_set_boolean(keyfile, "global",
					"OfflineMode", global_offlinemode);

	__connman_storage_save_global(keyfile);

	g_key_file_free(keyfile);

	return;
}

static connman_bool_t connman_technology_load_offlinemode()
{
	GKeyFile *keyfile;
	GError *error = NULL;
	connman_bool_t offlinemode;

	/* If there is a error, we enable offlinemode */
	keyfile = __connman_storage_load_global();
	if (keyfile == NULL)
		return TRUE;

	offlinemode = g_key_file_get_boolean(keyfile, "global",
						"OfflineMode", &error);
	if (error != NULL) {
		offlinemode = TRUE;
		g_clear_error(&error);
	}

	g_key_file_free(keyfile);

	return offlinemode;
}

static void append_properties(DBusMessageIter *iter,
		struct connman_technology *technology)
{
	DBusMessageIter dict;
	const char *str;

	connman_dbus_dict_open(iter, &dict);

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

	connman_dbus_dict_close(iter, &dict);
}

static void technology_added_signal(struct connman_technology *technology)
{
	DBusMessage *signal;
	DBusMessageIter iter;

	signal = dbus_message_new_signal(CONNMAN_MANAGER_PATH,
			CONNMAN_MANAGER_INTERFACE, "TechnologyAdded");
	if (signal == NULL)
		return;

	dbus_message_iter_init_append(signal, &iter);
	append_properties(&iter, technology);

	dbus_connection_send(connection, signal, NULL);
	dbus_message_unref(signal);
}

static void technology_removed_signal(struct connman_technology *technology)
{
	g_dbus_emit_signal(connection, CONNMAN_MANAGER_PATH,
			CONNMAN_MANAGER_INTERFACE, "TechnologyRemoved",
			DBUS_TYPE_OBJECT_PATH, technology->path);
}

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *message, void *user_data)
{
	struct connman_technology *technology = user_data;
	DBusMessage *reply;
	DBusMessageIter iter;

	reply = dbus_message_new_method_return(message);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);
	append_properties(&iter, technology);

	return reply;
}

void __connman_technology_list_struct(DBusMessageIter *array)
{
	GSList *list;
	DBusMessageIter entry;

	for (list = technology_list; list; list = list->next) {
		struct connman_technology *technology = list->data;

		if (technology->path == NULL)
			continue;

		dbus_message_iter_open_container(array, DBUS_TYPE_STRUCT,
				NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_OBJECT_PATH,
				&technology->path);
		append_properties(&entry, technology);
		dbus_message_iter_close_container(array, &entry);
	}
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

		if (type != DBUS_TYPE_BOOLEAN)
			return __connman_error_invalid_arguments(msg);

		dbus_message_iter_get_basic(&value, &tethering);

		if (technology->tethering == tethering)
			return __connman_error_in_progress(msg);

		err = set_tethering(technology, tethering);
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
		__sync_fetch_and_add(&technology->refcount, 1);
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

	load_state(technology);

	if (g_dbus_register_interface(connection, technology->path,
					CONNMAN_TECHNOLOGY_INTERFACE,
					technology_methods, technology_signals,
					NULL, technology, NULL) == FALSE) {
		connman_error("Failed to register %s", technology->path);
		g_free(technology);
		return NULL;
	}

	technology_list = g_slist_append(technology_list, technology);

	technology_added_signal(technology);

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

	if (__sync_fetch_and_sub(&technology->refcount, 1) != 1)
		return;

	if (technology->driver) {
		technology->driver->remove(technology);
		technology->driver = NULL;
	}

	technology_list = g_slist_remove(technology_list, technology);

	technology_removed_signal(technology);

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

	if (technology->enable_persistent && !global_offlinemode)
		__connman_device_enable(device);
	/* if technology persistent state is offline */
	if (!technology->enable_persistent)
		__connman_device_disable(device);

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

	if (__sync_fetch_and_add(&technology->enabled, 1) == 0) {
		__connman_notifier_enable(type);
		technology->state = CONNMAN_TECHNOLOGY_STATE_ENABLED;
		state_changed(technology);
	}

	if (technology->pending_reply != NULL) {
		g_dbus_send_reply(connection, technology->pending_reply, DBUS_TYPE_INVALID);
		dbus_message_unref(technology->pending_reply);
		g_source_remove(technology->pending_timeout);
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
		/*
		 * This is a bit of a trick. When msg is not NULL it means
		 * thats technology_enable was invoked from the manager API. Hence we save
		 * the state here.
		 */
		technology->enable_persistent = TRUE;
		save_state(technology);
	}

	__connman_rfkill_block(technology->type, FALSE);

	/*
	 * An empty device list means that devices in the technology
	 * were rfkill blocked. The unblock above will enable the devs.
	 */
	if (technology->device_list == NULL) {
		ret = 0;
		goto done;
	}

	for (list = technology->device_list; list; list = list->next) {
		struct connman_device *device = list->data;

		err = __connman_device_enable(device);
		/*
		 * err = 0 : Device was enabled right away.
		 * If atleast one device gets enabled, we consider
		 * the technology to be enabled.
		 */
		if (err == 0)
			ret = 0;
	}

done:
	if (ret == 0) {
		if (msg != NULL)
			g_dbus_send_reply(connection, msg, DBUS_TYPE_INVALID);
		return ret;
	}

	if (msg != NULL) {
		if (err == -EINPROGRESS) {
			technology->pending_reply = dbus_message_ref(msg);
			technology->pending_timeout = g_timeout_add_seconds(10,
					technology_pending_reply, technology);
		} else {
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

	technology = technology_find(type);
	if (technology == NULL)
		return -ENXIO;

	if (technology->pending_reply != NULL) {
		g_dbus_send_reply(connection, technology->pending_reply, DBUS_TYPE_INVALID);
		dbus_message_unref(technology->pending_reply);
		g_source_remove(technology->pending_timeout);
		technology->pending_reply = NULL;
		technology->pending_timeout = 0;
	}

	if (__sync_fetch_and_sub(&technology->enabled, 1) != 1)
		return 0;

	__connman_notifier_disable(type);
	technology->state = CONNMAN_TECHNOLOGY_STATE_OFFLINE;
	state_changed(technology);

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

	if (technology->tethering == TRUE)
		set_tethering(technology, FALSE);

	if (msg != NULL) {
		technology->enable_persistent = FALSE;
		save_state(technology);
	}

	__connman_rfkill_block(technology->type, TRUE);

	for (list = technology->device_list; list; list = list->next) {
		struct connman_device *device = list->data;

		err = __connman_device_disable(device);
		if (err == 0)
			ret = 0;
	}

done:
	if (ret == 0) {
		if (msg != NULL)
			g_dbus_send_reply(connection, msg, DBUS_TYPE_INVALID);
		return ret;
	}

	if (msg != NULL) {
		if (err == -EINPROGRESS) {
			technology->pending_reply = dbus_message_ref(msg);
			technology->pending_timeout = g_timeout_add_seconds(10,
					technology_pending_reply, technology);
		} else {
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

	if (global_offlinemode == offlinemode)
		return 0;

	DBG("offlinemode %s", offlinemode ? "On" : "Off");

	/*
	 * This is a bit tricky. When you set offlinemode, there is no
	 * way to differentiate between attempting offline mode and
	 * resuming offlinemode from last saved profile. We need that
	 * information in rfkill_update, otherwise it falls back on the
	 * technology's persistent state. Hence we set the offline mode here
	 * but save it & call the notifier only if its successful.
	 */

	global_offlinemode = offlinemode;

	/* Traverse technology list, enable/disable each technology. */
	for (list = technology_list; list; list = list->next) {
		struct connman_technology *technology = list->data;

		if (offlinemode)
			err = __connman_technology_disable(technology->type, NULL);

		if (!offlinemode && technology->enable_persistent)
			err = __connman_technology_enable(technology->type, NULL);
	}

	if (err == 0 || err == -EINPROGRESS || err == -EALREADY) {
		connman_technology_save_offlinemode();
		__connman_notifier_offlinemode(offlinemode);
	} else
		global_offlinemode = connman_technology_load_offlinemode();

	return err;
}

int __connman_technology_add_rfkill(unsigned int index,
					enum connman_service_type type,
						connman_bool_t softblock,
						connman_bool_t hardblock)
{
	struct connman_technology *technology;
	struct connman_rfkill *rfkill;

	DBG("index %u type %d soft %u hard %u", index, type,
							softblock, hardblock);

	technology = technology_get(type);
	if (technology == NULL)
		return -ENXIO;

	rfkill = g_try_new0(struct connman_rfkill, 1);
	if (rfkill == NULL)
		return -ENOMEM;

	__connman_notifier_register(type);

	rfkill->index = index;
	rfkill->type = type;
	rfkill->softblock = softblock;
	rfkill->hardblock = hardblock;

	g_hash_table_replace(technology->rfkill_list, &rfkill->index, rfkill);

	if (hardblock) {
		DBG("%s is switched off.", get_name(type));
		return 0;
	}

	/*
	 * If Offline mode is on, we softblock the device if it isnt already.
	 * If Offline mode is off, we rely on the persistent state of tech.
	 */
	if (global_offlinemode) {
		if (!softblock)
			return __connman_rfkill_block(type, TRUE);
	} else {
		if (technology->enable_persistent && softblock)
			return __connman_rfkill_block(type, FALSE);
		/* if technology persistent state is offline */
		if (!technology->enable_persistent && !softblock)
			return __connman_rfkill_block(type, TRUE);
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

	DBG("index %u soft %u hard %u", index, softblock, hardblock);

	technology = technology_find(type);
	if (technology == NULL)
		return -ENXIO;

	rfkill = g_hash_table_lookup(technology->rfkill_list, &index);
	if (rfkill == NULL)
		return -ENXIO;

	if (rfkill->softblock == softblock &&
		rfkill->hardblock == hardblock)
		return 0;

	rfkill->softblock = softblock;
	rfkill->hardblock = hardblock;

	if (hardblock) {
		DBG("%s is switched off.", get_name(type));
		return 0;
	}

	if (!global_offlinemode) {
		if (technology->enable_persistent && softblock)
			return __connman_rfkill_block(type, FALSE);
		if (!technology->enable_persistent && !softblock)
			return __connman_rfkill_block(type, TRUE);
	}

	return 0;
}

int __connman_technology_remove_rfkill(unsigned int index,
					enum connman_service_type type)
{
	struct connman_technology *technology;
	struct connman_rfkill *rfkill;

	DBG("index %u", index);

	technology = technology_find(type);
	if (technology == NULL)
		return -ENXIO;

	rfkill = g_hash_table_lookup(technology->rfkill_list, &index);
	if (rfkill == NULL)
		return -ENXIO;

	g_hash_table_remove(technology->rfkill_list, &index);

	technology_put(technology);

	return 0;
}

int __connman_technology_init(void)
{
	DBG("");

	connection = connman_dbus_get_connection();

	global_offlinemode = connman_technology_load_offlinemode();

	return 0;
}

void __connman_technology_cleanup(void)
{
	DBG("");

	dbus_connection_unref(connection);
}
