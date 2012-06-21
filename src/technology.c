/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2012  Intel Corporation. All rights reserved.
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

/*
 * List of devices with no technology associated with them either because of
 * no compiled in support or the driver is not yet loaded.
*/
static GSList *techless_device_list = NULL;
static GHashTable *rfkill_list;

static connman_bool_t global_offlinemode;

struct connman_rfkill {
	unsigned int index;
	enum connman_service_type type;
	connman_bool_t softblock;
	connman_bool_t hardblock;
};

struct connman_technology {
	int refcount;
	enum connman_service_type type;
	char *path;
	GSList *device_list;
	int enabled;
	char *regdom;
	connman_bool_t connected;

	connman_bool_t tethering;
	char *tethering_ident;
	char *tethering_passphrase;

	connman_bool_t enable_persistent; /* Save the tech state */

	struct connman_technology_driver *driver;
	void *driver_data;

	DBusMessage *pending_reply;
	guint pending_timeout;

	GSList *scan_pending;
};

static GSList *driver_list = NULL;

static gint compare_priority(gconstpointer a, gconstpointer b)
{
	const struct connman_technology_driver *driver1 = a;
	const struct connman_technology_driver *driver2 = b;

	return driver2->priority - driver1->priority;
}

static void rfkill_check(gpointer key, gpointer value, gpointer user_data)
{
	struct connman_rfkill *rfkill = value;
	enum connman_service_type type = GPOINTER_TO_INT(user_data);

	/* Calling _technology_rfkill_add will update the tech. */
	if (rfkill->type == type)
		__connman_technology_add_rfkill(rfkill->index, type,
				rfkill->softblock, rfkill->hardblock);
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
	struct connman_device *device;
	enum connman_service_type type;

	DBG("Registering %s driver", driver->name);

	driver_list = g_slist_insert_sorted(driver_list, driver,
							compare_priority);

	if (techless_device_list == NULL)
		goto check_rfkill;

	/*
	 * Check for technology less devices if this driver
	 * can service any of them.
	*/
	for (list = techless_device_list; list; list = list->next) {
		device = list->data;

		type = __connman_device_get_service_type(device);
		if (type != driver->type)
			continue;

		techless_device_list = g_slist_remove(techless_device_list,
								device);

		__connman_technology_add_device(device);
	}

check_rfkill:
	/* Check for orphaned rfkill switches. */
	g_hash_table_foreach(rfkill_list, rfkill_check,
					GINT_TO_POINTER(driver->type));

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

	DBG("Unregistering driver %p name %s", driver, driver->name);

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
		if (technology->type == CONNMAN_SERVICE_TYPE_ETHERNET)
			/* We enable ethernet by default */
			technology->enable_persistent = TRUE;
		else
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
		if (technology->type == CONNMAN_SERVICE_TYPE_ETHERNET)
			technology->enable_persistent = TRUE;
		else
			technology->enable_persistent = FALSE;

		save_state(technology);
		g_clear_error(&error);
	}
done:
	g_free(identifier);

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
		return FALSE;

	offlinemode = g_key_file_get_boolean(keyfile, "global",
						"OfflineMode", &error);
	if (error != NULL) {
		offlinemode = FALSE;
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
	connman_bool_t powered;

	connman_dbus_dict_open(iter, &dict);

	str = get_name(technology->type);
	if (str != NULL)
		connman_dbus_dict_append_basic(&dict, "Name",
						DBUS_TYPE_STRING, &str);

	str = __connman_service_type2string(technology->type);
	if (str != NULL)
		connman_dbus_dict_append_basic(&dict, "Type",
						DBUS_TYPE_STRING, &str);

	__sync_synchronize();
	if (technology->enabled > 0)
		powered = TRUE;
	else
		powered = FALSE;
	connman_dbus_dict_append_basic(&dict, "Powered",
					DBUS_TYPE_BOOLEAN, &powered);

	connman_dbus_dict_append_basic(&dict, "Connected",
					DBUS_TYPE_BOOLEAN,
					&technology->connected);

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
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH,
							&technology->path);
	append_properties(&iter, technology);

	dbus_connection_send(connection, signal, NULL);
	dbus_message_unref(signal);
}

static void technology_removed_signal(struct connman_technology *technology)
{
	g_dbus_emit_signal(connection, CONNMAN_MANAGER_PATH,
			CONNMAN_MANAGER_INTERFACE, "TechnologyRemoved",
			DBUS_TYPE_OBJECT_PATH, &technology->path,
			DBUS_TYPE_INVALID);
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

static int technology_enable(struct connman_technology *technology,
		DBusMessage *msg)
{
	GSList *list;
	int err = 0;
	int ret = -ENODEV;
	DBusMessage *reply;

	DBG("technology %p enable", technology);

	__sync_synchronize();
	if (technology->enabled > 0) {
		err = -EALREADY;
		goto done;
	}

	if (technology->pending_reply != NULL) {
		err = -EBUSY;
		goto done;
	}

	if (msg != NULL) {
		/*
		 * This is a bit of a trick. When msg is not NULL it means
		 * thats technology_enable was invoked from the manager API.
		 * Hence we save the state here.
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
			if (err == -EALREADY)
				reply = __connman_error_already_enabled(msg);
			else
				reply = __connman_error_failed(msg, -err);
			if (reply != NULL)
				g_dbus_send_message(connection, reply);
		}
	}

	return err;
}

static int technology_disable(struct connman_technology *technology,
		DBusMessage *msg)
{
	GSList *list;
	int err = 0;
	int ret = -ENODEV;
	DBusMessage *reply;

	DBG("technology %p disable", technology);

	__sync_synchronize();
	if (technology->enabled == 0) {
		err = -EALREADY;
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
			if (err == -EALREADY)
				reply = __connman_error_already_disabled(msg);
			else
				reply = __connman_error_failed(msg, -err);
			if (reply != NULL)
				g_dbus_send_message(connection, reply);
		}
	}

	return err;
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

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &name);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
		return __connman_error_invalid_arguments(msg);

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
	} else if (g_str_equal(name, "Powered") == TRUE) {
		connman_bool_t enable;

		if (type != DBUS_TYPE_BOOLEAN)
			return __connman_error_invalid_arguments(msg);

		dbus_message_iter_get_basic(&value, &enable);
		if (enable == TRUE)
			technology_enable(technology, msg);
		else
			technology_disable(technology, msg);

	} else
		return __connman_error_invalid_property(msg);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

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

static void reply_scan_pending(struct connman_technology *technology, int err)
{
	DBusMessage *reply;

	DBG("technology %p err %d", technology, err);

	while (technology->scan_pending != NULL) {
		DBusMessage *msg = technology->scan_pending->data;

		DBG("reply to %s", dbus_message_get_sender(msg));

		if (err == 0)
			reply = g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
		else
			reply = __connman_error_failed(msg, -err);
		g_dbus_send_message(connection, reply);
		dbus_message_unref(msg);

		technology->scan_pending =
			g_slist_delete_link(technology->scan_pending,
					technology->scan_pending);
	}
}

void __connman_technology_scan_started(struct connman_device *device)
{
	DBG("device %p", device);
}

void __connman_technology_scan_stopped(struct connman_device *device)
{
	int count = 0;
	struct connman_technology *technology;
	enum connman_service_type type;
	GSList *list;

	type = __connman_device_get_service_type(device);
	technology = technology_find(type);

	DBG("technology %p device %p", technology, device);

	if (technology == NULL)
		return;

	for (list = technology->device_list; list != NULL; list = list->next) {
		struct connman_device *other_device = list->data;

		if (device == other_device)
			continue;

		if (__connman_device_get_service_type(other_device) != type)
			continue;

		if (connman_device_get_scanning(other_device) == TRUE)
			count += 1;
	}

	if (count == 0)
		reply_scan_pending(technology, 0);
}

static DBusMessage *scan(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct connman_technology *technology = data;
	int err;

	DBG ("technology %p request from %s", technology,
			dbus_message_get_sender(msg));

	dbus_message_ref(msg);
	technology->scan_pending =
		g_slist_prepend(technology->scan_pending, msg);

	err = __connman_device_request_scan(technology->type);
	if (err < 0)
		reply_scan_pending(technology, err);

	return NULL;
}

static const GDBusMethodTable technology_methods[] = {
	{ GDBUS_DEPRECATED_METHOD("GetProperties",
			NULL, GDBUS_ARGS({ "properties", "a{sv}" }),
			get_properties) },
	{ GDBUS_METHOD("SetProperty",
			GDBUS_ARGS({ "name", "s" }, { "value", "v" }),
			NULL, set_property) },
	{ GDBUS_ASYNC_METHOD("Scan", NULL, NULL, scan) },
	{ },
};

static const GDBusSignalTable technology_signals[] = {
	{ GDBUS_SIGNAL("PropertyChanged",
			GDBUS_ARGS({ "name", "s" }, { "value", "v" })) },
	{ },
};

static struct connman_technology *technology_get(enum connman_service_type type)
{
	struct connman_technology *technology;
	struct connman_technology_driver *driver = NULL;
	const char *str;
	GSList *list;
	int err;

	DBG("type %d", type);

	str = __connman_service_type2string(type);
	if (str == NULL)
		return NULL;

	technology = technology_find(type);
	if (technology != NULL) {
		__sync_fetch_and_add(&technology->refcount, 1);
		return technology;
	}

	/* First check if we have a driver for this technology type */
	for (list = driver_list; list; list = list->next) {
		driver = list->data;

		if (driver->type == type)
			break;
		else
			driver = NULL;
	}

	if (driver == NULL) {
		DBG("No matching driver found for %s.",
				__connman_service_type2string(type));
		return NULL;
	}

	technology = g_try_new0(struct connman_technology, 1);
	if (technology == NULL)
		return NULL;

	technology->refcount = 1;

	technology->type = type;
	technology->path = g_strdup_printf("%s/technology/%s",
							CONNMAN_PATH, str);

	technology->device_list = NULL;

	technology->pending_reply = NULL;

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

	technology->driver = driver;
	err = driver->probe(technology);
	if (err != 0)
		DBG("Driver probe failed for technology %p", technology);

	DBG("technology %p", technology);

	return technology;
}

static void technology_put(struct connman_technology *technology)
{
	DBG("technology %p", technology);

	if (__sync_sub_and_fetch(&technology->refcount, 1) > 0)
		return;

	reply_scan_pending(technology, -EINTR);

	if (technology->driver) {
		technology->driver->remove(technology);
		technology->driver = NULL;
	}

	technology_list = g_slist_remove(technology_list, technology);

	technology_removed_signal(technology);

	g_dbus_unregister_interface(connection, technology->path,
						CONNMAN_TECHNOLOGY_INTERFACE);

	g_slist_free(technology->device_list);

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

	connman_info("Adding interface %s [ %s ]", name,
				__connman_service_type2string(type));

	technology = technology_find(type);

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
}

int __connman_technology_add_device(struct connman_device *device)
{
	struct connman_technology *technology;
	enum connman_service_type type;

	DBG("device %p", device);

	type = __connman_device_get_service_type(device);

	technology = technology_get(type);
	if (technology == NULL) {
		/*
		 * Since no driver can be found for this device at the moment we
		 * add it to the techless device list.
		*/
		techless_device_list = g_slist_prepend(techless_device_list,
								device);

		return -ENXIO;
	}

	if (technology->enable_persistent && !global_offlinemode) {
		int err = __connman_device_enable(device);
		/*
		 * connman_technology_add_device() calls __connman_device_enable()
		 * but since the device is already enabled, the calls does not
		 * propagate through to connman_technology_enabled via
		 * connman_device_set_powered.
		 */
		if (err == -EALREADY)
			__connman_technology_enabled(type);
	}
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

	technology = technology_find(type);
	if (technology == NULL) {
		techless_device_list = g_slist_remove(techless_device_list,
								device);
		return -ENXIO;
	}

	technology->device_list = g_slist_remove(technology->device_list,
								device);
	technology_put(technology);

	return 0;
}

static void powered_changed(struct connman_technology *technology)
{
	connman_bool_t powered;

	__sync_synchronize();
	if (technology->enabled >0)
		powered = TRUE;
	else
		powered = FALSE;

	connman_dbus_property_changed_basic(technology->path,
			CONNMAN_TECHNOLOGY_INTERFACE, "Powered",
			DBUS_TYPE_BOOLEAN, &powered);
}

int __connman_technology_enabled(enum connman_service_type type)
{
	struct connman_technology *technology;

	technology = technology_find(type);
	if (technology == NULL)
		return -ENXIO;

	if (__sync_fetch_and_add(&technology->enabled, 1) != 0)
		return -EALREADY;

	powered_changed(technology);

	if (technology->pending_reply != NULL) {
		g_dbus_send_reply(connection, technology->pending_reply, DBUS_TYPE_INVALID);
		dbus_message_unref(technology->pending_reply);
		g_source_remove(technology->pending_timeout);
		technology->pending_reply = NULL;
		technology->pending_timeout = 0;
	}

	return 0;
}

int __connman_technology_disabled(enum connman_service_type type)
{
	struct connman_technology *technology;

	technology = technology_find(type);
	if (technology == NULL)
		return -ENXIO;

	if (__sync_fetch_and_sub(&technology->enabled, 1) != 1)
		return -EINPROGRESS;

	if (technology->pending_reply != NULL) {
		g_dbus_send_reply(connection, technology->pending_reply, DBUS_TYPE_INVALID);
		dbus_message_unref(technology->pending_reply);
		g_source_remove(technology->pending_timeout);
		technology->pending_reply = NULL;
		technology->pending_timeout = 0;
	}

	powered_changed(technology);

	return 0;
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
			err = technology_disable(technology, NULL);

		if (!offlinemode && technology->enable_persistent)
			err = technology_enable(technology, NULL);
	}

	if (err == 0 || err == -EINPROGRESS || err == -EALREADY) {
		connman_technology_save_offlinemode();
		__connman_notifier_offlinemode(offlinemode);
	} else
		global_offlinemode = connman_technology_load_offlinemode();

	return err;
}

void __connman_technology_set_connected(enum connman_service_type type,
		connman_bool_t connected)
{
	struct connman_technology *technology;

	technology = technology_find(type);
	if (technology == NULL)
		return;

	DBG("technology %p connected %d", technology, connected);

	technology->connected = connected;

	connman_dbus_property_changed_basic(technology->path,
			CONNMAN_TECHNOLOGY_INTERFACE, "Connected",
			DBUS_TYPE_BOOLEAN, &connected);
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

	rfkill = g_hash_table_lookup(rfkill_list, &index);
	if (rfkill != NULL)
		goto done;

	rfkill = g_try_new0(struct connman_rfkill, 1);
	if (rfkill == NULL)
		return -ENOMEM;

	rfkill->index = index;
	rfkill->type = type;
	rfkill->softblock = softblock;
	rfkill->hardblock = hardblock;

	g_hash_table_insert(rfkill_list, &rfkill->index, rfkill);

done:
	technology = technology_get(type);
	/* If there is no driver for this type, ignore it. */
	if (technology == NULL)
		return -ENXIO;

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

	rfkill = g_hash_table_lookup(rfkill_list, &index);
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

	technology = technology_find(type);
	/* If there is no driver for this type, ignore it. */
	if (technology == NULL)
		return -ENXIO;

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

	rfkill = g_hash_table_lookup(rfkill_list, &index);
	if (rfkill == NULL)
		return -ENXIO;

	g_hash_table_remove(rfkill_list, &index);

	technology = technology_find(type);
	if (technology == NULL)
		return -ENXIO;

	technology_put(technology);

	return 0;
}

int __connman_technology_init(void)
{
	DBG("");

	connection = connman_dbus_get_connection();

	rfkill_list = g_hash_table_new_full(g_int_hash, g_int_equal,
							NULL, free_rfkill);

	global_offlinemode = connman_technology_load_offlinemode();

	/* This will create settings file if it is missing */
	connman_technology_save_offlinemode();

	return 0;
}

void __connman_technology_cleanup(void)
{
	DBG("");

	g_hash_table_destroy(rfkill_list);

	dbus_connection_unref(connection);
}
