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

#include "connman.h"

static GSList *storage_list = NULL;

static gint compare_priority(gconstpointer a, gconstpointer b)
{
	const struct connman_storage *storage1 = a;
	const struct connman_storage *storage2 = b;

	return storage2->priority - storage1->priority;
}

/**
 * connman_storage_register:
 * @storage: storage module
 *
 * Register a new storage module
 *
 * Returns: %0 on success
 */
int connman_storage_register(struct connman_storage *storage)
{
	DBG("storage %p name %s", storage, storage->name);

	storage_list = g_slist_insert_sorted(storage_list, storage,
							compare_priority);

	return 0;
}

/**
 * connman_storage_unregister:
 * @storage: storage module
 *
 * Remove a previously registered storage module
 */
void connman_storage_unregister(struct connman_storage *storage)
{
	DBG("storage %p name %s", storage, storage->name);

	storage_list = g_slist_remove(storage_list, storage);
}

int __connman_storage_load_device(struct connman_device *device)
{
	GSList *list;

	DBG("device %p", device);

	for (list = storage_list; list; list = list->next) {
		struct connman_storage *storage = list->data;

		if (storage->device_load) {
			DBG("%s", storage->name);

			if (storage->device_load(device) == 0)
				return 0;
		}
	}

	return -ENOENT;
}

int __connman_storage_save_device(struct connman_device *device)
{
	GSList *list;

	DBG("device %p", device);

	for (list = storage_list; list; list = list->next) {
		struct connman_storage *storage = list->data;

		if (storage->device_save) {
			DBG("%s", storage->name);

			if (storage->device_save(device) == 0)
				return 0;
		}
	}

	return -ENOENT;
}

int __connman_storage_load_network(struct connman_network *network)
{
	GSList *list;

	DBG("network %p", network);

	for (list = storage_list; list; list = list->next) {
		struct connman_storage *storage = list->data;

		if (storage->network_load) {
			DBG("%s", storage->name);

			if (storage->network_load(network) == 0)
				return 0;
		}
	}

	return -ENOENT;
}

int __connman_storage_save_network(struct connman_network *network)
{
	GSList *list;

	DBG("network %p", network);

	for (list = storage_list; list; list = list->next) {
		struct connman_storage *storage = list->data;

		if (storage->network_save) {
			DBG("%s", storage->name);

			if (storage->network_save(network) == 0)
				return 0;
		}
	}

	return -ENOENT;
}

int __connman_storage_init(void)
{
	DBG("");

	return 0;
}

void __connman_storage_cleanup(void)
{
	DBG("");
}

static int do_load(GKeyFile *keyfile, struct connman_element *element)
{
	const gchar *value;

	DBG("element %p name %s", element, element->name);

	value = g_key_file_get_string(keyfile, element->path,
						"Policy", NULL);
	if (value != NULL)
		element->policy = __connman_element_string2policy(value);

	if (element->type == CONNMAN_ELEMENT_TYPE_NETWORK)
		element->remember = g_key_file_get_boolean(keyfile,
					element->path, "Remember", NULL);

	value = g_key_file_get_string(keyfile, element->path,
						"WiFi.Security", NULL);
	if (value != NULL)
		connman_element_set_property(element,
				CONNMAN_PROPERTY_ID_WIFI_SECURITY, &value);

	value = g_key_file_get_string(keyfile, element->path,
						"WiFi.Passphrase", NULL);
	if (value != NULL)
		connman_element_set_property(element,
				CONNMAN_PROPERTY_ID_WIFI_PASSPHRASE, &value);

	return 0;
}

int __connman_element_load(struct connman_element *element)
{
	GKeyFile *keyfile;
	gchar *pathname, *data = NULL;
	gsize length;

	DBG("element %p name %s", element, element->name);

	pathname = g_strdup_printf("%s/elements.conf", STORAGEDIR);
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

	do_load(keyfile, element);

	g_key_file_free(keyfile);

	return 0;
}

static void do_update(GKeyFile *keyfile, struct connman_element *element)
{
	GSList *list;
	char *value;
	const char *str;

	DBG("element %p name %s", element, element->name);

	g_key_file_set_string(keyfile, element->path, "Name", element->name);

	str = __connman_element_policy2string(element->policy);
	if (str != NULL)
		g_key_file_set_string(keyfile, element->path, "Policy", str);

	//g_key_file_set_boolean(keyfile, element->path, "Enabled",
	//						element->enabled);

	if (element->type == CONNMAN_ELEMENT_TYPE_NETWORK)
		g_key_file_set_boolean(keyfile, element->path, "Remember",
							element->remember);

	__connman_element_lock(element);

	for (list = element->properties; list; list = list->next) {
		struct connman_property *property = list->data;

		if (property->flags & CONNMAN_PROPERTY_FLAG_STATIC)
			continue;

		if (property->flags & CONNMAN_PROPERTY_FLAG_REFERENCE)
			continue;

		if (property->type == DBUS_TYPE_STRING)
			g_key_file_set_string(keyfile, element->path,
					property->name, property->value);
	}

	__connman_element_unlock(element);

	if (connman_element_get_value(element,
			CONNMAN_PROPERTY_ID_WIFI_SECURITY, &value) == 0)
		g_key_file_set_string(keyfile, element->path,
						"WiFi.Security", value);

	if (connman_element_get_value(element,
			CONNMAN_PROPERTY_ID_WIFI_PASSPHRASE, &value) == 0)
		g_key_file_set_string(keyfile, element->path,
						"WiFi.Passphrase", value);
}

int __connman_element_store(struct connman_element *element)
{
	GKeyFile *keyfile;
	gchar *pathname, *data = NULL;
	gsize length;

	DBG("element %p name %s", element, element->name);

	if (element->type != CONNMAN_ELEMENT_TYPE_DEVICE &&
				element->type != CONNMAN_ELEMENT_TYPE_NETWORK)
		return -EINVAL;

	if (element->subtype == CONNMAN_ELEMENT_SUBTYPE_FAKE)
		return -EINVAL;

	pathname = g_strdup_printf("%s/elements.conf", STORAGEDIR);
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
	do_update(keyfile, element);

	data = g_key_file_to_data(keyfile, &length, NULL);

	g_file_set_contents(pathname, data, length, NULL);

done:
	g_free(data);

	g_key_file_free(keyfile);

	g_free(pathname);

	return 0;
}
