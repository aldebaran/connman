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

GKeyFile *__connman_storage_open(void)
{
	GKeyFile *keyfile;
	gchar *pathname, *data = NULL;
	gboolean result;
	gsize length;

	DBG("");

	pathname = g_strdup_printf("%s/%s.conf", STORAGEDIR,
					__connman_profile_active_ident());
	if (pathname == NULL)
		return NULL;

	result = g_file_get_contents(pathname, &data, &length, NULL);

	g_free(pathname);

	if (result == FALSE)
		return NULL;

	keyfile = g_key_file_new();

	if (length > 0) {
		if (g_key_file_load_from_data(keyfile, data, length,
							0, NULL) == FALSE)
			goto done;
	}

done:
	g_free(data);

	DBG("keyfile %p", keyfile);

	return keyfile;
}

void __connman_storage_close(GKeyFile *keyfile, gboolean save)
{
	gchar *pathname, *data = NULL;
	gsize length = 0;

	DBG("keyfile %p save %d", keyfile, save);

	if (save == FALSE) {
		g_key_file_free(keyfile);
		return;
	}

	pathname = g_strdup_printf("%s/%s.conf", STORAGEDIR,
					__connman_profile_active_ident());
	if (pathname == NULL)
		return;

	data = g_key_file_to_data(keyfile, &length, NULL);

	if (g_file_set_contents(pathname, data, length, NULL) == FALSE)
		connman_error("Failed to store information");

	g_free(data);

	g_free(pathname);

	g_key_file_free(keyfile);
}

int __connman_storage_load_global(void)
{
	GSList *list;

	DBG("");

	for (list = storage_list; list; list = list->next) {
		struct connman_storage *storage = list->data;

		if (storage->global_load) {
			if (storage->global_load() == 0)
				return 0;
		}
	}

	return -ENOENT;
}

int __connman_storage_save_global(void)
{
	GSList *list;

	DBG("");

	for (list = storage_list; list; list = list->next) {
		struct connman_storage *storage = list->data;

		if (storage->global_save) {
			if (storage->global_save() == 0)
				return 0;
		}
	}

	return -ENOENT;
}

int __connman_storage_load_device(struct connman_device *device)
{
	GSList *list;

	DBG("device %p", device);

	for (list = storage_list; list; list = list->next) {
		struct connman_storage *storage = list->data;

		if (storage->device_load) {
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
			if (storage->device_save(device) == 0)
				return 0;
		}
	}

	return -ENOENT;
}

int __connman_storage_load_service(struct connman_service *service)
{
	GSList *list;

	DBG("service %p", service);

	for (list = storage_list; list; list = list->next) {
		struct connman_storage *storage = list->data;

		if (storage->service_load) {
			if (storage->service_load(service) == 0)
				return 0;
		}
	}

	return -ENOENT;
}

int __connman_storage_save_service(struct connman_service *service)
{
	GSList *list;

	DBG("service %p", service);

	for (list = storage_list; list; list = list->next) {
		struct connman_storage *storage = list->data;

		if (storage->service_save) {
			if (storage->service_save(service) == 0)
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
