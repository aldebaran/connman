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
#include <unistd.h>

#include "connman.h"

#define PROFILE_SUFFIX	"profile"
#define CONFIG_SUFFIX	"config"

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

GKeyFile *__connman_storage_open(const char *ident, const char *suffix)
{
	GKeyFile *keyfile;
	gchar *pathname, *data = NULL;
	gboolean result;
	gsize length;

	DBG("ident %s suffix %s", ident, suffix);

	pathname = g_strdup_printf("%s/%s.%s", STORAGEDIR, ident, suffix);
	if (pathname == NULL)
		return NULL;

	result = g_file_get_contents(pathname, &data, &length, NULL);

	g_free(pathname);

	keyfile = g_key_file_new();

	if (result == FALSE)
		goto done;

	if (length > 0)
		g_key_file_load_from_data(keyfile, data, length, 0, NULL);

	g_free(data);

done:
	DBG("keyfile %p", keyfile);

	return keyfile;
}

void __connman_storage_close(const char *ident, const char *suffix,
					GKeyFile *keyfile, gboolean save)
{
	gchar *pathname, *data = NULL;
	gsize length = 0;

	DBG("ident %s suffix %s keyfile %p save %d",
					ident, suffix, keyfile, save);

	if (save == FALSE) {
		g_key_file_free(keyfile);
		return;
	}

	pathname = g_strdup_printf("%s/%s.%s", STORAGEDIR, ident, suffix);
	if (pathname == NULL)
		return;

	data = g_key_file_to_data(keyfile, &length, NULL);

	if (g_file_set_contents(pathname, data, length, NULL) == FALSE)
		connman_error("Failed to store information");

	g_free(data);

	g_free(pathname);

	g_key_file_free(keyfile);
}

void __connman_storage_delete(const char *ident, const char *suffix)
{
	gchar *pathname;

	DBG("ident %s suffix %s", ident, suffix);

	pathname = g_strdup_printf("%s/%s.%s", STORAGEDIR, ident, suffix);
	if (pathname == NULL)
		return;

	if (unlink(pathname) < 0)
		connman_error("Failed to remove %s", pathname);
}

GKeyFile *__connman_storage_open_profile(const char *ident)
{
	return __connman_storage_open(ident, PROFILE_SUFFIX);
}

void __connman_storage_close_profile(const char *ident,
					GKeyFile *keyfile, gboolean save)
{
	__connman_storage_close(ident, PROFILE_SUFFIX, keyfile, save);
}

void __connman_storage_delete_profile(const char *ident)
{
	__connman_storage_delete(ident, PROFILE_SUFFIX);
}

GKeyFile *__connman_storage_open_config(const char *ident)
{
	return __connman_storage_open(ident, CONFIG_SUFFIX);
}

void __connman_storage_close_config(const char *ident,
					GKeyFile *keyfile, gboolean save)
{
	__connman_storage_close(ident, CONFIG_SUFFIX, keyfile, save);
}

void __connman_storage_delete_config(const char *ident)
{
	__connman_storage_delete(ident, CONFIG_SUFFIX);
}

int __connman_storage_init_profile(void)
{
	GSList *list;

	DBG("");

	for (list = storage_list; list; list = list->next) {
		struct connman_storage *storage = list->data;

		if (storage->profile_init) {
			if (storage->profile_init() == 0)
				return 0;
		}
	}

	return -ENOENT;
}

int __connman_storage_load_profile(struct connman_profile *profile)
{
	GSList *list;

	DBG("profile %p", profile);

	for (list = storage_list; list; list = list->next) {
		struct connman_storage *storage = list->data;

		if (storage->profile_load) {
			if (storage->profile_load(profile) == 0)
				return 0;
		}
	}

	return -ENOENT;
}

int __connman_storage_save_profile(struct connman_profile *profile)
{
	GSList *list;

	DBG("profile %p", profile);

	for (list = storage_list; list; list = list->next) {
		struct connman_storage *storage = list->data;

		if (storage->profile_save) {
			if (storage->profile_save(profile) == 0)
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

int __connman_storage_load_technology(struct connman_technology *technology)
{
	GSList *list;

	DBG("technology %p", technology);

	for (list = storage_list; list; list = list->next) {
		struct connman_storage *storage = list->data;

		if (storage->tech_load) {
			if (storage->tech_load(technology) == 0)
				return 0;
		}
	}

	return -ENOENT;
}

int __connman_storage_save_technology(struct connman_technology *technology)
{
	GSList *list;

	DBG("technology %p", technology);

	for (list = storage_list; list; list = list->next) {
		struct connman_storage *storage = list->data;

		if (storage->tech_save) {
			if (storage->tech_save(technology) == 0)
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
