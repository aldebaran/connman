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
