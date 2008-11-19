/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2008  Intel Corporation. All rights reserved.
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

int __connman_storage_init(void)
{
	DBG("");

	return 0;
}

void __connman_storage_cleanup(void)
{
	DBG("");
}

int __connman_element_load(struct connman_element *element)
{
	DBG("element %p name %s", element, element->name);

	return 0;
}

static void do_update(GKeyFile *keyfile, struct connman_element *element)
{
	GSList *list;

	DBG("element %p name %s", element, element->name);

	g_key_file_set_string(keyfile, element->path, "Name", element->name);

	g_key_file_set_boolean(keyfile, element->path, "Enabled",
							element->enabled);

	connman_element_lock(element);

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

	connman_element_unlock(element);
}

int __connman_element_store(struct connman_element *element)
{
	GKeyFile *keyfile;
	gchar *pathname, *data = NULL;
	gsize length;

	DBG("element %p name %s", element, element->name);

	pathname = g_strdup_printf("%s/elements.conf", STORAGEDIR);
	if (pathname == NULL)
		return -ENOMEM;

	keyfile = g_key_file_new();

	if (g_file_get_contents(pathname, &data, &length, NULL) == FALSE)
		goto update;

	if (length > 0) {
		if (g_key_file_load_from_data(keyfile, data, length,
				G_KEY_FILE_KEEP_COMMENTS, NULL) == FALSE)
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
