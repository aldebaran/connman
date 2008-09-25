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

#include <dbus/dbus.h>

#include <glib.h>
#include <gmodule.h>

#include "connman.h"

static GSList *plugins = NULL;

struct connman_plugin {
	GModule *module;
	struct connman_plugin_desc *desc;
};

static gboolean add_plugin(GModule *module, struct connman_plugin_desc *desc)
{
	struct connman_plugin *plugin;

	plugin = g_try_new0(struct connman_plugin, 1);
	if (plugin == NULL)
		return FALSE;

	plugin->module = module;
	plugin->desc = desc;

	plugins = g_slist_append(plugins, plugin);

	desc->init();

	return TRUE;
}

static void load_plugins(const gchar *path)
{
	GDir *dir;
	const gchar *file;
	gchar *filename;

	dir = g_dir_open(path, 0, NULL);
	if (dir != NULL) {
		while ((file = g_dir_read_name(dir)) != NULL) {
			GModule *module;
			struct connman_plugin_desc *desc;

			if (g_str_has_prefix(file, "lib") == TRUE ||
					g_str_has_suffix(file, ".so") == FALSE)
				continue;

			filename = g_build_filename(path, file, NULL);

			module = g_module_open(filename, 0);
			if (module == NULL) {
				g_warning("Can't load %s: %s", filename,
							g_module_error());
				continue;
			}

			g_free(filename);

			DBG("%s", g_module_name(module));

			if (g_module_symbol(module, "connman_plugin_desc",
						(gpointer) &desc) == FALSE) {
				g_warning("Can't load symbol");
				g_module_close(module);
				continue;
			}

			if (desc == NULL || desc->init == NULL) {
				g_module_close(module);
				continue;
			}

			if (add_plugin(module, desc) == FALSE)
				g_module_close(module);
		}

		g_dir_close(dir);
	}
}

int __connman_plugin_init(void)
{
	DBG("");

	if (g_module_supported() == FALSE) {
		g_warning("Modules not supported: %s", g_module_error());
		return FALSE;
	}

	load_plugins(PLUGINDIR);

	return 0;
}

void __connman_plugin_cleanup(void)
{
	GSList *list;

	DBG("");

	for (list = plugins; list; list = list->next) {
		struct connman_plugin *plugin = list->data;

		DBG("%s", g_module_name(plugin->module));

		if (plugin->desc->exit)
			plugin->desc->exit();

		g_module_close(plugin->module);

		g_free(plugin);
	}

	g_slist_free(plugins);
}
