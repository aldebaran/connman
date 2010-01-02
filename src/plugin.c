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

#include <dlfcn.h>

#include <glib.h>

#ifdef CONNMAN_PLUGIN_BUILTIN
#undef CONNMAN_PLUGIN_BUILTIN
#endif

#include "connman.h"

/*
 * Plugins that are using libraries with threads and their own mainloop
 * will crash on exit. This is a bug inside these libraries, but there is
 * nothing much that can be done about it.
 */
#ifdef NEED_THREADS
#define PLUGINFLAG (RTLD_NOW | RTLD_NODELETE)
#else
#define PLUGINFLAG (RTLD_NOW)
#endif

static GSList *plugins = NULL;

struct connman_plugin {
	void *handle;
	gboolean active;
	struct connman_plugin_desc *desc;
};

static gint compare_priority(gconstpointer a, gconstpointer b)
{
	const struct connman_plugin *plugin1 = a;
	const struct connman_plugin *plugin2 = b;

	return plugin2->desc->priority - plugin1->desc->priority;
}

static gboolean add_plugin(void *handle, struct connman_plugin_desc *desc)
{
	struct connman_plugin *plugin;

	if (desc->init == NULL)
		return FALSE;

	if (g_str_equal(desc->version, CONNMAN_VERSION) == FALSE) {
		connman_error("Version mismatch for %s", desc->description);
		return FALSE;
	}

	plugin = g_try_new0(struct connman_plugin, 1);
	if (plugin == NULL)
		return FALSE;

	plugin->handle = handle;
	plugin->active = FALSE;
	plugin->desc = desc;

	plugins = g_slist_insert_sorted(plugins, plugin, compare_priority);

	return TRUE;
}

static gboolean check_plugin(struct connman_plugin_desc *desc,
				const char *pattern, const char *exclude)
{
	if (exclude != NULL &&
			g_pattern_match_simple(exclude, desc->name) == TRUE) {
		connman_info("Excluding %s", desc->description);
		return FALSE;
	}

	if (pattern != NULL &&
			g_pattern_match_simple(pattern, desc->name) == FALSE) {
		connman_info("Ignoring %s", desc->description);
		return FALSE;
	}

	return TRUE;
}

#include "builtin.h"

int __connman_plugin_init(const char *pattern, const char *exclude)
{
	GSList *list;
	GDir *dir;
	const gchar *file;
	gchar *filename;
	unsigned int i;

	DBG("");

	for (i = 0; __connman_builtin[i]; i++) {
		if (check_plugin(__connman_builtin[i],
						pattern, exclude) == FALSE)
			continue;

		add_plugin(NULL, __connman_builtin[i]);
	}

	dir = g_dir_open(PLUGINDIR, 0, NULL);
	if (dir != NULL) {
		while ((file = g_dir_read_name(dir)) != NULL) {
			void *handle;
			struct connman_plugin_desc *desc;

			if (g_str_has_prefix(file, "lib") == TRUE ||
					g_str_has_suffix(file, ".so") == FALSE)
				continue;

			filename = g_build_filename(PLUGINDIR, file, NULL);

			handle = dlopen(filename, PLUGINFLAG);
			if (handle == NULL) {
				connman_error("Can't load %s: %s",
							filename, dlerror());
				g_free(filename);
				continue;
			}

			g_free(filename);

			desc = dlsym(handle, "connman_plugin_desc");
			if (desc == NULL) {
				connman_error("Can't load symbol: %s",
								dlerror());
				dlclose(handle);
				continue;
			}

			if (check_plugin(desc, pattern, exclude) == FALSE) {
				dlclose(handle);
				continue;
			}

			if (add_plugin(handle, desc) == FALSE)
				dlclose(handle);
		}

		g_dir_close(dir);
	}

	for (list = plugins; list; list = list->next) {
		struct connman_plugin *plugin = list->data;

		if (plugin->desc->init() < 0)
			continue;

		plugin->active = TRUE;
	}

	return 0;
}

void __connman_plugin_cleanup(void)
{
	GSList *list;

	DBG("");

	for (list = plugins; list; list = list->next) {
		struct connman_plugin *plugin = list->data;

		if (plugin->active == TRUE && plugin->desc->exit)
			plugin->desc->exit();

		if (plugin->handle != NULL)
			dlclose(plugin->handle);

		g_free(plugin);
	}

	g_slist_free(plugins);
}
