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

#ifndef __CONNMAN_PLUGIN_H
#define __CONNMAN_PLUGIN_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef CONNMAN_API_SUBJECT_TO_CHANGE
#error "Please define CONNMAN_API_SUBJECT_TO_CHANGE to acknowledge your \
understanding that ConnMan hasn't reached a stable API."
#endif

/**
 * SECTION:plugin
 * @title: Plugin premitives
 * @short_description: Functions for declaring plugins
 */

struct connman_plugin_desc {
	const char *name;
	const char *description;
	const char *version;
	int (*init) (void);
	void (*exit) (void);
};

/**
 * CONNMAN_PLUGIN_DEFINE:
 * @name: plugin name
 * @description: plugin description
 * @version: plugin version string
 * @init: init function called on plugin loading
 * @exit: exit function called on plugin removal
 *
 * Macro for defining a plugin descriptor
 *
 * |[
 * #include <connman/plugin.h>
 *
 * static int example_init(void)
 * {
 * 	return 0;
 * }
 *
 * static void example_exit(void)
 * {
 * }
 *
 * CONNMAN_PLUGIN_DEFINE(example, "Example plugin", VERSION,
 * 					example_init, example_exit)
 * ]|
 */
#define CONNMAN_PLUGIN_DEFINE(name, description, version, init, exit) \
		struct connman_plugin_desc connman_plugin_desc = { \
			#name, description, version, init, exit \
		};

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_PLUGIN_H */
