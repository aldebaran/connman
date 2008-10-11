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

#include <stdio.h>
#include <sys/stat.h>

#include <dbus/dbus.h>
#include <hal/libhal.h>

#include <connman/plugin.h>
#include <connman/element.h>
#include <connman/log.h>

static struct {
	const char *name;
	enum connman_element_subtype subtype;
} capabilities[] = {
	{ "net.80203", CONNMAN_ELEMENT_SUBTYPE_ETHERNET },
	{ "net.80211", CONNMAN_ELEMENT_SUBTYPE_WIFI     },
	{ "net.wimax", CONNMAN_ELEMENT_SUBTYPE_WIMAX    },
	{ "modem",     CONNMAN_ELEMENT_SUBTYPE_MODEM    },
	{ }
};

static GStaticMutex element_mutex = G_STATIC_MUTEX_INIT;
static GSList *element_list = NULL;

static void device_info(LibHalContext *ctx, const char *udi,
					struct connman_element *element)
{
	char *parent, *subsys, *value;

	parent = libhal_device_get_property_string(ctx, udi,
						"info.parent", NULL);

	subsys = libhal_device_get_property_string(ctx, udi,
						"linux.subsystem", NULL);

	value = libhal_device_get_property_string(ctx, udi,
						"info.linux.driver", NULL);
	if (value == NULL) {
		value = libhal_device_get_property_string(ctx, parent,
						"info.linux.driver", NULL);
		if (value != NULL)
			connman_element_add_static_property(element,
					"Driver", DBUS_TYPE_STRING, &value);
	}

	if (g_str_equal(subsys, "net") == TRUE ||
					g_str_equal(subsys, "tty") == TRUE) {
		value = libhal_device_get_property_string(ctx, parent,
							"info.vendor", NULL);
		if (value != NULL)
			connman_element_add_static_property(element,
					"Vendor", DBUS_TYPE_STRING, &value);

		value = libhal_device_get_property_string(ctx, parent,
							"info.product", NULL);
		if (value != NULL)
			connman_element_add_static_property(element,
					"Product", DBUS_TYPE_STRING, &value);
	}
}

static void device_netdev(LibHalContext *ctx, const char *udi,
					struct connman_element *element)
{
	if (element->subtype == CONNMAN_ELEMENT_SUBTYPE_ETHERNET ||
			element->subtype == CONNMAN_ELEMENT_SUBTYPE_WIFI ||
			element->subtype == CONNMAN_ELEMENT_SUBTYPE_WIMAX) {
		element->index = libhal_device_get_property_int(ctx,
						udi, "net.linux.ifindex", NULL);

		element->name = libhal_device_get_property_string(ctx,
						udi, "net.interface", NULL);
	}

	if (element->subtype == CONNMAN_ELEMENT_SUBTYPE_MODEM) {
		element->index = libhal_device_get_property_int(ctx,
						udi, "serial.port", NULL);

		element->name = libhal_device_get_property_string(ctx,
						udi, "serial.device", NULL);
	}
}

static void create_element(LibHalContext *ctx, const char *udi,
					enum connman_element_subtype subtype)
{
	struct connman_element *element;

	DBG("ctx %p udi %s", ctx, udi);

	if (subtype == CONNMAN_ELEMENT_SUBTYPE_ETHERNET) {
		char *sysfs_path, wimax_path[PATH_MAX];
		struct stat st;

		sysfs_path = libhal_device_get_property_string(ctx, udi,
						"linux.sysfs_path", NULL);
		if (sysfs_path != NULL) {
			snprintf(wimax_path, PATH_MAX, "%s/wimax", sysfs_path);

			if (stat(wimax_path, &st) == 0 &&
						(st.st_mode & S_IFDIR))
				subtype = CONNMAN_ELEMENT_SUBTYPE_WIMAX;
		}
	}

	element = connman_element_create(NULL);

	element->type = CONNMAN_ELEMENT_TYPE_DEVICE;
	element->subtype = subtype;

	device_info(ctx, udi, element);
	device_netdev(ctx, udi, element);

	if (element->name == NULL) {
		element->name = g_path_get_basename(udi);
		if (element->name == NULL) {
			connman_element_unref(element);
			return;
		}
	}

	g_static_mutex_lock(&element_mutex);

	connman_element_register(element, NULL);

	element_list = g_slist_append(element_list, element);

	g_static_mutex_unlock(&element_mutex);
}

static void device_added(LibHalContext *ctx, const char *udi)
{
	int i;

	DBG("ctx %p udi %s", ctx, udi);

	for (i = 0; capabilities[i].name; i++) {
		if (libhal_device_query_capability(ctx, udi,
					capabilities[i].name, NULL) == TRUE)
			create_element(ctx, udi, capabilities[i].subtype);
	}
}

static void device_removed(LibHalContext *ctx, const char *udi)
{
	struct connman_element *removal = NULL;
	GSList *list;
	gchar *name;

	DBG("ctx %p udi %s", ctx, udi);

	name = g_path_get_basename(udi);

	g_static_mutex_lock(&element_mutex);

	for (list = element_list; list; list = list->next) {
		struct connman_element *element = list->data;

		if (g_str_equal(element->name, name) == TRUE) {
			removal = element;
			break;
		}
	}

	if (removal != NULL) {
		element_list = g_slist_remove(element_list, removal);

		connman_element_unregister(removal);
		connman_element_unref(removal);
	}

	g_static_mutex_unlock(&element_mutex);

	g_free(name);
}

static void probe_capability(LibHalContext *ctx, const char *capability,
					enum connman_element_subtype subtype)
{
	char **list;
	int num;

	DBG("ctx %p capability %s", ctx, capability);

	list = libhal_find_device_by_capability(ctx, capability, &num, NULL);
	if (list) {
		char **tmp = list;

		while (*tmp) {
			create_element(ctx, *tmp, subtype);
			tmp++;
		}

		libhal_free_string_array(list);
	}
}

static void find_devices(LibHalContext *ctx)
{
	int i;

	DBG("ctx %p", ctx);

	for (i = 0; capabilities[i].name; i++)
		probe_capability(ctx, capabilities[i].name,
						capabilities[i].subtype);
}

static LibHalContext *hal_ctx = NULL;

static void libhal_init(void *data)
{
	DBusConnection *conn = data;

	DBG("conn %p", conn);

	if (hal_ctx != NULL)
		return;

	hal_ctx = libhal_ctx_new();
	if (hal_ctx == NULL)
		return;

	if (libhal_ctx_set_dbus_connection(hal_ctx, conn) == FALSE) {
		libhal_ctx_free(hal_ctx);
		return;
	}

	if (libhal_ctx_init(hal_ctx, NULL) == FALSE) {
		libhal_ctx_free(hal_ctx);
		return ;
	}

	libhal_ctx_set_device_added(hal_ctx, device_added);
	libhal_ctx_set_device_removed(hal_ctx, device_removed);

	//libhal_ctx_set_device_new_capability(hal_ctx, new_capability);
	//libhal_ctx_set_device_lost_capability(hal_ctx, lost_capability);

	find_devices(hal_ctx);
}

static void libhal_cleanup(void *data)
{
	DBusConnection *conn = data;
	GSList *list;

	DBG("conn %p", conn);

	g_static_mutex_lock(&element_mutex);

	for (list = element_list; list; list = list->next) {
		struct connman_element *element = list->data;

		connman_element_unregister(element);
		connman_element_unref(element);
	}

	g_slist_free(element_list);
	element_list = NULL;

	g_static_mutex_unlock(&element_mutex);

	if (hal_ctx == NULL)
		return;

	libhal_ctx_shutdown(hal_ctx, NULL);

	libhal_ctx_free(hal_ctx);

	hal_ctx = NULL;
}

static int hal_init(void)
{
	DBusConnection *conn;

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (conn == NULL)
		return -EIO;

	libhal_init(conn);

	return 0;
}

static void hal_exit(void)
{
	DBusConnection *conn;

	conn = libhal_ctx_get_dbus_connection(hal_ctx);
	if (conn == NULL)
		return;

	libhal_cleanup(conn);

	dbus_connection_unref(conn);
}

CONNMAN_PLUGIN_DEFINE("hal", "Hardware detection plugin", VERSION,
							hal_init, hal_exit)
