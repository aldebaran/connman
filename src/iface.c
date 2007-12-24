/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007  Intel Corporation. All rights reserved.
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

#include <string.h>
#include <arpa/inet.h>

#include <glib.h>
#include <gdbus.h>

#include <hal/libhal.h>

#include "connman.h"

static GSList *drivers = NULL;

int connman_iface_register(struct connman_iface_driver *driver)
{
	DBG("driver %p", driver);

	drivers = g_slist_append(drivers, driver);

	return 0;
}

void connman_iface_unregister(struct connman_iface_driver *driver)
{
	DBG("driver %p", driver);

	drivers = g_slist_remove(drivers, driver);
}

static GSList *interfaces = NULL;

static void device_free(void *data)
{
	struct connman_iface *iface = data;

	DBG("iface %p", iface);

	if (iface->driver && iface->driver->remove)
		iface->driver->remove(iface);

	g_free(iface->path);
	g_free(iface->udi);
	g_free(iface->sysfs);
	g_free(iface);
}

static int probe_device(LibHalContext *ctx,
			struct connman_iface_driver *driver, const char *udi)
{
	DBusConnection *conn;
	struct connman_iface *iface;
	char *temp, *sysfs;
	int err;

	DBG("ctx %p driver %p udi %s", ctx, driver, udi);

	if (!driver->probe)
		return -1;

	iface = g_try_new0(struct connman_iface, 1);
	if (iface == NULL)
		return -1;

	temp = g_path_get_basename(udi);
	iface->path = g_strdup_printf("%s/%s", CONNMAN_IFACE_BASEPATH, temp);
	g_free(temp);

	iface->udi = g_strdup(udi);

	DBG("path %s", iface->path);

	sysfs = libhal_device_get_property_string(ctx, udi,
						"linux.sysfs_path", NULL);
	if (sysfs != NULL)
		iface->sysfs = g_strdup(sysfs);

	iface->type = CONNMAN_IFACE_TYPE_UNKNOWN;
	iface->flags = 0;

	DBG("iface %p", iface);

	err = driver->probe(iface);
	if (err < 0) {
		device_free(iface);
		return -1;
	}

	iface->driver = driver;

	conn = libhal_ctx_get_dbus_connection(ctx);

	g_dbus_register_object(conn, iface->path, iface, device_free);

	interfaces = g_slist_append(interfaces, iface);

	if ((iface->flags & CONNMAN_IFACE_FLAG_IPV4) &&
						driver->get_ipv4) {
		driver->get_ipv4(iface, &iface->ipv4);

		DBG("address %s", inet_ntoa(iface->ipv4.address));
	}

	return 0;
}

static void device_added(LibHalContext *ctx, const char *udi)
{
	GSList *list;

	DBG("ctx %p udi %s", ctx, udi);

	for (list = drivers; list; list = list->next) {
		struct connman_iface_driver *driver = list->data;

		if (driver->capability == NULL)
			continue;

		if (libhal_device_query_capability(ctx, udi,
					driver->capability, NULL) == TRUE) {
			if (probe_device(ctx, driver, udi) == 0)
				break;
		}
	}
}

static void device_removed(LibHalContext *ctx, const char *udi)
{
	DBusConnection *conn;
	GSList *list;

	DBG("ctx %p udi %s", ctx, udi);

	conn = libhal_ctx_get_dbus_connection(ctx);

	for (list = interfaces; list; list = list->next) {
		struct connman_iface *iface = list->data;

		if (strcmp(udi, iface->udi) == 0) {
			interfaces = g_slist_remove(interfaces, iface);
			g_dbus_unregister_object(conn, iface->path);
			break;
		}
	}
}

static void probe_driver(LibHalContext *ctx,
				struct connman_iface_driver *driver)
{
	char **list;
	int num;

	DBG("ctx %p driver %p", ctx, driver);

	list = libhal_find_device_by_capability(ctx,
					driver->capability, &num, NULL);
	if (list) {
		char **tmp = list;

		while (*tmp) {
			probe_device(ctx, driver, *tmp);
			tmp++;
		}

		libhal_free_string_array(list);
	}
}

static void find_devices(LibHalContext *ctx)
{
	GSList *list;

	DBG("ctx %p", ctx);

	for (list = drivers; list; list = list->next) {
		struct connman_iface_driver *driver = list->data;

		DBG("driver %p", driver);

		if (driver->capability == NULL)
			continue;

		probe_driver(ctx, driver);
	}
}

static LibHalContext *hal_ctx = NULL;

static void hal_init(void *data)
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

static void hal_cleanup(void *data)
{
	DBusConnection *conn = data;
	GSList *list;

	DBG("conn %p", conn);

	if (hal_ctx == NULL)
		return;

	for (list = interfaces; list; list = list->next) {
		struct connman_iface *iface = list->data;

		DBG("path %s", iface->path);

		g_dbus_unregister_object(conn, iface->path);
	}

	g_slist_free(interfaces);

	interfaces = NULL;

	libhal_ctx_shutdown(hal_ctx, NULL);

	libhal_ctx_free(hal_ctx);

	hal_ctx = NULL;
}

static DBusConnection *connection = NULL;
static guint hal_watch = 0;

int __connman_iface_init(DBusConnection *conn)
{
	DBG("conn %p", conn);

	connection = dbus_connection_ref(conn);
	if (connection == NULL)
		return -1;

	hal_init(connection);

	hal_watch = g_dbus_add_watch(connection, "org.freedesktop.Hal",
				hal_init, hal_cleanup, connection, NULL);

	return 0;
}

void __connman_iface_cleanup(void)
{
	DBG("conn %p", connection);

	g_dbus_remove_watch(connection, hal_watch);

	hal_cleanup(connection);

	dbus_connection_unref(connection);
}
