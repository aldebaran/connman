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

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

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

struct connman_iface *__connman_iface_find(int index)
{
	GSList *list;

	for (list = interfaces; list; list = list->next) {
		struct connman_iface *iface = list->data;

		if (iface->index == index)
			return iface;
	}

	return NULL;
}

void __connman_iface_list(DBusMessageIter *iter)
{
	GSList *list;

	DBG("");

	for (list = interfaces; list; list = list->next) {
		struct connman_iface *iface = list->data;

		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_OBJECT_PATH, &iface->path);
	}
}

int connman_iface_update(struct connman_iface *iface,
					enum connman_iface_state state)
{
	switch (state) {
	case CONNMAN_IFACE_STATE_ACTIVE:
		if (iface->type == CONNMAN_IFACE_TYPE_80211) {
			if (iface->driver->scan)
				iface->driver->scan(iface);

			if (iface->driver->connect)
				iface->driver->connect(iface, NULL);
		}
		break;

	case CONNMAN_IFACE_STATE_CONNECTED:
		__connman_dhcp_request(iface);
		break;

	default:
		break;
	}

	iface->state = state;

	return 0;
}

void connman_iface_indicate_carrier(struct connman_iface *iface, int carrier)
{
	DBG("iface %p carrier %d", iface, carrier);
}

int connman_iface_get_ipv4(struct connman_iface *iface,
						struct connman_ipv4 *ipv4)
{
	struct {
		struct nlmsghdr hdr;
		struct rtgenmsg msg;
	} req;

	if ((iface->flags & CONNMAN_IFACE_FLAG_RTNL) == 0)
		return -1;

	DBG("iface %p ipv4 %p", iface, ipv4);

	memset(&req, 0, sizeof(req));
	req.hdr.nlmsg_len = sizeof(req);
	req.hdr.nlmsg_type = RTM_GETADDR;
	req.hdr.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
	req.hdr.nlmsg_pid = 0;
	req.hdr.nlmsg_seq = 4711;
	req.msg.rtgen_family = AF_INET;

	__connman_rtnl_send(&req, sizeof(req));

	return 0;
}

int connman_iface_set_ipv4(struct connman_iface *iface,
						struct connman_ipv4 *ipv4)
{
	if ((iface->flags & CONNMAN_IFACE_FLAG_RTNL) == 0)
		return -1;

	DBG("iface %p ipv4 %p", iface, ipv4);

	return 0;
}

static DBusMessage *enable_iface(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_iface *iface = data;
	struct connman_iface_driver *driver = iface->driver;
	DBusMessage *reply;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	if (driver->activate)
		driver->activate(iface);

	dbus_message_append_args(reply, DBUS_TYPE_INVALID);

	return reply;
}

static GDBusMethodTable iface_methods[] = {
	{ "Enable", "", "", enable_iface },
	{ },
};

static dbus_bool_t get_type(DBusConnection *conn,
					DBusMessageIter *iter, void *data)
{
	struct connman_iface *iface = data;
	const char *type;

	DBG("iface %p", iface);

	switch (iface->type) {
	case CONNMAN_IFACE_TYPE_80203:
		type = "80203";
		break;
	case CONNMAN_IFACE_TYPE_80211:
		type = "80211";
		break;
	case CONNMAN_IFACE_TYPE_WIMAX:
		type = "wimax";
		break;
	case CONNMAN_IFACE_TYPE_BLUETOOTH:
		type = "bluetooth";
		break;
	default:
		type = "unknown";
		break;
	}

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &type);

	return TRUE;
}

static GDBusPropertyTable iface_properties[] = {
	{ "Type", "s", get_type },
	{ },
};

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

	iface->index = -1;

	if (g_str_has_prefix(driver->capability, "net") == TRUE)
		iface->index = libhal_device_get_property_int(ctx, udi,
						"net.linux.ifindex", NULL);

	iface->type = CONNMAN_IFACE_TYPE_UNKNOWN;
	iface->flags = 0;
	iface->state = CONNMAN_IFACE_STATE_UNKNOWN;

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

	if (iface->flags & CONNMAN_IFACE_FLAG_IPV4) {
		if (driver->get_ipv4)
			driver->get_ipv4(iface, &iface->ipv4);
		else
			connman_iface_get_ipv4(iface, &iface->ipv4);

		DBG("address %s", inet_ntoa(iface->ipv4.address));
	}

	g_dbus_register_interface(conn, iface->path,
					CONNMAN_IFACE_INTERFACE,
					iface_methods, NULL, iface_properties);

	g_dbus_emit_signal(conn, CONNMAN_MANAGER_PATH,
					CONNMAN_MANAGER_INTERFACE,
					"InterfaceAdded",
					DBUS_TYPE_OBJECT_PATH, &iface->path,
					DBUS_TYPE_INVALID);

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
			g_dbus_emit_signal(conn, CONNMAN_MANAGER_PATH,
					CONNMAN_MANAGER_INTERFACE,
					"InterfaceRemoved",
					DBUS_TYPE_OBJECT_PATH, &iface->path,
					DBUS_TYPE_INVALID);
			interfaces = g_slist_remove(interfaces, iface);
			g_dbus_unregister_interface(conn, iface->path,
						CONNMAN_IFACE_INTERFACE);
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

		g_dbus_emit_signal(conn, CONNMAN_MANAGER_PATH,
					CONNMAN_MANAGER_INTERFACE,
					"InterfaceRemoved",
					DBUS_TYPE_OBJECT_PATH, &iface->path,
					DBUS_TYPE_INVALID);

		g_dbus_unregister_interface(conn, iface->path,
						CONNMAN_IFACE_INTERFACE);

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
