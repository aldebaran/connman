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

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/route.h>

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
	case CONNMAN_IFACE_STATE_ENABLED:
		if (iface->type == CONNMAN_IFACE_TYPE_80211) {
			if (iface->driver->connect)
				iface->driver->connect(iface, NULL);
		}
		break;

	case CONNMAN_IFACE_STATE_CARRIER:
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
	req.hdr.nlmsg_len = sizeof(req.hdr) + sizeof(req.msg);
	req.hdr.nlmsg_type = RTM_GETADDR;
	req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.hdr.nlmsg_pid = 0;
	req.hdr.nlmsg_seq = 4711;
	req.msg.rtgen_family = AF_INET;

	__connman_rtnl_send(&req, sizeof(req));

	return 0;
}

int connman_iface_set_ipv4(struct connman_iface *iface,
						struct connman_ipv4 *ipv4)
{
	struct ifreq ifr;
	struct rtentry rt;
	struct sockaddr_in *addr;
	char cmd[128];
	int sk, err;

	if ((iface->flags & CONNMAN_IFACE_FLAG_RTNL) == 0)
		return -1;

	DBG("iface %p ipv4 %p", iface, ipv4);

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = iface->index;

	if (ioctl(sk, SIOCGIFNAME, &ifr) < 0) {
		close(sk);
		return -1;
	}

	DBG("ifname %s", ifr.ifr_name);

	addr = (struct sockaddr_in *) &ifr.ifr_addr;
	addr->sin_family = AF_INET;
	addr->sin_addr = ipv4->address;

	err = ioctl(sk, SIOCSIFADDR, &ifr);

	if (err < 0)
		DBG("address setting failed (%s)", strerror(errno));

	addr = (struct sockaddr_in *) &ifr.ifr_netmask;
	addr->sin_family = AF_INET;
	addr->sin_addr = ipv4->netmask;

	err = ioctl(sk, SIOCSIFNETMASK, &ifr);

	if (err < 0)
		DBG("netmask setting failed (%s)", strerror(errno));

	addr = (struct sockaddr_in *) &ifr.ifr_broadaddr;
	addr->sin_family = AF_INET;
	addr->sin_addr = ipv4->broadcast;

	err = ioctl(sk, SIOCSIFBRDADDR, &ifr);

	if (err < 0)
		DBG("broadcast setting failed (%s)", strerror(errno));

	memset(&rt, 0, sizeof(rt));
	rt.rt_flags = RTF_UP | RTF_GATEWAY;

	addr = (struct sockaddr_in *) &rt.rt_dst;
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = INADDR_ANY;

	addr = (struct sockaddr_in *) &rt.rt_gateway;
	addr->sin_family = AF_INET;
	addr->sin_addr = ipv4->gateway;

	addr = (struct sockaddr_in *) &rt.rt_genmask;
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = INADDR_ANY;

	err = ioctl(sk, SIOCADDRT, &rt);

	close(sk);

	if (err < 0) {
		DBG("default route failed (%s)", strerror(errno));
		return -1;
	}

	sprintf(cmd, "echo \"nameserver %s\" | resolvconf -a %s",
				inet_ntoa(ipv4->nameserver), ifr.ifr_name);

	DBG("%s", cmd);

	system(cmd);

	return 0;
}

int connman_iface_clear_ipv4(struct connman_iface *iface)
{
	struct ifreq ifr;
	struct sockaddr_in *addr;
	char cmd[128];
	int sk, err;

	if ((iface->flags & CONNMAN_IFACE_FLAG_RTNL) == 0)
		return -1;

	DBG("iface %p", iface);

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = iface->index;

	if (ioctl(sk, SIOCGIFNAME, &ifr) < 0) {
		close(sk);
		return -1;
	}

	DBG("ifname %s", ifr.ifr_name);

	addr = (struct sockaddr_in *) &ifr.ifr_addr;
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = INADDR_ANY;

	//err = ioctl(sk, SIOCDIFADDR, &ifr);
	err = ioctl(sk, SIOCSIFADDR, &ifr);

	close(sk);

	if (err < 0 && errno != EADDRNOTAVAIL) {
		DBG("address removal failed (%s)", strerror(errno));
		return -1;
	}

	sprintf(cmd, "resolvconf -d %s", ifr.ifr_name);

	DBG("%s", cmd);

	system(cmd);

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

static DBusMessage *scan_iface(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_iface *iface = data;
	struct connman_iface_driver *driver = iface->driver;
	DBusMessage *reply;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	if (driver->scan)
		driver->scan(iface);

	dbus_message_append_args(reply, DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *set_network(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_iface *iface = data;
	struct connman_iface_driver *driver = iface->driver;
	DBusMessage *reply;
	const char *network;

	DBG("conn %p", conn);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &network,
							DBUS_TYPE_INVALID);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	if (driver->set_network)
		driver->set_network(iface, network);

	dbus_message_append_args(reply, DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *set_passphrase(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_iface *iface = data;
	struct connman_iface_driver *driver = iface->driver;
	DBusMessage *reply;
	const char *passphrase;

	DBG("conn %p", conn);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &passphrase,
							DBUS_TYPE_INVALID);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	if (driver->set_passphrase)
		driver->set_passphrase(iface, passphrase);

	dbus_message_append_args(reply, DBUS_TYPE_INVALID);

	return reply;
}

static GDBusMethodTable iface_methods[] = {
	{ "Enable",        "",  "", enable_iface   },
	{ "Scan",          "",  "", scan_iface     },
	{ "SetNetwork",    "s", "", set_network    },
	{ "SetPassphrase", "s", "", set_passphrase },
	{ },
};

static void device_free(void *data)
{
	struct connman_iface *iface = data;

	DBG("iface %p", iface);

	connman_iface_clear_ipv4(iface);

	if (iface->driver && iface->driver->remove)
		iface->driver->remove(iface);

	g_free(iface->path);
	g_free(iface->udi);
	g_free(iface->sysfs);
	g_free(iface->device.driver);
	g_free(iface->device.vendor);
	g_free(iface->device.product);
	g_free(iface);
}

static void detect_device_info(LibHalContext *ctx, struct connman_iface *iface)
{
	char *parent, *subsys, *value;

	parent = libhal_device_get_property_string(ctx, iface->udi,
						"info.parent", NULL);

	subsys = libhal_device_get_property_string(ctx, iface->udi,
						"linux.subsystem", NULL);

	value = libhal_device_get_property_string(ctx, iface->udi,
						"info.linux.driver", NULL);
	if (value == NULL) {
		value = libhal_device_get_property_string(ctx, parent,
						"info.linux.driver", NULL);
		if (value != NULL)
			iface->device.driver = g_strdup(value);
	}

	if (strcmp(subsys, "net") == 0) {
		value = libhal_device_get_property_string(ctx, parent,
							"info.vendor", NULL);
		if (value != NULL)
			iface->device.vendor = g_strdup(value);

		value = libhal_device_get_property_string(ctx, parent,
							"info.product", NULL);
		if (value != NULL)
			iface->device.product = g_strdup(value);
	}
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

	detect_device_info(ctx, iface);

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
					iface_methods, NULL, NULL);

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
