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

#include <glib.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE

#include <connman/dbus.h>

#define NM_SERVICE    "org.freedesktop.NetworkManager"
#define NM_PATH       "/org/freedesktop/NetworkManager"
#define NM_INTERFACE  NM_SERVICE

int __connman_dbus_init(DBusConnection *conn);
void __connman_dbus_cleanup(void);

DBusMessage *__connman_error_failed(DBusMessage *msg);
DBusMessage *__connman_error_invalid_arguments(DBusMessage *msg);
DBusMessage *__connman_error_permission_denied(DBusMessage *msg);
DBusMessage *__connman_error_not_supported(DBusMessage *msg);

int __connman_selftest(void);

int __connman_storage_init(void);
void __connman_storage_cleanup(void);

int __connman_manager_init(DBusConnection *conn, gboolean compat);
void __connman_manager_cleanup(void);

int __connman_agent_init(DBusConnection *conn);
void __connman_agent_cleanup(void);

int __connman_agent_register(const char *sender, const char *path);
int __connman_agent_unregister(const char *sender, const char *path);

int __connman_profile_init(DBusConnection *conn);
void __connman_profile_cleanup(void);

void __connman_profile_list(DBusMessageIter *iter);

#include <connman/log.h>

int __connman_log_init(gboolean detach, gboolean debug);
void __connman_log_cleanup(void);

#include <connman/plugin.h>

int __connman_plugin_init(void);
void __connman_plugin_cleanup(void);

#include <connman/security.h>

int __connman_security_check_privileges(DBusMessage *message);

#include <connman/ipv4.h>

const char *__connman_ipv4_method2string(enum connman_ipv4_method method);
enum connman_ipv4_method __connman_ipv4_string2method(const char *method);

#include <connman/resolver.h>

int __connman_resolver_selftest(void);

#include <connman/driver.h>

void __connman_driver_rescan(struct connman_driver *driver);

#include <connman/element.h>

int __connman_element_init(DBusConnection *conn, const char *device);
void __connman_element_start(void);
void __connman_element_stop(void);
void __connman_element_cleanup(void);

typedef void (* element_cb_t) (struct connman_element *element,
							gpointer user_data);

void __connman_element_foreach(struct connman_element *element,
				enum connman_element_type type,
				element_cb_t callback, gpointer user_data);
void __connman_element_list(struct connman_element *element,
					enum connman_element_type type,
							DBusMessageIter *iter);
int __connman_element_count(struct connman_element *element,
					enum connman_element_type type);

const char *__connman_element_type2string(enum connman_element_type type);
const char *__connman_element_subtype2string(enum connman_element_subtype type);

const char *__connman_element_policy2string(enum connman_element_policy policy);
enum connman_element_policy __connman_element_string2policy(const char *policy);

int __connman_element_load(struct connman_element *element);
int __connman_element_store(struct connman_element *element);

static inline void __connman_element_lock(struct connman_element *element)
{
}

static inline void __connman_element_unlock(struct connman_element *element)
{
}

int __connman_detect_init(void);
void __connman_detect_cleanup(void);

#ifdef HAVE_UDEV
int __connman_udev_init(void);
void __connman_udev_cleanup(void);
#else
static inline int __connman_udev_init(void)
{
	return 0;
}

static inline void __connman_udev_cleanup(void)
{
}
#endif

#include <connman/device.h>

int __connman_device_init(void);
void __connman_device_cleanup(void);

#include <connman/network.h>

int __connman_network_init(void);
void __connman_network_cleanup(void);

void __connman_network_set_device(struct connman_network *network,
					struct connman_device *device);

#include <connman/rtnl.h>

int __connman_rtnl_init(void);
void __connman_rtnl_cleanup(void);

int __connman_rtnl_send(const void *buf, size_t len);
