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
DBusMessage *__connman_error_not_implemented(DBusMessage *msg);
DBusMessage *__connman_error_no_carrier(DBusMessage *msg);

int __connman_selftest(void);

int __connman_manager_init(DBusConnection *conn, gboolean compat);
void __connman_manager_cleanup(void);

int __connman_agent_init(DBusConnection *conn);
void __connman_agent_cleanup(void);

int __connman_agent_register(const char *sender, const char *path);
int __connman_agent_unregister(const char *sender, const char *path);

int __connman_profile_init(DBusConnection *conn);
void __connman_profile_cleanup(void);

void __connman_profile_list(DBusMessageIter *iter);
const char *__connman_profile_active(void);

void __connman_profile_changed(void);

#include <connman/log.h>

int __connman_log_init(gboolean detach, gboolean debug);
void __connman_log_cleanup(void);

void __connman_toggle_debug(void);
gboolean __connman_debug_enabled(void);

#include <connman/plugin.h>

int __connman_plugin_init(const char *pattern, const char *exclude);
void __connman_plugin_cleanup(void);

#include <connman/security.h>

int __connman_security_check_privilege(DBusMessage *message,
				enum connman_security_privilege privilege);

#include <connman/ipv4.h>

const char *__connman_ipv4_method2string(enum connman_ipv4_method method);
enum connman_ipv4_method __connman_ipv4_string2method(const char *method);

#include <connman/ipconfig.h>

#include <connman/resolver.h>

int __connman_resolver_init(void);
void __connman_resolver_cleanup(void);

int __connman_resolver_selftest(void);

#include <connman/storage.h>

int __connman_storage_init(void);
void __connman_storage_cleanup(void);

int __connman_storage_init_device();
int __connman_storage_load_device(struct connman_device *device);
int __connman_storage_save_device(struct connman_device *device);
int __connman_storage_init_network();
int __connman_storage_load_network(struct connman_network *network);
int __connman_storage_save_network(struct connman_network *network);

#include <connman/driver.h>

void __connman_driver_rescan(struct connman_driver *driver);

#include <connman/element.h>

int __connman_element_init(DBusConnection *conn, const char *device,
							const char *nodevice);
void __connman_element_start(void);
void __connman_element_stop(void);
void __connman_element_cleanup(void);

void __connman_element_initialize(struct connman_element *element);

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

struct connman_service *__connman_element_get_service(struct connman_element *element);
struct connman_device *__connman_element_get_device(struct connman_element *element);
const char *__connman_element_get_device_path(struct connman_element *element);
const char *__connman_element_get_network_path(struct connman_element *element);

const char *__connman_element_type2string(enum connman_element_type type);

static inline void __connman_element_lock(struct connman_element *element)
{
}

static inline void __connman_element_unlock(struct connman_element *element)
{
}

int __connman_element_append_ipv4(struct connman_element *element,
						DBusMessageIter *dict);
int __connman_element_set_ipv4(struct connman_element *element,
				const char *name, DBusMessageIter *value);

int __connman_detect_init(void);
void __connman_detect_cleanup(void);

int __connman_ipv4_init(void);
void __connman_ipv4_cleanup(void);

int __connman_connection_init(void);
void __connman_connection_cleanup(void);

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

void __connman_device_increase_connections(struct connman_device *device);
void __connman_device_decrease_connections(struct connman_device *device);

void __connman_device_set_network(struct connman_device *device,
					struct connman_network *network);

int __connman_device_connect(struct connman_device *device);
int __connman_device_disconnect(struct connman_device *device);

connman_bool_t __connman_device_has_driver(struct connman_device *device);

const char *__connman_device_get_type(struct connman_device *device);
const char *__connman_device_get_ident(struct connman_device *device);

int __connman_device_set_offlinemode(connman_bool_t offlinemode);

int __connman_profile_add_device(struct connman_device *device);
int __connman_profile_remove_device(struct connman_device *device);

#include <connman/network.h>

int __connman_network_init(void);
void __connman_network_cleanup(void);

void __connman_network_set_device(struct connman_network *network,
					struct connman_device *device);

int __connman_network_disconnect(struct connman_network *network);

connman_bool_t __connman_network_has_driver(struct connman_network *network);

const char *__connman_network_get_type(struct connman_network *network);
const char *__connman_network_get_group(struct connman_network *network);
const char *__connman_network_get_ident(struct connman_network *network);

int __connman_profile_add_network(struct connman_network *network);
int __connman_profile_remove_network(struct connman_network *network);

#include <connman/service.h>

int __connman_service_init(void);
void __connman_service_cleanup(void);

void __connman_service_list(DBusMessageIter *iter);

struct connman_service *__connman_service_lookup_from_device(struct connman_device *device);
struct connman_service *__connman_service_create_from_device(struct connman_device *device);

struct connman_service *__connman_service_lookup_from_network(struct connman_network *network);
struct connman_service *__connman_service_create_from_network(struct connman_network *network);

int __connman_service_set_carrier(struct connman_service *service,
						connman_bool_t carrier);
int __connman_service_indicate_configuration(struct connman_service *service);
int __connman_service_ready(struct connman_service *service);
int __connman_service_disconnect(struct connman_service *service);

#include <connman/notifier.h>

int __connman_notifier_init(void);
void __connman_notifier_cleanup(void);

void __connman_notifier_device_type_increase(enum connman_device_type type);
void __connman_notifier_device_type_decrease(enum connman_device_type type);
void __connman_notifier_offline_mode(connman_bool_t enabled);

#include <connman/rtnl.h>

int __connman_rtnl_init(void);
void __connman_rtnl_cleanup(void);

int __connman_rtnl_send(const void *buf, size_t len);
