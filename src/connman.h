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

DBusMessage *__connman_error_failed(DBusMessage *msg, int errnum);
DBusMessage *__connman_error_invalid_arguments(DBusMessage *msg);
DBusMessage *__connman_error_permission_denied(DBusMessage *msg);
DBusMessage *__connman_error_passphrase_required(DBusMessage *msg);
DBusMessage *__connman_error_not_supported(DBusMessage *msg);
DBusMessage *__connman_error_not_implemented(DBusMessage *msg);
DBusMessage *__connman_error_not_found(DBusMessage *msg);
DBusMessage *__connman_error_no_carrier(DBusMessage *msg);
DBusMessage *__connman_error_in_progress(DBusMessage *msg);
DBusMessage *__connman_error_already_exists(DBusMessage *msg);
DBusMessage *__connman_error_already_enabled(DBusMessage *msg);
DBusMessage *__connman_error_already_disabled(DBusMessage *msg);
DBusMessage *__connman_error_already_connected(DBusMessage *msg);
DBusMessage *__connman_error_not_connected(DBusMessage *msg);
DBusMessage *__connman_error_operation_aborted(DBusMessage *msg);
DBusMessage *__connman_error_operation_timeout(DBusMessage *msg);
DBusMessage *__connman_error_invalid_service(DBusMessage *msg);
DBusMessage *__connman_error_invalid_property(DBusMessage *msg);

int __connman_selftest(void);

#include <connman/types.h>

int __connman_manager_init(DBusConnection *conn, gboolean compat);
void __connman_manager_cleanup(void);

int __connman_agent_init(DBusConnection *conn);
void __connman_agent_cleanup(void);

int __connman_agent_register(const char *sender, const char *path);
int __connman_agent_unregister(const char *sender, const char *path);

#include <connman/log.h>

int __connman_log_init(gboolean detach, gboolean debug);
void __connman_log_cleanup(void);

void __connman_toggle_debug(void);
gboolean __connman_debug_enabled(void);

#include <connman/option.h>

#include <connman/plugin.h>

int __connman_plugin_init(const char *pattern, const char *exclude);
void __connman_plugin_cleanup(void);

#include <connman/task.h>

int __connman_task_init(void);
void __connman_task_cleanup(void);

#include <connman/security.h>

int __connman_security_check_privilege(DBusMessage *message,
				enum connman_security_privilege privilege);

#include <connman/ipconfig.h>

int __connman_ipconfig_get_index(struct connman_ipconfig *ipconfig);

void __connman_ipconfig_add_address(struct connman_ipconfig *ipconfig,
				const char *label, unsigned int prefixlen,
				const char *address, const char *broadcast);
void __connman_ipconfig_del_address(struct connman_ipconfig *ipconfig,
				const char *label, unsigned int prefixlen,
				const char *address, const char *broadcast);

const char *__connman_ipconfig_method2string(enum connman_ipconfig_method method);
enum connman_ipconfig_method __connman_ipconfig_string2method(const char *method);

void __connman_ipconfig_append_ipv4(struct connman_ipconfig *ipconfig,
				DBusMessageIter *iter, const char *prefix);
int __connman_ipconfig_set_ipv4(struct connman_ipconfig *ipconfig,
				const char *key, DBusMessageIter *value);

int __connman_ipconfig_load(struct connman_ipconfig *ipconfig,
		GKeyFile *keyfile, const char *identifier, const char *prefix);
int __connman_ipconfig_save(struct connman_ipconfig *ipconfig,
		GKeyFile *keyfile, const char *identifier, const char *prefix);

#include <connman/inet.h>

enum connman_device_type __connman_inet_get_device_type(int index);

#include <connman/wifi.h>

#include <connman/rfkill.h>

int __connman_rfkill_init(void);
void __connman_rfkill_cleanup(void);

#include <connman/resolver.h>

int __connman_resolver_init(void);
void __connman_resolver_cleanup(void);

int __connman_resolver_selftest(void);

#include <connman/storage.h>

int __connman_storage_init(void);
void __connman_storage_cleanup(void);

GKeyFile *__connman_storage_open(const char *ident);
void __connman_storage_close(const char *ident,
					GKeyFile *keyfile, gboolean save);
void __connman_storage_delete(const char *ident);

int __connman_storage_init_profile(void);
int __connman_storage_load_profile(struct connman_profile *profile);
int __connman_storage_save_profile(struct connman_profile *profile);
int __connman_storage_load_service(struct connman_service *service);
int __connman_storage_save_service(struct connman_service *service);
int __connman_storage_load_device(struct connman_device *device);
int __connman_storage_save_device(struct connman_device *device);

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

struct connman_device *__connman_element_find_device(enum connman_service_type type);
int __connman_element_request_scan(enum connman_service_type type);
int __connman_element_enable_technology(enum connman_service_type type);
int __connman_element_disable_technology(enum connman_service_type type);

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

int __connman_ipv4_init(void);
void __connman_ipv4_cleanup(void);

int __connman_connection_init(void);
void __connman_connection_cleanup(void);

gboolean __connman_connection_update_gateway(void);

int __connman_udev_init(void);
void __connman_udev_start(void);
void __connman_udev_cleanup(void);
char *__connman_udev_get_devtype(const char *ifname);
char *__connman_udev_get_mbm_devnode(const char *ifname);
void __connman_udev_rfkill(const char *sysname, connman_bool_t blocked);

#include <connman/device.h>

int __connman_device_init(void);
void __connman_device_cleanup(void);

enum connman_service_type __connman_device_get_service_type(struct connman_device *device);

int __connman_device_get_phyindex(struct connman_device *device);
void __connman_device_set_phyindex(struct connman_device *device,
							int phyindex);
int __connman_device_set_blocked(struct connman_device *device,
						connman_bool_t blocked);


void __connman_device_increase_connections(struct connman_device *device);
void __connman_device_decrease_connections(struct connman_device *device);

void __connman_device_set_network(struct connman_device *device,
					struct connman_network *network);
void __connman_device_cleanup_networks(struct connman_device *device);

int __connman_device_scan(struct connman_device *device);
int __connman_device_enable(struct connman_device *device);
int __connman_device_enable_persistent(struct connman_device *device);
int __connman_device_disable(struct connman_device *device);
int __connman_device_disable_persistent(struct connman_device *device);
int __connman_device_connect(struct connman_device *device);
int __connman_device_disconnect(struct connman_device *device);

connman_bool_t __connman_device_has_driver(struct connman_device *device);

const char *__connman_device_get_type(struct connman_device *device);
const char *__connman_device_get_ident(struct connman_device *device);

int __connman_device_set_offlinemode(connman_bool_t offlinemode);

#include <connman/network.h>

int __connman_network_init(void);
void __connman_network_cleanup(void);

void __connman_network_set_device(struct connman_network *network,
					struct connman_device *device);

int __connman_network_connect(struct connman_network *network);
int __connman_network_disconnect(struct connman_network *network);

connman_bool_t __connman_network_has_driver(struct connman_network *network);

const char *__connman_network_get_type(struct connman_network *network);
const char *__connman_network_get_group(struct connman_network *network);
const char *__connman_network_get_ident(struct connman_network *network);
connman_bool_t __connman_network_get_weakness(struct connman_network *network);

#include <connman/profile.h>

int __connman_profile_init(DBusConnection *conn);
void __connman_profile_cleanup(void);

connman_bool_t __connman_profile_get_offlinemode(void);
int __connman_profile_set_offlinemode(connman_bool_t offlinemode);
int __connman_profile_save_default(void);

void __connman_profile_list(DBusMessageIter *iter);
const char *__connman_profile_active_ident(void);
const char *__connman_profile_active_path(void);

int __connman_profile_create(const char *name, const char **path);
int __connman_profile_remove(const char *path);

void __connman_profile_changed(gboolean delayed);

int __connman_profile_add_device(struct connman_device *device);
int __connman_profile_remove_device(struct connman_device *device);

int __connman_profile_add_network(struct connman_network *network);
int __connman_profile_update_network(struct connman_network *network);
int __connman_profile_remove_network(struct connman_network *network);

#include <connman/service.h>

int __connman_service_init(void);
void __connman_service_cleanup(void);

void __connman_service_list(DBusMessageIter *iter);
const char *__connman_service_default(void);

void __connman_service_put(struct connman_service *service);

struct connman_service *__connman_service_lookup_from_device(struct connman_device *device);
struct connman_service *__connman_service_create_from_device(struct connman_device *device);
void __connman_service_remove_from_device(struct connman_device *device);

struct connman_service *__connman_service_lookup_from_network(struct connman_network *network);
struct connman_service *__connman_service_create_from_network(struct connman_network *network);
void __connman_service_update_from_network(struct connman_network *network);
void __connman_service_remove_from_network(struct connman_network *network);

unsigned int __connman_service_get_order(struct connman_service *service);

int __connman_service_set_carrier(struct connman_service *service,
						connman_bool_t carrier);
int __connman_service_indicate_state(struct connman_service *service,
					enum connman_service_state state);
int __connman_service_indicate_error(struct connman_service *service,
					enum connman_service_error error);
int __connman_service_indicate_default(struct connman_service *service);

int __connman_service_connect(struct connman_service *service);
int __connman_service_disconnect(struct connman_service *service);
int __connman_service_create_and_connect(DBusMessage *msg);
void __connman_service_auto_connect(void);

#include <connman/provider.h>

#include <connman/notifier.h>

int __connman_notifier_init(void);
void __connman_notifier_cleanup(void);

void __connman_notifier_list_registered(DBusMessageIter *iter);
void __connman_notifier_list_enabled(DBusMessageIter *iter);
void __connman_notifier_list_connected(DBusMessageIter *iter);

void __connman_notifier_register(enum connman_service_type type);
void __connman_notifier_unregister(enum connman_service_type type);
void __connman_notifier_enable(enum connman_service_type type);
void __connman_notifier_disable(enum connman_service_type type);
void __connman_notifier_connect(enum connman_service_type type);
void __connman_notifier_disconnect(enum connman_service_type type);
void __connman_notifier_offlinemode(connman_bool_t enabled);

connman_bool_t __connman_notifier_is_enabled(enum connman_service_type type);

#include <connman/rtnl.h>

int __connman_rtnl_init(void);
void __connman_rtnl_start(void);
void __connman_rtnl_cleanup(void);

int __connman_rtnl_send(const void *buf, size_t len);

int __connman_rtnl_register_ipconfig(struct connman_ipconfig *ipconfig);
void __connman_rtnl_unregister_ipconfig(struct connman_ipconfig *ipconfig);
