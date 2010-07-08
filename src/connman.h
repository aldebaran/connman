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
DBusMessage *__connman_error_not_registered(DBusMessage *msg);
DBusMessage *__connman_error_not_unique(DBusMessage *msg);
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

int __connman_manager_init(gboolean compat);
void __connman_manager_cleanup(void);

int __connman_agent_init(void);
void __connman_agent_cleanup(void);

int __connman_agent_register(const char *sender, const char *path);
int __connman_agent_unregister(const char *sender, const char *path);

struct connman_service;
struct connman_ipconfig;

int __connman_counter_register(const char *owner, const char *path,
						unsigned int interval);
int __connman_counter_unregister(const char *owner, const char *path);

void __connman_counter_notify(struct connman_ipconfig *config,
			unsigned int rx_packets, unsigned int tx_packets,
			unsigned int rx_bytes, unsigned int tx_bytes,
			unsigned int rx_error, unsigned int tx_error,
			unsigned int rx_dropped, unsigned int tx_dropped);

int __connman_counter_add_service(struct connman_service *service);
void __connman_counter_remove_service(struct connman_service *service);

int __connman_counter_init(void);
void __connman_counter_cleanup(void);


typedef void (* passphrase_cb_t) (struct connman_service *service,
				const char *passphrase, void *user_data);

int __connman_agent_request_passphrase(struct connman_service *service,
				passphrase_cb_t callback, void *user_data);

#include <connman/log.h>

int __connman_log_init(const char *debug, connman_bool_t detach);
void __connman_log_cleanup(void);

void __connman_debug_list_available(DBusMessageIter *iter, void *user_data);
void __connman_debug_list_enabled(DBusMessageIter *iter, void *user_data);

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

GKeyFile *__connman_storage_open(const char *ident, const char *suffix);
void __connman_storage_close(const char *ident, const char *suffix,
					GKeyFile *keyfile, gboolean save);
void __connman_storage_delete(const char *ident, const char *suffix);

GKeyFile *__connman_storage_open_profile(const char *ident);
void __connman_storage_close_profile(const char *ident,
					GKeyFile *keyfile, gboolean save);
void __connman_storage_delete_profile(const char *ident);

GKeyFile *__connman_storage_open_config(const char *ident);
void __connman_storage_close_config(const char *ident,
					GKeyFile *keyfile, gboolean save);
void __connman_storage_delete_config(const char *ident);

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

int __connman_element_init(const char *device, const char *nodevice);
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

struct connman_service *__connman_element_get_service(struct connman_element *element);
struct connman_device *__connman_element_get_device(struct connman_element *element);
const char *__connman_element_get_device_path(struct connman_element *element);
const char *__connman_element_get_network_path(struct connman_element *element);

struct connman_device *__connman_element_find_device(enum connman_service_type type);
int __connman_element_request_scan(enum connman_service_type type);
int __connman_element_enable_technology(enum connman_service_type type);
int __connman_element_disable_technology(enum connman_service_type type);

gboolean __connman_element_device_isfiltered(const char *devname);

#include <connman/ipconfig.h>

int __connman_ipconfig_init(void);
void __connman_ipconfig_cleanup(void);

struct rtnl_link_stats;

void __connman_ipconfig_newlink(int index, unsigned short type,
				unsigned int flags, const char *address,
							unsigned short mtu,
						struct rtnl_link_stats *stats);
void __connman_ipconfig_dellink(int index, struct rtnl_link_stats *stats);
void __connman_ipconfig_newaddr(int index, const char *label,
				unsigned char prefixlen, const char *address);
void __connman_ipconfig_deladdr(int index, const char *label,
				unsigned char prefixlen, const char *address);
void __connman_ipconfig_newroute(int index, unsigned char scope,
					const char *dst, const char *gateway);
void __connman_ipconfig_delroute(int index, unsigned char scope,
					const char *dst, const char *gateway);

void __connman_ipconfig_foreach(void (*function) (int index, void *user_data),
							void *user_data);
unsigned short __connman_ipconfig_get_type(int index);
unsigned int __connman_ipconfig_get_flags(int index);
const char *__connman_ipconfig_get_gateway(int index);
void __connman_ipconfig_set_index(struct connman_ipconfig *ipconfig, int index);

int __connman_ipconfig_enable(struct connman_ipconfig *ipconfig);
int __connman_ipconfig_disable(struct connman_ipconfig *ipconfig);

const char *__connman_ipconfig_method2string(enum connman_ipconfig_method method);
enum connman_ipconfig_method __connman_ipconfig_string2method(const char *method);

void __connman_ipconfig_append_ipv4(struct connman_ipconfig *ipconfig,
							DBusMessageIter *iter);
void __connman_ipconfig_append_ipv4config(struct connman_ipconfig *ipconfig,
							DBusMessageIter *iter);
int __connman_ipconfig_set_ipv4config(struct connman_ipconfig *ipconfig,
							DBusMessageIter *value);
void __connman_ipconfig_append_proxy(struct connman_ipconfig *ipconfig,
							DBusMessageIter *iter);
void __connman_ipconfig_append_ethernet(struct connman_ipconfig *ipconfig,
							DBusMessageIter *iter);
enum connman_ipconfig_method __connman_ipconfig_get_method(
				struct connman_ipconfig *ipconfig);
int __connman_ipconfig_set_gateway(struct connman_ipconfig *ipconfig,
					struct connman_element *parent);
int __connman_ipconfig_set_address(struct connman_ipconfig *ipconfig);
int __connman_ipconfig_clear_address(struct connman_ipconfig *ipconfig);

int __connman_ipconfig_load(struct connman_ipconfig *ipconfig,
		GKeyFile *keyfile, const char *identifier, const char *prefix);
int __connman_ipconfig_save(struct connman_ipconfig *ipconfig,
		GKeyFile *keyfile, const char *identifier, const char *prefix);

#include <connman/utsname.h>

int __connman_utsname_set_hostname(const char *hostname);
int __connman_utsname_set_domainname(const char *domainname);

#include <connman/timeserver.h>

int __connman_timeserver_init(void);
void __connman_timeserver_cleanup(void);

#include <connman/dhcp.h>

int __connman_dhcp_init(void);
void __connman_dhcp_cleanup(void);

int __connman_ipv4_init(void);
void __connman_ipv4_cleanup(void);

int __connman_connection_init(void);
void __connman_connection_cleanup(void);

gboolean __connman_connection_update_gateway(void);

int __connman_udev_init(void);
void __connman_udev_start(void);
void __connman_udev_cleanup(void);
char *__connman_udev_get_devtype(const char *ifname);
void __connman_udev_rfkill(const char *sysname, connman_bool_t blocked);
connman_bool_t __connman_udev_get_blocked(int phyindex);

#include <connman/device.h>

void __connman_technology_list(DBusMessageIter *iter, void *user_data);

int __connman_technology_add_device(struct connman_device *device);
int __connman_technology_remove_device(struct connman_device *device);
int __connman_technology_enable_device(struct connman_device *device);
int __connman_technology_disable_device(struct connman_device *device);
int __connman_technology_add_rfkill(unsigned int index,
					enum connman_service_type type,
						connman_bool_t softblock,
						connman_bool_t hardblock);
int __connman_technology_update_rfkill(unsigned int index,
						connman_bool_t softblock,
						connman_bool_t hardblock);
int __connman_technology_remove_rfkill(unsigned int index);

int __connman_device_init(void);
void __connman_device_cleanup(void);

void __connman_device_list(DBusMessageIter *iter, void *user_data);

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
int __connman_device_disconnect(struct connman_device *device);

connman_bool_t __connman_device_has_driver(struct connman_device *device);

void __connman_device_set_reconnect(struct connman_device *device,
						connman_bool_t reconnect);
connman_bool_t __connman_device_get_reconnect(struct connman_device *device);

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
int __connman_network_clear_ipconfig(struct connman_network *network,
					struct connman_ipconfig *ipconfig);
int __connman_network_set_ipconfig(struct connman_network *network,
					struct connman_ipconfig *ipconfig);

connman_bool_t __connman_network_has_driver(struct connman_network *network);

const char *__connman_network_get_type(struct connman_network *network);
const char *__connman_network_get_group(struct connman_network *network);
const char *__connman_network_get_ident(struct connman_network *network);
connman_bool_t __connman_network_get_weakness(struct connman_network *network);
connman_bool_t __connman_network_get_connecting(struct connman_network *network);

int __connman_config_init();
void __connman_config_cleanup(void);

int __connman_config_provision_service(struct connman_service *service);

#include <connman/profile.h>

int __connman_profile_init();
void __connman_profile_cleanup(void);

connman_bool_t __connman_profile_get_offlinemode(void);
int __connman_profile_set_offlinemode(connman_bool_t offlinemode);
int __connman_profile_save_default(void);

void __connman_profile_list(DBusMessageIter *iter, void *user_data);
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

int __connman_tethering_init(void);
void __connman_tethering_cleanup(void);

connman_bool_t __connman_tethering_get_status(void);
int __connman_tethering_set_status(connman_bool_t status);
void __connman_tethering_update_interface(const char *interface);

#include <connman/service.h>

int __connman_service_init(void);
void __connman_service_cleanup(void);

void __connman_service_list(DBusMessageIter *iter, void *user_data);
void __connman_service_list_struct(DBusMessageIter *iter);
const char *__connman_service_default(void);

void __connman_service_put(struct connman_service *service);

struct connman_service *__connman_service_lookup_from_network(struct connman_network *network);
struct connman_service *__connman_service_create_from_network(struct connman_network *network);
void __connman_service_update_from_network(struct connman_network *network);
void __connman_service_remove_from_network(struct connman_network *network);

void __connman_service_create_ipconfig(struct connman_service *service,
								int index);
struct connman_ipconfig *__connman_service_get_ipconfig(
				struct connman_service *service);
const char *__connman_service_get_path(struct connman_service *service);
unsigned int __connman_service_get_order(struct connman_service *service);
struct connman_network *__connman_service_get_network(struct connman_service *service);
int __connman_service_set_favorite(struct connman_service *service,
						connman_bool_t favorite);
int __connman_service_set_immutable(struct connman_service *service,
						connman_bool_t immutable);

void __connman_service_set_string(struct connman_service *service,
					const char *key, const char *value);
int __connman_service_indicate_state(struct connman_service *service,
					enum connman_service_state state);
int __connman_service_indicate_error(struct connman_service *service,
					enum connman_service_error error);
int __connman_service_indicate_default(struct connman_service *service);

int __connman_service_lookup(const char *pattern, const char **path);
int __connman_service_connect(struct connman_service *service);
int __connman_service_disconnect(struct connman_service *service);
int __connman_service_create_and_connect(DBusMessage *msg);
void __connman_service_auto_connect(void);
struct connman_service *__connman_service_connect_type(enum connman_service_type type);

const char *__connman_service_type2string(enum connman_service_type type);

void __connman_service_append_nameserver(struct connman_service *service,
						const char *nameserver);
void __connman_service_remove_nameserver(struct connman_service *service,
						const char *nameserver);

unsigned long __connman_service_stats_get_rx_packets(struct connman_service *service);
unsigned long __connman_service_stats_get_tx_packets(struct connman_service *service);
unsigned long __connman_service_stats_get_rx_bytes(struct connman_service *service);
unsigned long __connman_service_stats_get_tx_bytes(struct connman_service *service);
unsigned long __connman_service_stats_get_rx_errors(struct connman_service *service);
unsigned long __connman_service_stats_get_tx_errors(struct connman_service *service);
unsigned long __connman_service_stats_get_rx_dropped(struct connman_service *service);
unsigned long __connman_service_stats_get_tx_dropped(struct connman_service *service);
unsigned long __connman_service_stats_get_time(struct connman_service *service);
void __connman_service_stats_update(struct connman_service *service,
				unsigned int rx_packets, unsigned int tx_packets,
				unsigned int rx_bytes, unsigned int tx_bytes,
				unsigned int rx_error, unsigned int tx_error,
				unsigned int rx_dropped, unsigned int tx_dropped);

#include <connman/location.h>

int __connman_location_init(void);
void __connman_location_cleanup(void);

struct connman_location *__connman_location_create(struct connman_service *service);
struct connman_location *__connman_service_get_location(struct connman_service *service);

int __connman_location_detect(struct connman_service *service);
int __connman_location_finish(struct connman_service *service);

#include <connman/provider.h>

void __connman_provider_list(DBusMessageIter *iter, void *user_data);
int __connman_provider_create_and_connect(DBusMessage *msg);
int __connman_provider_indicate_state(struct connman_provider *provider,
				     enum connman_provider_state state);
int __connman_provider_indicate_error(struct connman_provider *provider,
				     enum connman_provider_error error);
int __connman_provider_remove(const char *path);
void __connman_provider_cleanup(void);
int __connman_provider_init(void);

#include <connman/notifier.h>

int __connman_technology_init(void);
void __connman_technology_cleanup(void);

int __connman_notifier_init(void);
void __connman_notifier_cleanup(void);

void __connman_notifier_list_registered(DBusMessageIter *iter, void *user_data);
void __connman_notifier_list_enabled(DBusMessageIter *iter, void *user_data);
void __connman_notifier_list_connected(DBusMessageIter *iter, void *user_data);

void __connman_notifier_register(enum connman_service_type type);
void __connman_notifier_unregister(enum connman_service_type type);
void __connman_notifier_enable(enum connman_service_type type);
void __connman_notifier_disable(enum connman_service_type type);
void __connman_notifier_connect(enum connman_service_type type);
void __connman_notifier_disconnect(enum connman_service_type type);
void __connman_notifier_offlinemode(connman_bool_t enabled);
void __connman_notifier_default_changed(struct connman_service *service);

connman_bool_t __connman_notifier_is_registered(enum connman_service_type type);
connman_bool_t __connman_notifier_is_enabled(enum connman_service_type type);
unsigned int __connman_notifier_count_connected(void);
const char *__connman_notifier_get_state(void);

#include <connman/rtnl.h>

int __connman_rtnl_init(void);
void __connman_rtnl_start(void);
void __connman_rtnl_cleanup(void);

unsigned int __connman_rtnl_update_interval_add(unsigned int interval);
unsigned int __connman_rtnl_update_interval_remove(unsigned int interval);
int __connman_rtnl_request_update(void);
int __connman_rtnl_send(const void *buf, size_t len);

int __connman_session_release(const char *owner);
struct connman_service *__connman_session_request(const char *bearer, const char *owner);
int __connman_session_init(void);
void __connman_session_cleanup(void);
