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

#include <connman/types.h>

int __connman_manager_init(void);
void __connman_manager_cleanup(void);

int __connman_clock_init(void);
void __connman_clock_cleanup(void);

void __connman_clock_update_timezone(void);

int __connman_timezone_init(void);
void __connman_timezone_cleanup(void);

char *__connman_timezone_lookup(void);
int __connman_timezone_change(const char *zone);

int __connman_agent_init(void);
void __connman_agent_cleanup(void);

int __connman_agent_register(const char *sender, const char *path);
int __connman_agent_unregister(const char *sender, const char *path);

void __connman_counter_send_usage(const char *path,
					DBusMessage *message);
int __connman_counter_register(const char *owner, const char *path,
						unsigned int interval);
int __connman_counter_unregister(const char *owner, const char *path);

int __connman_counter_init(void);
void __connman_counter_cleanup(void);

struct connman_service *service;

typedef void (* passphrase_cb_t) (struct connman_service *service,
				const char *identity, const char *passphrase,
				void *user_data);
typedef void (* report_error_cb_t) (struct connman_service *service,
				gboolean retry, void *user_data);
int __connman_agent_request_input(struct connman_service *service,
				passphrase_cb_t callback, void *user_data);
int __connman_agent_report_error(struct connman_service *service,
				const char *error,
				report_error_cb_t callback, void *user_data);


#include <connman/log.h>

int __connman_log_init(const char *debug, connman_bool_t detach);
void __connman_log_cleanup(void);

void __connman_debug_list_available(DBusMessageIter *iter, void *user_data);
void __connman_debug_list_enabled(DBusMessageIter *iter, void *user_data);

#include <connman/option.h>

#include <connman/setting.h>

#include <connman/plugin.h>

int __connman_plugin_init(const char *pattern, const char *exclude);
void __connman_plugin_cleanup(void);

#include <connman/task.h>

int __connman_task_init(void);
void __connman_task_cleanup(void);

#include <connman/inet.h>

int __connman_inet_modify_address(int cmd, int flags, int index, int family,
				const char *address,
				const char *peer,
				unsigned char prefixlen,
				const char *broadcast);

#include <netinet/ip6.h>
#include <netinet/icmp6.h>

typedef void (*__connman_inet_rs_cb_t) (struct nd_router_advert *reply,
					void *user_data);

int __connman_inet_ipv6_send_rs(int index, int timeout,
			__connman_inet_rs_cb_t callback, void *user_data);

#include <connman/wifi.h>

#include <connman/rfkill.h>

int __connman_rfkill_init(void);
void __connman_rfkill_cleanup(void);

#include <connman/resolver.h>

int __connman_resolver_init(connman_bool_t dnsproxy);
void __connman_resolver_cleanup(void);
int __connman_resolvfile_append(const char *interface, const char *domain, const char *server);
int __connman_resolvfile_remove(const char *interface, const char *domain, const char *server);

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

struct connman_device *__connman_element_find_device(enum connman_service_type type);
int __connman_element_request_scan(enum connman_service_type type);
int __connman_element_enable_technology(enum connman_service_type type);
int __connman_element_disable_technology(enum connman_service_type type);

gboolean __connman_element_device_isfiltered(const char *devname);

int __connman_detect_init(void);
void __connman_detect_cleanup(void);

void __connman_element_set_driver(struct connman_element *element);

#include <connman/proxy.h>

int __connman_proxy_init(void);
void __connman_proxy_cleanup(void);

#include <connman/ipconfig.h>

int __connman_ipconfig_init(void);
void __connman_ipconfig_cleanup(void);

struct rtnl_link_stats;

void __connman_ipconfig_newlink(int index, unsigned short type,
				unsigned int flags, const char *address,
							unsigned short mtu,
						struct rtnl_link_stats *stats);
void __connman_ipconfig_dellink(int index, struct rtnl_link_stats *stats);
void __connman_ipconfig_newaddr(int index, int family, const char *label,
				unsigned char prefixlen, const char *address);
void __connman_ipconfig_deladdr(int index, int family, const char *label,
				unsigned char prefixlen, const char *address);
void __connman_ipconfig_newroute(int index, int family, unsigned char scope,
					const char *dst, const char *gateway);
void __connman_ipconfig_delroute(int index, int family, unsigned char scope,
					const char *dst, const char *gateway);

void __connman_ipconfig_foreach(void (*function) (int index, void *user_data),
							void *user_data);
enum connman_ipconfig_type __connman_ipconfig_get_config_type(
					struct connman_ipconfig *ipconfig);
unsigned short __connman_ipconfig_get_type_from_index(int index);
unsigned int __connman_ipconfig_get_flags_from_index(int index);
const char *__connman_ipconfig_get_gateway_from_index(int index);
void __connman_ipconfig_set_index(struct connman_ipconfig *ipconfig, int index);

const char *__connman_ipconfig_get_local(struct connman_ipconfig *ipconfig);
void __connman_ipconfig_set_local(struct connman_ipconfig *ipconfig, const char *address);
const char *__connman_ipconfig_get_peer(struct connman_ipconfig *ipconfig);
void __connman_ipconfig_set_peer(struct connman_ipconfig *ipconfig, const char *address);
const char *__connman_ipconfig_get_broadcast(struct connman_ipconfig *ipconfig);
void __connman_ipconfig_set_broadcast(struct connman_ipconfig *ipconfig, const char *broadcast);
const char *__connman_ipconfig_get_gateway(struct connman_ipconfig *ipconfig);
void __connman_ipconfig_set_gateway(struct connman_ipconfig *ipconfig, const char *gateway);
unsigned char __connman_ipconfig_get_prefixlen(struct connman_ipconfig *ipconfig);
void __connman_ipconfig_set_prefixlen(struct connman_ipconfig *ipconfig, unsigned char prefixlen);

int __connman_ipconfig_enable(struct connman_ipconfig *ipconfig);
int __connman_ipconfig_disable(struct connman_ipconfig *ipconfig);

const char *__connman_ipconfig_method2string(enum connman_ipconfig_method method);
enum connman_ipconfig_method __connman_ipconfig_string2method(const char *method);

void __connman_ipconfig_append_ipv4(struct connman_ipconfig *ipconfig,
							DBusMessageIter *iter);
void __connman_ipconfig_append_ipv4config(struct connman_ipconfig *ipconfig,
							DBusMessageIter *iter);
void __connman_ipconfig_append_ipv6(struct connman_ipconfig *ipconfig,
					DBusMessageIter *iter,
					struct connman_ipconfig *ip4config);
void __connman_ipconfig_append_ipv6config(struct connman_ipconfig *ipconfig,
							DBusMessageIter *iter);
int __connman_ipconfig_set_config(struct connman_ipconfig *ipconfig,
							DBusMessageIter *array);
void __connman_ipconfig_append_ethernet(struct connman_ipconfig *ipconfig,
							DBusMessageIter *iter);
enum connman_ipconfig_method __connman_ipconfig_get_method(
				struct connman_ipconfig *ipconfig);

int __connman_ipconfig_address_add(struct connman_ipconfig *ipconfig);
int __connman_ipconfig_address_remove(struct connman_ipconfig *ipconfig);
int __connman_ipconfig_gateway_add(struct connman_ipconfig *ipconfig);
void __connman_ipconfig_gateway_remove(struct connman_ipconfig *ipconfig);
unsigned char __connman_ipconfig_netmask_prefix_len(const char *netmask);

int __connman_ipconfig_set_proxy_autoconfig(struct connman_ipconfig *ipconfig,
							const char *url);
const char *__connman_ipconfig_get_proxy_autoconfig(struct connman_ipconfig *ipconfig);

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

typedef void (* dhcp_cb) (struct connman_network *network,
				connman_bool_t success);
int __connman_dhcp_start(struct connman_network *network, dhcp_cb callback);
void __connman_dhcp_stop(struct connman_network *network);
int __connman_dhcp_init(void);
void __connman_dhcp_cleanup(void);

int __connman_ipv4_init(void);
void __connman_ipv4_cleanup(void);

int __connman_connection_init(void);
void __connman_connection_cleanup(void);

int __connman_connection_gateway_add(struct connman_service *service,
					const char *ipv4_gateway,
					const char *ipv6_gateway,
					const char *peer);
void __connman_connection_gateway_remove(struct connman_service *service);

gboolean __connman_connection_update_gateway(void);

int __connman_wpad_init(void);
void __connman_wpad_cleanup(void);
int __connman_wpad_start(struct connman_service *service);
void __connman_wpad_stop(struct connman_service *service);

int __connman_wispr_init(void);
void __connman_wispr_cleanup(void);

#include <connman/technology.h>

void __connman_technology_list(DBusMessageIter *iter, void *user_data);

int __connman_technology_add_device(struct connman_device *device);
int __connman_technology_remove_device(struct connman_device *device);
int __connman_technology_enable(enum connman_service_type type);
int __connman_technology_disable(enum connman_service_type type);
int __connman_technology_add_rfkill(unsigned int index,
					enum connman_service_type type,
						connman_bool_t softblock,
						connman_bool_t hardblock);
int __connman_technology_update_rfkill(unsigned int index,
						connman_bool_t softblock,
						connman_bool_t hardblock);
int __connman_technology_remove_rfkill(unsigned int index);

void __connman_technology_add_interface(enum connman_service_type type,
				int index, const char *name, const char *ident);
void __connman_technology_remove_interface(enum connman_service_type type,
				int index, const char *name, const char *ident);

connman_bool_t __connman_technology_get_blocked(enum connman_service_type type);

#include <connman/device.h>

int __connman_device_init(void);
void __connman_device_cleanup(void);

void __connman_device_list(DBusMessageIter *iter, void *user_data);

enum connman_service_type __connman_device_get_service_type(struct connman_device *device);

int __connman_device_get_phyindex(struct connman_device *device);
void __connman_device_set_phyindex(struct connman_device *device,
							int phyindex);
int __connman_device_set_blocked(struct connman_device *device,
						connman_bool_t blocked);
connman_bool_t __connman_device_get_blocked(struct connman_device *device);

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

connman_bool_t __connman_device_scanning(struct connman_device *device);

connman_bool_t __connman_device_has_driver(struct connman_device *device);

void __connman_device_set_reconnect(struct connman_device *device,
						connman_bool_t reconnect);
connman_bool_t __connman_device_get_reconnect(struct connman_device *device);

const char *__connman_device_get_type(struct connman_device *device);

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
				struct connman_ipconfig *ipconfig_ipv4,
				struct connman_ipconfig *ipconfig_ipv6);

connman_bool_t __connman_network_has_driver(struct connman_network *network);

const char *__connman_network_get_type(struct connman_network *network);
const char *__connman_network_get_group(struct connman_network *network);
const char *__connman_network_get_ident(struct connman_network *network);
connman_bool_t __connman_network_get_weakness(struct connman_network *network);

int __connman_config_init();
void __connman_config_cleanup(void);

int __connman_config_load_service(GKeyFile *keyfile, const char *group, connman_bool_t persistent);
int __connman_config_provision_service(struct connman_service *service);

#include <connman/profile.h>

int __connman_profile_init();
void __connman_profile_cleanup(void);

connman_bool_t __connman_profile_get_offlinemode(void);
int __connman_profile_set_offlinemode(connman_bool_t offlinemode, connman_bool_t all_devices);
int __connman_profile_save_default(void);

void __connman_profile_list(DBusMessageIter *iter, void *user_data);
const char *__connman_profile_active_ident(void);
const char *__connman_profile_active_path(void);

int __connman_profile_create(const char *name, const char **path);
int __connman_profile_remove(const char *path);

void __connman_profile_changed(gboolean delayed);

int __connman_tethering_init(void);
void __connman_tethering_cleanup(void);

const char *__connman_tethering_get_bridge(void);
void __connman_tethering_update_interface(const char *interface);
void __connman_tethering_set_enabled(void);
void __connman_tethering_set_disabled(void);

int __connman_private_network_request(DBusMessage *msg, const char *owner);
int __connman_private_network_release(const char *owner);

#include <connman/provider.h>

void __connman_provider_append_properties(struct connman_provider *provider, DBusMessageIter *iter);
void __connman_provider_list(DBusMessageIter *iter, void *user_data);
int __connman_provider_create_and_connect(DBusMessage *msg);
const char * __connman_provider_get_ident(struct connman_provider *provider);
int __connman_provider_indicate_state(struct connman_provider *provider,
					enum connman_provider_state state);
int __connman_provider_indicate_error(struct connman_provider *provider,
					enum connman_provider_error error);
int __connman_provider_connect(struct connman_provider *provider);
int __connman_provider_disconnect(struct connman_provider *provider);
int __connman_provider_remove(const char *path);
void __connman_provider_cleanup(void);
int __connman_provider_init(void);

#include <connman/service.h>

int __connman_service_init(void);
void __connman_service_cleanup(void);

void __connman_service_list(DBusMessageIter *iter, void *user_data);
void __connman_service_list_struct(DBusMessageIter *iter);
const char *__connman_service_default(void);

void __connman_service_put(struct connman_service *service);

struct connman_service *__connman_service_lookup_from_network(struct connman_network *network);
struct connman_service *__connman_service_lookup_from_index(int index);
struct connman_service *__connman_service_create_from_network(struct connman_network *network);
struct connman_service *__connman_service_create_from_provider(struct connman_provider *provider);
void __connman_service_update_from_network(struct connman_network *network);
void __connman_service_remove_from_network(struct connman_network *network);

void __connman_service_create_ip4config(struct connman_service *service,
								int index);
void __connman_service_create_ip6config(struct connman_service *service,
								int index);
struct connman_ipconfig *__connman_service_get_ip4config(
				struct connman_service *service);
struct connman_ipconfig *__connman_service_get_ip6config(
				struct connman_service *service);
struct connman_ipconfig *__connman_service_get_ipconfig(
				struct connman_service *service, int family);
const char *__connman_service_get_ident(struct connman_service *service);
const char *__connman_service_get_path(struct connman_service *service);
unsigned int __connman_service_get_order(struct connman_service *service);
struct connman_network *__connman_service_get_network(struct connman_service *service);
enum connman_service_security __connman_service_get_security(struct connman_service *service);
const char *__connman_service_get_phase2(struct connman_service *service);
connman_bool_t __connman_service_wps_enabled(struct connman_service *service);
int __connman_service_set_favorite(struct connman_service *service,
						connman_bool_t favorite);
connman_bool_t __connman_service_get_immutable(struct connman_service *service);
int __connman_service_set_immutable(struct connman_service *service,
						connman_bool_t immutable);

void __connman_service_set_string(struct connman_service *service,
					const char *key, const char *value);
int __connman_service_indicate_state(struct connman_service *service,
					enum connman_service_state new_state,
					enum connman_ipconfig_type type);
int __connman_service_indicate_error(struct connman_service *service,
					enum connman_service_error error);
int __connman_service_clear_error(struct connman_service *service);
int __connman_service_indicate_default(struct connman_service *service);
int __connman_service_request_login(struct connman_service *service);

int __connman_service_lookup(const char *pattern, const char **path);
int __connman_service_connect(struct connman_service *service);
int __connman_service_disconnect(struct connman_service *service);
int __connman_service_disconnect_all(void);
int __connman_service_create_and_connect(DBusMessage *msg);
int __connman_service_provision(DBusMessage *msg);
void __connman_service_auto_connect(void);

const char *__connman_service_type2string(enum connman_service_type type);

int __connman_service_nameserver_append(struct connman_service *service,
					const char *nameserver);
int __connman_service_nameserver_remove(struct connman_service *service,
					const char *nameserver);
void __connman_service_nameserver_clear(struct connman_service *service);
void __connman_service_nameserver_add_routes(struct connman_service *service,
						const char *gw);
void __connman_service_nameserver_del_routes(struct connman_service *service);
int __connman_service_timeserver_append(struct connman_service *service,
						const char *timeserver);
int __connman_service_timeserver_remove(struct connman_service *service,
						const char *timeserver);
void __connman_service_set_pac(struct connman_service *service,
					const char *pac);
int __connman_service_get_index(struct connman_service *service);
void __connman_service_set_domainname(struct connman_service *service,
						const char *domainname);
const char *__connman_service_get_domainname(struct connman_service *service);
const char *__connman_service_get_nameserver(struct connman_service *service);
void __connman_service_set_proxy_autoconfig(struct connman_service *service,
							const char *url);

void __connman_service_set_identity(struct connman_service *service,
					const char *identity);
void __connman_service_set_passphrase(struct connman_service *service,
					const char* passphrase);

void __connman_service_notify(struct connman_service *service,
			unsigned int rx_packets, unsigned int tx_packets,
			unsigned int rx_bytes, unsigned int tx_bytes,
			unsigned int rx_error, unsigned int tx_error,
			unsigned int rx_dropped, unsigned int tx_dropped);

int __connman_service_counter_register(const char *counter);
void __connman_service_counter_unregister(const char *counter);

struct connman_session;
typedef connman_bool_t (* service_match_cb) (struct connman_session *session,
					struct connman_service *service);

GSequence *__connman_service_get_list(struct connman_session *session,
					service_match_cb service_match);

connman_bool_t __connman_service_is_connecting(struct connman_service *service);
connman_bool_t __connman_service_is_connected(struct connman_service *service);
connman_bool_t __connman_service_is_idle(struct connman_service *service);
const char *__connman_service_get_name(struct connman_service *service);

#include <connman/location.h>

int __connman_location_init(void);
void __connman_location_cleanup(void);

struct connman_location *__connman_location_create(struct connman_service *service);
struct connman_location *__connman_service_get_location(struct connman_service *service);

int __connman_location_detect(struct connman_service *service);
int __connman_location_finish(struct connman_service *service);

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
void __connman_notifier_service_add(struct connman_service *service);
void __connman_notifier_service_remove(struct connman_service *service);
void __connman_notifier_enable(enum connman_service_type type);
void __connman_notifier_disable(enum connman_service_type type);
void __connman_notifier_connect(enum connman_service_type type);
void __connman_notifier_disconnect(enum connman_service_type type);
void __connman_notifier_offlinemode(connman_bool_t enabled);
void __connman_notifier_default_changed(struct connman_service *service);
void __connman_notifier_proxy_changed(struct connman_service *service);
void __connman_notifier_service_state_changed(struct connman_service *service,
					enum connman_service_state state);
void __connman_notifier_ipconfig_changed(struct connman_service *service,
					struct connman_ipconfig *ipconfig);

connman_bool_t __connman_notifier_is_registered(enum connman_service_type type);
connman_bool_t __connman_notifier_is_enabled(enum connman_service_type type);
unsigned int __connman_notifier_count_connected(void);
const char *__connman_notifier_get_state(void);

#include <connman/rtnl.h>

int __connman_rtnl_init(void);
void __connman_rtnl_start(void);
void __connman_rtnl_cleanup(void);

enum connman_device_type __connman_rtnl_get_device_type(int index);
unsigned int __connman_rtnl_update_interval_add(unsigned int interval);
unsigned int __connman_rtnl_update_interval_remove(unsigned int interval);
int __connman_rtnl_request_update(void);
int __connman_rtnl_send(const void *buf, size_t len);

connman_bool_t __connman_session_mode();
void __connman_session_set_mode(connman_bool_t enable);

int __connman_session_create(DBusMessage *msg);
int __connman_session_destroy(DBusMessage *msg);

int __connman_session_init(void);
void __connman_session_cleanup(void);

struct connman_stats_data {
	unsigned int rx_packets;
	unsigned int tx_packets;
	unsigned int rx_bytes;
	unsigned int tx_bytes;
	unsigned int rx_errors;
	unsigned int tx_errors;
	unsigned int rx_dropped;
	unsigned int tx_dropped;
	unsigned int time;
};

int __connman_stats_init(void);
void __connman_stats_cleanup(void);
int __connman_stats_service_register(struct connman_service *service);
void __connman_stats_service_unregister(struct connman_service *service);
int  __connman_stats_update(struct connman_service *service,
				connman_bool_t roaming,
				struct connman_stats_data *data);
int __connman_stats_get(struct connman_service *service,
				connman_bool_t roaming,
				struct connman_stats_data *data);

int __connman_iptables_init(void);
void __connman_iptables_cleanup(void);
int __connman_iptables_command(const char *format, ...)
				__attribute__((format(printf, 1, 2)));
int __connman_iptables_commit(const char *table_name);

int __connman_dnsproxy_init(void);
void __connman_dnsproxy_cleanup(void);
int __connman_dnsproxy_append(const char *interface, const char *domain, const char *server);
int __connman_dnsproxy_remove(const char *interface, const char *domain, const char *server);
void __connman_dnsproxy_flush(void);

int __connman_6to4_probe(struct connman_service *service);
void __connman_6to4_remove(struct connman_ipconfig *ipconfig);
int __connman_6to4_check(struct connman_ipconfig *ipconfig);
