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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <net/if.h>

#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP	0x10000
#endif

#include <gdbus.h>

#include "connman.h"

struct connman_ipaddress {
	unsigned char prefixlen;
	char *address;
};

struct connman_ipconfig {
	gint refcount;
	int index;
	char *interface;
	unsigned short type;
	unsigned int flags;
	enum connman_ipconfig_method method;
	GSList *address_list;
};

static void free_address_list(struct connman_ipconfig *ipconfig)
{
	GSList *list;

	for (list = ipconfig->address_list; list; list = list->next) {
		struct connman_ipaddress *ipaddress = list->data;

		g_free(ipaddress->address);
		g_free(ipaddress);
	}

	g_slist_free(ipconfig->address_list);
	ipconfig->address_list = NULL;
}

static struct connman_ipaddress *find_ipaddress(struct connman_ipconfig *ipconfig,
				unsigned char prefixlen, const char *address)
{
	GSList *list;

	for (list = ipconfig->address_list; list; list = list->next) {
		struct connman_ipaddress *ipaddress = list->data;

		if (g_strcmp0(ipaddress->address, address) == 0 &&
					ipaddress->prefixlen == prefixlen)
			return ipaddress;
	}

	return NULL;
}

/**
 * connman_ipconfig_create:
 *
 * Allocate a new ipconfig structure.
 *
 * Returns: a newly-allocated #connman_ipconfig structure
 */
struct connman_ipconfig *connman_ipconfig_create(int index)
{
	struct connman_ipconfig *ipconfig;

	DBG("");

	ipconfig = g_try_new0(struct connman_ipconfig, 1);
	if (ipconfig == NULL)
		return NULL;

	ipconfig->refcount = 1;

	ipconfig->index = index;
	ipconfig->interface = connman_inet_ifname(index);

	DBG("ipconfig %p", ipconfig);

	connman_info("%s {create} index %d", ipconfig->interface,
							ipconfig->index);

	return ipconfig;
}

/**
 * connman_ipconfig_ref:
 * @ipconfig: ipconfig structure
 *
 * Increase reference counter of ipconfig
 */
struct connman_ipconfig *connman_ipconfig_ref(struct connman_ipconfig *ipconfig)
{
	g_atomic_int_inc(&ipconfig->refcount);

	return ipconfig;
}

/**
 * connman_ipconfig_unref:
 * @ipconfig: ipconfig structure
 *
 * Decrease reference counter of ipconfig
 */
void connman_ipconfig_unref(struct connman_ipconfig *ipconfig)
{
	if (g_atomic_int_dec_and_test(&ipconfig->refcount) == TRUE) {
		connman_info("%s {remove} index %d", ipconfig->interface,
							ipconfig->index);

		free_address_list(ipconfig);

		g_free(ipconfig->interface);
		g_free(ipconfig);
	}
}

/**
 * connman_ipconfig_set_method:
 * @ipconfig: ipconfig structure
 * @method: configuration method
 *
 * Set the configuration method
 */
int connman_ipconfig_set_method(struct connman_ipconfig *ipconfig,
					enum connman_ipconfig_method method)
{
	ipconfig->method = method;

	return 0;
}

int __connman_ipconfig_get_index(struct connman_ipconfig *ipconfig)
{
	return ipconfig->index;
}

unsigned short __connman_ipconfig_get_type(struct connman_ipconfig *ipconfig)
{
	return ipconfig->type;
}

unsigned int __connman_ipconfig_get_flags(struct connman_ipconfig *ipconfig)
{
	return ipconfig->flags;
}

void __connman_ipconfig_update_link(struct connman_ipconfig *ipconfig,
					unsigned flags, unsigned change)
{
	GString *str;

	if (flags == ipconfig->flags)
		return;

	ipconfig->flags = flags;

	str = g_string_new(NULL);
	if (str == NULL)
		return;

	if (flags & IFF_UP)
		g_string_append(str, "UP");
	else
		g_string_append(str, "DOWN");

	if (flags & IFF_RUNNING)
		g_string_append(str, ",RUNNING");

	if (flags & IFF_LOWER_UP)
		g_string_append(str, ",LOWER_UP");

	connman_info("%s {update} flags %u change %u <%s>",
				ipconfig->interface, flags, change, str->str);

	g_string_free(str, TRUE);
}

void __connman_ipconfig_add_address(struct connman_ipconfig *ipconfig,
				const char *label, unsigned char prefixlen,
				const char *address, const char *broadcast)
{
	struct connman_ipaddress *ipaddress;

	ipaddress = g_try_new0(struct connman_ipaddress, 1);
	if (ipaddress == NULL)
		return;

	ipaddress->prefixlen = prefixlen;
	ipaddress->address = g_strdup(address);

	ipconfig->address_list = g_slist_append(ipconfig->address_list,
								ipaddress);

	connman_info("%s {add} address %s/%u label %s", ipconfig->interface,
						address, prefixlen, label);
}

void __connman_ipconfig_del_address(struct connman_ipconfig *ipconfig,
				const char *label, unsigned char prefixlen,
				const char *address, const char *broadcast)
{
	struct connman_ipaddress *ipaddress;

	ipaddress = find_ipaddress(ipconfig, prefixlen, address);
	if (ipaddress == NULL)
		return;

	ipconfig->address_list = g_slist_remove(ipconfig->address_list,
								ipaddress);

	g_free(ipaddress->address);
	g_free(ipaddress);

	connman_info("%s {del} address %s/%u label %s", ipconfig->interface,
						address, prefixlen, label);
}

static const char *scope2str(unsigned char scope)
{
	switch (scope) {
	case 0:
		return "UNIVERSE";
	case 253:
		return "LINK";
	}

	return "";
}

void __connman_ipconfig_add_route(struct connman_ipconfig *ipconfig,
				unsigned char scope, const char *destination,
							const char *gateway)
{
	connman_info("%s {add} route %s gw %s scope %u <%s>",
					ipconfig->interface, destination,
					gateway, scope, scope2str(scope));
}

void __connman_ipconfig_del_route(struct connman_ipconfig *ipconfig,
				unsigned char scope, const char *destination,
							const char *gateway)
{
	connman_info("%s {del} route %s gw %s scope %u <%s>",
					ipconfig->interface, destination,
					gateway, scope, scope2str(scope));
}

const char *__connman_ipconfig_method2string(enum connman_ipconfig_method method)
{
	switch (method) {
	case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
		break;
	case CONNMAN_IPCONFIG_METHOD_OFF:
		return "off";
	case CONNMAN_IPCONFIG_METHOD_STATIC:
		return "static";
	case CONNMAN_IPCONFIG_METHOD_DHCP:
		return "dhcp";
	}

	return NULL;
}

enum connman_ipconfig_method __connman_ipconfig_string2method(const char *method)
{
	if (g_strcmp0(method, "off") == 0)
		return CONNMAN_IPCONFIG_METHOD_OFF;
	else if (g_strcmp0(method, "static") == 0)
		return CONNMAN_IPCONFIG_METHOD_STATIC;
	else if (g_strcmp0(method, "dhcp") == 0)
		return CONNMAN_IPCONFIG_METHOD_DHCP;
	else
		return CONNMAN_IPCONFIG_METHOD_UNKNOWN;
}

static void append_variant(DBusMessageIter *iter, const char *prefix,
					const char *key, int type, void *val)
{
	char *str;

	if (prefix == NULL) {
		connman_dbus_dict_append_variant(iter, key, type, val);
		return;
	}

	str = g_strdup_printf("%s%s", prefix, key);
	if (str != NULL)
		connman_dbus_dict_append_variant(iter, str, type, val);

	g_free(str);
}

void __connman_ipconfig_append_ipv4(struct connman_ipconfig *ipconfig,
				DBusMessageIter *iter, const char *prefix)
{
	const char *str;

	str = __connman_ipconfig_method2string(ipconfig->method);
	if (str == NULL)
		return;

	append_variant(iter, prefix, "Method", DBUS_TYPE_STRING, &str);
}

int __connman_ipconfig_set_ipv4(struct connman_ipconfig *ipconfig,
				const char *key, DBusMessageIter *value)
{
	int type = dbus_message_iter_get_arg_type(value);

	DBG("ipconfig %p key %s type %d", ipconfig, key, type);

	if (g_strcmp0(key, "Method") == 0) {
		const char *method;

		if (type != DBUS_TYPE_STRING)
			return -EINVAL;

		dbus_message_iter_get_basic(value, &method);

		ipconfig->method = __connman_ipconfig_string2method(method);
	} else
		return -EINVAL;

	return 0;
}

int __connman_ipconfig_load(struct connman_ipconfig *ipconfig,
		GKeyFile *keyfile, const char *identifier, const char *prefix)
{
	DBG("ipconfig %p identifier %s", ipconfig, identifier);

	return 0;
}

int __connman_ipconfig_save(struct connman_ipconfig *ipconfig,
		GKeyFile *keyfile, const char *identifier, const char *prefix)
{
	DBG("ipconfig %p identifier %s", ipconfig, identifier);

	return 0;
}

static GSList *driver_list = NULL;

static gint compare_priority(gconstpointer a, gconstpointer b)
{
	const struct connman_ipconfig_driver *driver1 = a;
	const struct connman_ipconfig_driver *driver2 = b;

	return driver2->priority - driver1->priority;
}

/**
 * connman_ipconfig_driver_register:
 * @driver: IP configuration driver
 *
 * Register a new IP configuration driver
 *
 * Returns: %0 on success
 */
int connman_ipconfig_driver_register(struct connman_ipconfig_driver *driver)
{
	DBG("driver %p name %s", driver, driver->name);

	driver_list = g_slist_insert_sorted(driver_list, driver,
							compare_priority);

	return 0;
}

/**
 * connman_ipconfig_driver_unregister:
 * @driver: IP configuration driver
 *
 * Remove a previously registered IP configuration driver.
 */
void connman_ipconfig_driver_unregister(struct connman_ipconfig_driver *driver)
{
	DBG("driver %p name %s", driver, driver->name);

	driver_list = g_slist_remove(driver_list, driver);
}
