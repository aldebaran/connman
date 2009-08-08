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

#include <gdbus.h>

#include "connman.h"

struct connman_ipconfig {
	gint refcount;
	int index;
	char *interface;
	enum connman_ipconfig_method method;
};

/**
 * connman_ipconfig_create:
 *
 * Allocate a new ipconfig structure.
 *
 * Returns: a newly-allocated #connman_ipconfig structure
 */
struct connman_ipconfig *connman_ipconfig_create(const char *interface)
{
	struct connman_ipconfig *ipconfig;
	int index;

	DBG("");

	index = connman_inet_ifindex(interface);
	if (index < 0)
		return NULL;

	ipconfig = g_try_new0(struct connman_ipconfig, 1);
	if (ipconfig == NULL)
		return NULL;

	ipconfig->index = index;
	ipconfig->interface = g_strdup(interface);

	DBG("ipconfig %p", ipconfig);

	__connman_rtnl_register_ipconfig(ipconfig);

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
		__connman_rtnl_unregister_ipconfig(ipconfig);

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

void __connman_ipconfig_add_address(struct connman_ipconfig *ipconfig,
				const char *label, unsigned int prefixlen,
				const char *address, const char *broadcast)
{
	connman_info("%s {add} address %s/%d label %s", ipconfig->interface,
						address, prefixlen, label);
}

void __connman_ipconfig_del_address(struct connman_ipconfig *ipconfig,
				const char *label, unsigned int prefixlen,
				const char *address, const char *broadcast)
{
	connman_info("%s {del} address %s/%d label %s", ipconfig->interface,
						address, prefixlen, label);
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
