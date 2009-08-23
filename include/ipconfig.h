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

#ifndef __CONNMAN_IPCONFIG_H
#define __CONNMAN_IPCONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * SECTION:ipconfig
 * @title: IP configuration premitives
 * @short_description: Functions for IP configuration handling
 */

struct connman_ipaddress {
	unsigned char prefixlen;
	char *local;
	char *peer;
	char *broadcast;
};

struct connman_ipaddress *connman_ipaddress_alloc(void);
void connman_ipaddress_free(struct connman_ipaddress *ipaddress);
void connman_ipaddress_copy(struct connman_ipaddress *ipaddress,
					struct connman_ipaddress *source);

enum connman_ipconfig_type {
	CONNMAN_IPCONFIG_TYPE_UNKNOWN = 0,
	CONNMAN_IPCONFIG_TYPE_IPV4    = 1,
	CONNMAN_IPCONFIG_TYPE_IPV6    = 2,
};

enum connman_ipconfig_method {
	CONNMAN_IPCONFIG_METHOD_UNKNOWN = 0,
	CONNMAN_IPCONFIG_METHOD_IGNORE  = 1,
	CONNMAN_IPCONFIG_METHOD_STATIC  = 2,
	CONNMAN_IPCONFIG_METHOD_DHCP    = 3,
};

struct connman_ipconfig;

struct connman_ipconfig_ops {
	void (*up) (struct connman_ipconfig *ipconfig);
	void (*down) (struct connman_ipconfig *ipconfig);
	void (*lower_up) (struct connman_ipconfig *ipconfig);
	void (*lower_down) (struct connman_ipconfig *ipconfig);
	void (*ip_bound) (struct connman_ipconfig *ipconfig);
	void (*ip_release) (struct connman_ipconfig *ipconfig);
};

struct connman_ipconfig *connman_ipconfig_create(int index);
struct connman_ipconfig *connman_ipconfig_clone(struct connman_ipconfig *ipconfig);
struct connman_ipconfig *connman_ipconfig_ref(struct connman_ipconfig *ipconfig);
void connman_ipconfig_unref(struct connman_ipconfig *ipconfig);

void *connman_ipconfig_get_data(struct connman_ipconfig *ipconfig);
void connman_ipconfig_set_data(struct connman_ipconfig *ipconfig, void *data);

int connman_ipconfig_get_index(struct connman_ipconfig *ipconfig);
const char *connman_ipconfig_get_ifname(struct connman_ipconfig *ipconfig);

void connman_ipconfig_set_ops(struct connman_ipconfig *ipconfig,
				const struct connman_ipconfig_ops *ops);

int connman_ipconfig_set_method(struct connman_ipconfig *ipconfig,
					enum connman_ipconfig_method method);

void connman_ipconfig_bind(struct connman_ipconfig *ipconfig,
					struct connman_ipaddress *ipaddress);

#define CONNMAN_IPCONFIG_PRIORITY_LOW      -100
#define CONNMAN_IPCONFIG_PRIORITY_DEFAULT     0
#define CONNMAN_IPCONFIG_PRIORITY_HIGH      100

struct connman_ipconfig_driver {
	const char *name;
	enum connman_ipconfig_type type;
	int priority;
	int (*request) (struct connman_ipconfig *ipconfig);
	int (*release) (struct connman_ipconfig *ipconfig);
	int (*renew) (struct connman_ipconfig *ipconfig);
};

int connman_ipconfig_driver_register(struct connman_ipconfig_driver *driver);
void connman_ipconfig_driver_unregister(struct connman_ipconfig_driver *driver);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_IPCONFIG_H */
