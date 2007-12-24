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

#ifndef __CONNMAN_IFACE_H
#define __CONNMAN_IFACE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <netinet/in.h>

enum connman_iface_type {
	CONNMAN_IFACE_TYPE_UNKNOWN   = 0,
	CONNMAN_IFACE_TYPE_80203     = 1,
	CONNMAN_IFACE_TYPE_80211     = 2,
	CONNMAN_IFACE_TYPE_WIMAX     = 3,
	CONNMAN_IFACE_TYPE_BLUETOOTH = 4,
};

enum connman_iface_flags {
	CONNMAN_IFACE_FLAGS_CARRIER_DETECT	= (1 << 0),
	CONNMAN_IFACE_FLAGS_IPV4		= (1 << 1),
	CONNMAN_IFACE_FLAGS_IPV6		= (1 << 2),
};

struct connman_ipv4 {
	struct in_addr address;
	struct in_addr netmask;
	struct in_addr gateway;
	struct in_addr network;
	struct in_addr broadcast;
	struct in_addr nameserver;
};

struct connman_iface {
	struct connman_iface_driver *driver;
	char *path;
	char *udi;
	char *sysfs;
	enum connman_iface_type type;
	enum connman_iface_flags flags;
	struct connman_ipv4 ipv4;
};

struct connman_iface_driver {
	const char *name;
	const char *capability;
	int (*probe) (struct connman_iface *iface);
	void (*remove) (struct connman_iface *iface);
	int (*get_ipv4) (struct connman_iface *iface,
					struct connman_ipv4 *ipv4);
	int (*set_ipv4) (struct connman_iface *iface,
					struct connman_ipv4 *ipv4);
};

extern int connman_iface_register(struct connman_iface_driver *driver);
extern void connman_iface_unregister(struct connman_iface_driver *driver);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_IFACE_H */
