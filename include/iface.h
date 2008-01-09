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
	CONNMAN_IFACE_TYPE_MODEM     = 4,
	CONNMAN_IFACE_TYPE_BLUETOOTH = 5,
};

enum connman_iface_flags {
	CONNMAN_IFACE_FLAG_RTNL           = (1 << 0),
	CONNMAN_IFACE_FLAG_IPV4           = (1 << 1),
	CONNMAN_IFACE_FLAG_IPV6           = (1 << 2),
	CONNMAN_IFACE_FLAG_CARRIER_DETECT = (1 << 3),
};

enum connman_iface_state {
	CONNMAN_IFACE_STATE_UNKNOWN   = 0,
	CONNMAN_IFACE_STATE_OFF       = 1,
	CONNMAN_IFACE_STATE_ENABLED   = 2,
	CONNMAN_IFACE_STATE_CONNECT   = 3,
	CONNMAN_IFACE_STATE_CONFIG    = 4,
	CONNMAN_IFACE_STATE_CARRIER   = 5,
	CONNMAN_IFACE_STATE_READY     = 6,
	CONNMAN_IFACE_STATE_SHUTDOWN  = 7,
};

enum connman_iface_policy {
	CONNMAN_IFACE_POLICY_UNKNOWN = 0,
	CONNMAN_IFACE_POLICY_OFF     = 1,
	CONNMAN_IFACE_POLICY_IGNORE  = 2,
	CONNMAN_IFACE_POLICY_AUTO    = 3,
};

enum connman_ipv4_method {
	CONNMAN_IPV4_METHOD_UNKNOWN = 0,
	CONNMAN_IPV4_METHOD_OFF     = 1,
	CONNMAN_IPV4_METHOD_STATIC  = 2,
	CONNMAN_IPV4_METHOD_DHCP    = 3,
};

struct connman_ipv4 {
	enum connman_ipv4_method method;
	struct in_addr address;
	struct in_addr netmask;
	struct in_addr gateway;
	struct in_addr network;
	struct in_addr broadcast;
	struct in_addr nameserver;
};

struct connman_network {
	char *essid;
	char *psk;
};

struct connman_iface {
	char *path;
	char *udi;
	char *sysfs;
	char *identifier;
	int index;
	int carrier;
	enum connman_iface_type type;
	enum connman_iface_flags flags;
	enum connman_iface_state state;
	enum connman_iface_policy policy;
	struct connman_network network;
	struct connman_ipv4 ipv4;

	struct connman_iface_driver *driver;
	void *driver_data;

	struct {
		char *driver;
		char *vendor;
		char *product;
	} device;
};

struct connman_iface_driver {
	const char *name;
	const char *capability;
	int (*probe) (struct connman_iface *iface);
	void (*remove) (struct connman_iface *iface);
	int (*activate) (struct connman_iface *iface);
	int (*shutdown) (struct connman_iface *iface);
	int (*get_ipv4) (struct connman_iface *iface,
					struct connman_ipv4 *ipv4);
	int (*set_ipv4) (struct connman_iface *iface,
					struct connman_ipv4 *ipv4);
	int (*scan) (struct connman_iface *iface);
	int (*connect) (struct connman_iface *iface,
					struct connman_network *network);

	void (*set_network) (struct connman_iface *iface,
						const char *network);
	void (*set_passphrase) (struct connman_iface *iface,
						const char *passphrase);

	void (*rtnl_carrier) (struct connman_iface *iface, int carrier);
	void (*rtnl_wireless) (struct connman_iface *iface,
					void *data, unsigned short len);
};

extern int connman_iface_register(struct connman_iface_driver *driver);
extern void connman_iface_unregister(struct connman_iface_driver *driver);

static inline void *connman_iface_get_data(struct connman_iface *iface)
{
	return iface->driver_data;
}

static inline void connman_iface_set_data(struct connman_iface *iface,
								void *data)
{
	iface->driver_data = data;
}

extern int connman_iface_update(struct connman_iface *iface,
					enum connman_iface_state state);

extern void connman_iface_indicate_carrier(struct connman_iface *iface,
							int carrier);

extern int connman_iface_get_ipv4(struct connman_iface *iface,
						struct connman_ipv4 *ipv4);
extern int connman_iface_set_ipv4(struct connman_iface *iface,
						struct connman_ipv4 *ipv4);
extern int connman_iface_clear_ipv4(struct connman_iface *iface);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_IFACE_H */
