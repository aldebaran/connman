/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2012  Intel Corporation. All rights reserved.
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

struct connman_ipaddress;

struct connman_ipaddress *connman_ipaddress_alloc(int family);
void connman_ipaddress_free(struct connman_ipaddress *ipaddress);
int connman_ipaddress_set_ipv4(struct connman_ipaddress *ipaddress,
				const char *address, const char *netmask,
				const char *gateway);
int connman_ipaddress_set_ipv6(struct connman_ipaddress *ipaddress,
				const char *address,
				unsigned char prefix_length,
				const char *gateway);
void connman_ipaddress_set_peer(struct connman_ipaddress *ipaddress,
				const char *peer);
void connman_ipaddress_clear(struct connman_ipaddress *ipaddress);
void connman_ipaddress_copy(struct connman_ipaddress *ipaddress,
					struct connman_ipaddress *source);

enum connman_ipconfig_type {
	CONNMAN_IPCONFIG_TYPE_UNKNOWN = 0,
	CONNMAN_IPCONFIG_TYPE_ALL     = 0,
	CONNMAN_IPCONFIG_TYPE_IPV4    = 1,
	CONNMAN_IPCONFIG_TYPE_IPV6    = 2,
};

enum connman_ipconfig_method {
	CONNMAN_IPCONFIG_METHOD_UNKNOWN = 0,
	CONNMAN_IPCONFIG_METHOD_OFF     = 1,
	CONNMAN_IPCONFIG_METHOD_FIXED   = 2,
	CONNMAN_IPCONFIG_METHOD_MANUAL  = 3,
	CONNMAN_IPCONFIG_METHOD_DHCP    = 4,
	CONNMAN_IPCONFIG_METHOD_AUTO    = 5,
};

struct connman_ipconfig;

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_IPCONFIG_H */
