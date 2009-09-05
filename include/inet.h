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

#ifndef __CONNMAN_INET_H
#define __CONNMAN_INET_H

#include <arpa/inet.h>

#include <connman/device.h>
#include <connman/ipconfig.h>

#ifdef __cplusplus
extern "C" {
#endif

int connman_inet_ifindex(const char *name);
char *connman_inet_ifname(int index);

int connman_inet_ifup(int index);
int connman_inet_ifdown(int index);

struct connman_device *connman_inet_create_device(int index);
connman_bool_t connman_inet_is_mac80211(int index);

int connman_inet_set_address(int index, struct connman_ipaddress *ipaddress);
int connman_inet_clear_address(int index);
int connman_inet_set_gateway(int index, struct in_addr gateway);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_INET_H */
