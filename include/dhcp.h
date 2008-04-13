/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2008  Intel Corporation. All rights reserved.
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

#ifndef __CONNMAN_DHCP_H
#define __CONNMAN_DHCP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <connman/iface.h>

enum connman_dhcp_state {
	CONNMAN_DHCP_STATE_UNKNOWN = 0,
	CONNMAN_DHCP_STATE_INIT    = 1,
	CONNMAN_DHCP_STATE_BOUND   = 2,
	CONNMAN_DHCP_STATE_RENEW   = 3,
	CONNMAN_DHCP_STATE_FAILED  = 4,
};

struct connman_dhcp_driver {
	const char *name;
	int (*request) (struct connman_iface *iface);
	int (*release) (struct connman_iface *iface);
};

extern int connman_dhcp_register(struct connman_dhcp_driver *driver);
extern void connman_dhcp_unregister(struct connman_dhcp_driver *driver);

extern int connman_dhcp_update(struct connman_iface *iface,
				enum connman_dhcp_state state,
					struct connman_ipv4 *ipv4);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_DHCP_H */
