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

#ifndef __CONNMAN_DHCP_H
#define __CONNMAN_DHCP_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * SECTION:dhcp
 * @title: DHCP premitives
 * @short_description: Functions for handling DHCP
 */

enum connman_dhcp_state {
	CONNMAN_DHCP_STATE_UNKNOWN  = 0,
	CONNMAN_DHCP_STATE_IDLE     = 1,
	CONNMAN_DHCP_STATE_BOUND    = 2,
	CONNMAN_DHCP_STATE_RENEW    = 3,
	CONNMAN_DHCP_STATE_FAIL     = 4,
};

struct connman_dhcp;

struct connman_dhcp *connman_dhcp_ref(struct connman_dhcp *dhcp);
void connman_dhcp_unref(struct connman_dhcp *dhcp);

int connman_dhcp_get_index(struct connman_dhcp *dhcp);
char *connman_dhcp_get_interface(struct connman_dhcp *dhcp);

void connman_dhcp_bound(struct connman_dhcp *dhcp);

struct connman_dhcp_driver {
	const char *name;
	int priority;
	int (*request) (struct connman_dhcp *dhcp);
	int (*release) (struct connman_dhcp *dhcp);
	int (*renew) (struct connman_dhcp *dhcp);
};

int connman_dhcp_driver_register(struct connman_dhcp_driver *driver);
void connman_dhcp_driver_unregister(struct connman_dhcp_driver *driver);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_DHCP_H */
