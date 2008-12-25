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

#ifndef __CONNMAN_NETWORK_H
#define __CONNMAN_NETWORK_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * SECTION:network
 * @title: Network premitives
 * @short_description: Functions for handling networks
 */

enum connman_network_type {
	CONNMAN_NETWORK_TYPE_UNKNOWN = 0,
	CONNMAN_NETWORK_TYPE_WIFI    = 1,
};

struct connman_network;

extern struct connman_network *connman_network_create(const char *identifier,
						enum connman_network_type type);
extern struct connman_network *connman_network_ref(struct connman_network *network);
extern void connman_network_unref(struct connman_network *network);

struct connman_network_driver {
	const char *name;
	enum connman_network_type type;
	int priority;
	int (*probe) (struct connman_network *network);
	void (*remove) (struct connman_network *network);
};

extern int connman_network_driver_register(struct connman_network_driver *driver);
extern void connman_network_driver_unregister(struct connman_network_driver *driver);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_NETWORK_H */
