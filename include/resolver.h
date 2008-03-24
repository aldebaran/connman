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

#ifndef __CONNMAN_RESOLVER_H
#define __CONNMAN_RESOLVER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <connman/iface.h>

struct connman_resolver_driver {
	const char *name;
	int (*append) (struct connman_iface *iface, const char *nameserver);
	int (*remove) (struct connman_iface *iface);
};

extern int connman_resolver_register(struct connman_resolver_driver *driver);
extern void connman_resolver_unregister(struct connman_resolver_driver *driver);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_RESOLVER_H */
