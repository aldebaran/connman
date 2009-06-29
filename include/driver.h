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

#ifndef __CONNMAN_DRIVER_H
#define __CONNMAN_DRIVER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <connman/element.h>

/**
 * SECTION:driver
 * @title: Driver premitives
 * @short_description: Functions for registering drivers
 */

#define CONNMAN_DRIVER_PRIORITY_LOW      -100
#define CONNMAN_DRIVER_PRIORITY_DEFAULT     0
#define CONNMAN_DRIVER_PRIORITY_HIGH      100

struct connman_driver {
	const char *name;
	enum connman_element_type type;
	int priority;
	int (*probe) (struct connman_element *element);
	void (*remove) (struct connman_element *element);
	void (*update) (struct connman_element *element);
	void (*change) (struct connman_element *element);
};

int connman_driver_register(struct connman_driver *driver);
void connman_driver_unregister(struct connman_driver *driver);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_DRIVER_H */
