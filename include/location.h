/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2010  Intel Corporation. All rights reserved.
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

#ifndef __CONNMAN_LOCATION_H
#define __CONNMAN_LOCATION_H

#include <connman/service.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CONNMAN_LOCATION_PRIORITY_LOW          -100
#define CONNMAN_LOCATION_PRIORITY_DEFAULT      0
#define CONNMAN_LOCATION_PRIORITY_HIGH         100

/**
 * SECTION:location
 * @title: Location premitives
 * @short_description: Functions for detecting locations
 */

enum connman_location_result {
	CONNMAN_LOCATION_RESULT_UNKNOWN = 0,
	CONNMAN_LOCATION_RESULT_PORTAL  = 1,
	CONNMAN_LOCATION_RESULT_ONLINE  = 2,
};

struct connman_location;

struct connman_location *connman_location_ref(struct connman_location *location);
void connman_location_unref(struct connman_location *location);

enum connman_service_type connman_location_get_type(struct connman_location *location);
char *connman_location_get_interface(struct connman_location *location);
void connman_location_report_result(struct connman_location *location,
					enum connman_location_result result);

void *connman_location_get_data(struct connman_location *location);
void connman_location_set_data(struct connman_location *location, void *data);

struct connman_location_driver {
	const char *name;
	enum connman_service_type type;
	int priority;
	int (*detect) (struct connman_location *location);
	int (*finish) (struct connman_location *location);
};

int connman_location_driver_register(struct connman_location_driver *driver);
void connman_location_driver_unregister(struct connman_location_driver *driver);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_LOCATION_H */
