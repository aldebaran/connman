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

#ifndef __CONNMAN_DEVICE_H
#define __CONNMAN_DEVICE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <connman/element.h>

/**
 * SECTION:device
 * @title: Device driver premitives
 * @short_description: Functions for registering device drivers
 */

enum connman_device_type {
	CONNMAN_DEVICE_TYPE_UNKNOWN   = CONNMAN_ELEMENT_SUBTYPE_UNKNOWN,
	CONNMAN_DEVICE_TYPE_FAKE      = CONNMAN_ELEMENT_SUBTYPE_FAKE,
	CONNMAN_DEVICE_TYPE_ETHERNET  = CONNMAN_ELEMENT_SUBTYPE_ETHERNET,
	CONNMAN_DEVICE_TYPE_WIFI      = CONNMAN_ELEMENT_SUBTYPE_WIFI,
	CONNMAN_DEVICE_TYPE_WIMAX     = CONNMAN_ELEMENT_SUBTYPE_WIMAX,
	CONNMAN_DEVICE_TYPE_MODEM     = CONNMAN_ELEMENT_SUBTYPE_MODEM,
	CONNMAN_DEVICE_TYPE_BLUETOOTH = CONNMAN_ELEMENT_SUBTYPE_BLUETOOTH,
};

enum connman_device_capabilities {
	CONNMAN_DEVICE_CAPABILITY_SCANNING = (1 << 0),
};

enum connman_device_state {
	CONNMAN_DEVICE_STATE_UNKNOWN = 0,
	CONNMAN_DEVICE_STATE_OFF     = 1,
};

struct connman_device_driver;

struct connman_device {
	struct connman_element *element;
	unsigned long capabilities;
	enum connman_device_state state;

	struct connman_device_driver *driver;
	void *driver_data;

	GSList *networks;
};

extern int connman_device_set_enabled(struct connman_device *device,
							gboolean enabled);

struct connman_device_driver {
	const char *name;
	enum connman_device_type type;
	int priority;
	int (*probe) (struct connman_device *device);
	void (*remove) (struct connman_device *device);
	int (*scan) (struct connman_device *device);
};

extern int connman_device_driver_register(struct connman_device_driver *driver);
extern void connman_device_driver_unregister(struct connman_device_driver *driver);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_DEVICE_H */
