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

#ifndef __CONNMAN_DEVICE_H
#define __CONNMAN_DEVICE_H

#include <connman/types.h>
#include <connman/network.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * SECTION:device
 * @title: Device premitives
 * @short_description: Functions for handling devices
 */

enum connman_device_type {
	CONNMAN_DEVICE_TYPE_UNKNOWN   = 0,
	CONNMAN_DEVICE_TYPE_ETHERNET  = 1,
	CONNMAN_DEVICE_TYPE_WIFI      = 2,
	CONNMAN_DEVICE_TYPE_WIMAX     = 3,
	CONNMAN_DEVICE_TYPE_BLUETOOTH = 4,
	CONNMAN_DEVICE_TYPE_CELLULAR  = 5,
	CONNMAN_DEVICE_TYPE_GPS       = 6,
	CONNMAN_DEVICE_TYPE_GADGET    = 7,
	CONNMAN_DEVICE_TYPE_VENDOR    = 10000,
};

#define CONNMAN_DEVICE_PRIORITY_LOW      -100
#define CONNMAN_DEVICE_PRIORITY_DEFAULT     0
#define CONNMAN_DEVICE_PRIORITY_HIGH      100

struct connman_device;

struct connman_device *connman_device_create(const char *node,
						enum connman_device_type type);

#define connman_device_ref(device) \
	connman_device_ref_debug(device, __FILE__, __LINE__, __func__)

#define connman_device_unref(device) \
	connman_device_unref_debug(device, __FILE__, __LINE__, __func__)

struct connman_device *
connman_device_ref_debug(struct connman_device *device,
			const char *file, int line, const char *caller);
void connman_device_unref_debug(struct connman_device *device,
			const char *file, int line, const char *caller);

enum connman_device_type connman_device_get_type(struct connman_device *device);
void connman_device_set_index(struct connman_device *device, int index);
int connman_device_get_index(struct connman_device *device);
void connman_device_set_interface(struct connman_device *device,
						const char *interface);

void connman_device_set_ident(struct connman_device *device,
						const char *ident);
const char *connman_device_get_ident(struct connman_device *device);

int connman_device_set_powered(struct connman_device *device,
						connman_bool_t powered);
int connman_device_set_scanning(struct connman_device *device,
						connman_bool_t scanning);
connman_bool_t connman_device_get_scanning(struct connman_device *device);
void connman_device_reset_scanning(struct connman_device *device);

int connman_device_set_disconnected(struct connman_device *device,
						connman_bool_t disconnected);
connman_bool_t connman_device_get_disconnected(struct connman_device *device);

int connman_device_set_string(struct connman_device *device,
					const char *key, const char *value);
const char *connman_device_get_string(struct connman_device *device,
							const char *key);

int connman_device_add_network(struct connman_device *device,
					struct connman_network *network);
struct connman_network *connman_device_get_network(struct connman_device *device,
							const char *identifier);
int connman_device_remove_network(struct connman_device *device,
					struct connman_network *network);
void connman_device_remove_all_networks(struct connman_device *device);

int connman_device_register(struct connman_device *device);
void connman_device_unregister(struct connman_device *device);

void *connman_device_get_data(struct connman_device *device);
void connman_device_set_data(struct connman_device *device, void *data);

struct connman_device_driver {
	const char *name;
	enum connman_device_type type;
	int priority;
	int (*probe) (struct connman_device *device);
	void (*remove) (struct connman_device *device);
	int (*enable) (struct connman_device *device);
	int (*disable) (struct connman_device *device);
	int (*scan) (struct connman_device *device);
	int (*scan_fast) (struct connman_device *device);
	int (*scan_hidden)(struct connman_device *device,
			const char *ssid, unsigned int ssid_len,
			const char *identity, const char* passphrase,
			void *user_data);
};

int connman_device_driver_register(struct connman_device_driver *driver);
void connman_device_driver_unregister(struct connman_device_driver *driver);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_DEVICE_H */
