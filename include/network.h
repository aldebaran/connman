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

#ifndef __CONNMAN_NETWORK_H
#define __CONNMAN_NETWORK_H

#include <connman/types.h>
#include <connman/device.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * SECTION:network
 * @title: Network premitives
 * @short_description: Functions for handling networks
 */

enum connman_network_type {
	CONNMAN_NETWORK_TYPE_UNKNOWN       = 0,
	CONNMAN_NETWORK_TYPE_WIFI          = 1,
	CONNMAN_NETWORK_TYPE_WIMAX         = 2,
	CONNMAN_NETWORK_TYPE_BLUETOOTH_PAN = 8,
	CONNMAN_NETWORK_TYPE_BLUETOOTH_DUN = 9,
	CONNMAN_NETWORK_TYPE_MBM           = 22,
	CONNMAN_NETWORK_TYPE_HSO           = 23,
	CONNMAN_NETWORK_TYPE_VENDOR        = 10000,
};

enum connman_network_protocol {
	CONNMAN_NETWORK_PROTOCOL_UNKNOWN = 0,
	CONNMAN_NETWORK_PROTOCOL_IP      = 1,
	CONNMAN_NETWORK_PROTOCOL_PPP     = 2,
};

struct connman_network;

struct connman_network *connman_network_create(const char *identifier,
					enum connman_network_type type);
struct connman_network *connman_network_ref(struct connman_network *network);
void connman_network_unref(struct connman_network *network);

enum connman_network_type connman_network_get_type(struct connman_network *network);
const char *connman_network_get_identifier(struct connman_network *network);

const char *connman_network_get_path(struct connman_network *network);
void connman_network_set_index(struct connman_network *network, int index);
int connman_network_get_index(struct connman_network *network);

void connman_network_set_protocol(struct connman_network *network,
					enum connman_network_protocol protocol);
void connman_network_set_group(struct connman_network *network,
						const char *group);
const char *connman_network_get_group(struct connman_network *network);

int connman_network_set_available(struct connman_network *network,
						connman_bool_t available);
connman_bool_t connman_network_get_available(struct connman_network *network);
int connman_network_set_associating(struct connman_network *network,
						connman_bool_t associating);
int connman_network_set_connected(struct connman_network *network,
						connman_bool_t connected);
connman_bool_t connman_network_get_connected(struct connman_network *network);

connman_bool_t connman_network_get_associating(struct connman_network *network);

int connman_network_set_address(struct connman_network *network,
				const void *address, unsigned int size);
int connman_network_set_name(struct connman_network *network,
							const char *name);
int connman_network_set_strength(struct connman_network *network,
						connman_uint8_t strength);

int connman_network_set_string(struct connman_network *network,
					const char *key, const char *value);
const char *connman_network_get_string(struct connman_network *network,
							const char *key);
int connman_network_set_uint8(struct connman_network *network,
					const char *key, connman_uint8_t value);
connman_uint8_t connman_network_get_uint8(struct connman_network *network,
							const char *key);
int connman_network_set_uint16(struct connman_network *network,
					const char *key, connman_uint16_t value);
connman_uint16_t connman_network_get_uint16(struct connman_network *network,
							const char *key);
int connman_network_set_blob(struct connman_network *network,
			const char *key, const void *data, unsigned int size);
const void *connman_network_get_blob(struct connman_network *network,
					const char *key, unsigned int *size);

struct connman_device *connman_network_get_device(struct connman_network *network);

void *connman_network_get_data(struct connman_network *network);
void connman_network_set_data(struct connman_network *network, void *data);

struct connman_network_driver {
	const char *name;
	enum connman_network_type type;
	int priority;
	int (*probe) (struct connman_network *network);
	void (*remove) (struct connman_network *network);
	int (*connect) (struct connman_network *network);
	int (*disconnect) (struct connman_network *network);
};

int connman_network_driver_register(struct connman_network_driver *driver);
void connman_network_driver_unregister(struct connman_network_driver *driver);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_NETWORK_H */
