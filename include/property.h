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

#ifndef __CONNMAN_PROPERTY_H
#define __CONNMAN_PROPERTY_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * SECTION:property
 * @title: Property premitives
 * @short_description: Functions for handling properties
 */

#define CONNMAN_PROPERTY_ID_NAME	"Name"
#define CONNMAN_PROPERTY_ID_TYPE	"Type"
#define CONNMAN_PROPERTY_ID_PRIORITY	"Priority"
#define CONNMAN_PROPERTY_ID_STRENGTH	"Strength"

enum connman_property_id {
	CONNMAN_PROPERTY_ID_INVALID = 0,

	CONNMAN_PROPERTY_ID_IPV4_METHOD,
	CONNMAN_PROPERTY_ID_IPV4_ADDRESS,
	CONNMAN_PROPERTY_ID_IPV4_NETMASK,
	CONNMAN_PROPERTY_ID_IPV4_GATEWAY,
	CONNMAN_PROPERTY_ID_IPV4_BROADCAST,
	CONNMAN_PROPERTY_ID_IPV4_NAMESERVER,
};

enum connman_property_type {
	CONNMAN_PROPERTY_TYPE_INVALID = 0,
	CONNMAN_PROPERTY_TYPE_STRING,
	CONNMAN_PROPERTY_TYPE_UINT8,
	CONNMAN_PROPERTY_TYPE_BLOB,
};

struct connman_property {
	enum connman_property_id id;
	int type;
	int subtype;
	void *value;
	unsigned int size;
};

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_PROPERTY_H */
