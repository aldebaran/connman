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

enum connman_property_id {
	CONNMAN_PROPERTY_ID_INVALID = 0,

	CONNMAN_PROPERTY_ID_IPV4_METHOD,
	CONNMAN_PROPERTY_ID_IPV4_ADDRESS,
	CONNMAN_PROPERTY_ID_IPV4_NETMASK,
	CONNMAN_PROPERTY_ID_IPV4_GATEWAY,
	CONNMAN_PROPERTY_ID_IPV4_NAMESERVER,
};

/**
 * connman_property_flags:
 * @CONNMAN_PROPERTY_FLAG_STATIC: read-only property
 * @CONNMAN_PROPERTY_FLAG_REFERENCE: inheritated value (reference only)
 */
enum connman_property_flags {
	CONNMAN_PROPERTY_FLAG_STATIC     = (1 << 0),
	CONNMAN_PROPERTY_FLAG_REFERENCE  = (1 << 1),
};

struct connman_property {
	enum connman_property_flags flags;
	enum connman_property_id id;
	char *name;
	int type;
	void *value;
};

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_PROPERTY_H */
