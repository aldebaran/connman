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

#ifndef __CONNMAN_ELEMENT_H
#define __CONNMAN_ELEMENT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <errno.h>
#include <glib.h>

#include <connman/property.h>

/**
 * SECTION:element
 * @title: Element premitives
 * @short_description: Functions for handling elements
 */

enum connman_element_state {
	CONNMAN_ELEMENT_STATE_UNKNOWN   = 0,
	CONNMAN_ELEMENT_STATE_CONNECT   = 1,
	CONNMAN_ELEMENT_STATE_CONNECTED = 2,
	CONNMAN_ELEMENT_STATE_CLOSED    = 3,
};

enum connman_element_policy {
	CONNMAN_ELEMENT_POLICY_UNKNOWN = 0,
	CONNMAN_ELEMENT_POLICY_OFF     = 1,
	CONNMAN_ELEMENT_POLICY_AUTO    = 2,
	CONNMAN_ELEMENT_POLICY_IGNORE  = 3,
	CONNMAN_ELEMENT_POLICY_ASK     = 4,
};

enum connman_element_type {
	CONNMAN_ELEMENT_TYPE_UNKNOWN    = 0,
	CONNMAN_ELEMENT_TYPE_ROOT       = 1,
	CONNMAN_ELEMENT_TYPE_PROFILE    = 2,
	CONNMAN_ELEMENT_TYPE_DEVICE     = 3,
	CONNMAN_ELEMENT_TYPE_NETWORK    = 4,
	CONNMAN_ELEMENT_TYPE_SERVICE    = 5,
	CONNMAN_ELEMENT_TYPE_IPV4       = 6,
	CONNMAN_ELEMENT_TYPE_IPV6       = 7,
	CONNMAN_ELEMENT_TYPE_DHCP       = 8,
	CONNMAN_ELEMENT_TYPE_BOOTP      = 9,
	CONNMAN_ELEMENT_TYPE_ZEROCONF   = 10,

	CONNMAN_ELEMENT_TYPE_CONNECTION = 42,
};

enum connman_element_subtype {
	CONNMAN_ELEMENT_SUBTYPE_UNKNOWN   = 0,
	CONNMAN_ELEMENT_SUBTYPE_FAKE      = 1,
	CONNMAN_ELEMENT_SUBTYPE_NETWORK   = 2,
	CONNMAN_ELEMENT_SUBTYPE_ETHERNET  = 3,
	CONNMAN_ELEMENT_SUBTYPE_WIFI      = 4,
	CONNMAN_ELEMENT_SUBTYPE_WIMAX     = 5,
	CONNMAN_ELEMENT_SUBTYPE_MODEM     = 6,
	CONNMAN_ELEMENT_SUBTYPE_BLUETOOTH = 7,
};

struct connman_driver;

struct connman_element {
	gint refcount;
	gint index;
	gchar *name;
	gchar *path;
	enum connman_element_type type;
	enum connman_element_subtype subtype;
	enum connman_element_state state;
	enum connman_element_policy policy;
	gboolean enabled;
	gboolean available;
	gboolean remember;
	guint16 priority;
	gchar *devname;

	struct connman_element *parent;

	struct connman_driver *driver;
	void *driver_data;

	GSList *properties;

	struct {
		gchar *address;
		gchar *netmask;
		gchar *gateway;
		gchar *network;
		gchar *broadcast;
		gchar *nameserver;
	} ipv4;

	struct {
		gchar *security;
		gchar *passphrase;
	} wifi;
};

extern struct connman_element *connman_element_create(const char *name);
extern struct connman_element *connman_element_ref(struct connman_element *element);
extern void connman_element_unref(struct connman_element *element);

extern int connman_element_add_static_property(struct connman_element *element,
				const char *name, int type, const void *value);
extern int connman_element_add_static_array_property(struct connman_element *element,
			const char *name, int type, const void *value, int len);
extern int connman_element_define_properties(struct connman_element *element, ...);
extern int connman_element_create_property(struct connman_element *element,
						const char *name, int type);
extern int connman_element_set_property(struct connman_element *element,
				enum connman_property_id id, const void *value);
extern int connman_element_get_value(struct connman_element *element,
				enum connman_property_id id, void *value);
extern gboolean connman_element_get_static_property(struct connman_element *element,
						const char *name, void *value);
extern gboolean connman_element_get_static_array_property(struct connman_element *element,
					const char *name, void *value, int *len);
extern gboolean connman_element_match_static_property(struct connman_element *element,
					const char *name, const void *value);

extern int connman_element_register(struct connman_element *element,
					struct connman_element *parent);
extern void connman_element_unregister(struct connman_element *element);
extern void connman_element_unregister_children(struct connman_element *element);
extern void connman_element_update(struct connman_element *element);

extern int connman_element_set_enabled(struct connman_element *element,
							gboolean enabled);

extern int connman_element_set_enabled(struct connman_element *element,
							gboolean enabled);

static inline void *connman_element_get_data(struct connman_element *element)
{
	return element->driver_data;
}

static inline void connman_element_set_data(struct connman_element *element,
								void *data)
{
	element->driver_data = data;
}

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_ELEMENT_H */
