/*
 *
 *  DHCP client library with GLib integration
 *
 *  Copyright (C) 2009-2010  Intel Corporation. All rights reserved.
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

#ifndef __G_DHCP_H
#define __G_DHCP_H

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif

struct _GDHCPClient;

typedef struct _GDHCPClient GDHCPClient;

typedef enum {
	G_DHCP_CLIENT_ERROR_NONE,
	G_DHCP_CLIENT_ERROR_INTERFACE_UNAVAILABLE,
	G_DHCP_CLIENT_ERROR_INTERFACE_IN_USE,
	G_DHCP_CLIENT_ERROR_INTERFACE_DOWN,
	G_DHCP_CLIENT_ERROR_NOMEM,
	G_DHCP_CLIENT_ERROR_INVALID_INDEX,
	G_DHCP_CLIENT_ERROR_INVALID_OPTION
} GDHCPClientError;

typedef enum {
	G_DHCP_CLIENT_EVENT_LEASE_AVAILABLE,
	G_DHCP_CLIENT_EVENT_NO_LEASE,
	G_DHCP_CLIENT_EVENT_LEASE_LOST,
	G_DHCP_CLIENT_EVENT_ADDRESS_CONFLICT,
} GDHCPClientEvent;

typedef enum {
	G_DHCP_IPV4,
	G_DHCP_IPV6,
} GDHCPType;

#define G_DHCP_SUBNET		0x01
#define G_DHCP_ROUTER		0x03
#define G_DHCP_TIME_SERVER	0x04
#define G_DHCP_DNS_SERVER	0x06
#define G_DHCP_HOST_NAME	0x0c
#define G_DHCP_NTP_SERVER	0x2a

typedef void (*GDHCPClientEventFunc) (GDHCPClient *client, gpointer user_data);

typedef void (*GDHCPDebugFunc)(const char *str, gpointer user_data);

GDHCPClient *g_dhcp_client_new(GDHCPType type, int index,
						GDHCPClientError *error);

int g_dhcp_client_start(GDHCPClient *client);
void g_dhcp_client_stop(GDHCPClient *client);

void g_dhcp_client_ref(GDHCPClient *client);
void g_dhcp_client_unref(GDHCPClient *client);

void g_dhcp_client_register_event(GDHCPClient *client,
					GDHCPClientEvent event,
					GDHCPClientEventFunc func,
					gpointer user_data);

GDHCPClientError g_dhcp_client_set_request(GDHCPClient *client,
						unsigned char option_code);
GDHCPClientError g_dhcp_client_set_send(GDHCPClient *client,
						unsigned char option_code,
						const char *option_value);

char *g_dhcp_client_get_address(GDHCPClient *client);
GList *g_dhcp_client_get_option(GDHCPClient *client,
						unsigned char option_code);
int g_dhcp_client_get_index(GDHCPClient *client);

void g_dhcp_client_set_debug(GDHCPClient *client,
					GDHCPDebugFunc func, gpointer data);

#ifdef __cplusplus
}
#endif

#endif /* __G_DHCP_H */
