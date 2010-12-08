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

#ifndef __CONNMAN_SERVICE_H
#define __CONNMAN_SERVICE_H

#include <connman/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * SECTION:service
 * @title: Service premitives
 * @short_description: Functions for handling services
 */

enum connman_service_type {
	CONNMAN_SERVICE_TYPE_UNKNOWN   = 0,
	CONNMAN_SERVICE_TYPE_SYSTEM    = 1,
	CONNMAN_SERVICE_TYPE_ETHERNET  = 2,
	CONNMAN_SERVICE_TYPE_WIFI      = 3,
	CONNMAN_SERVICE_TYPE_WIMAX     = 4,
	CONNMAN_SERVICE_TYPE_BLUETOOTH = 5,
	CONNMAN_SERVICE_TYPE_CELLULAR  = 6,
	CONNMAN_SERVICE_TYPE_GPS       = 7,
	CONNMAN_SERVICE_TYPE_VPN       = 8,
	CONNMAN_SERVICE_TYPE_GADGET    = 9,
};

enum connman_service_mode {
	CONNMAN_SERVICE_MODE_UNKNOWN = 0,
	CONNMAN_SERVICE_MODE_MANAGED = 1,
	CONNMAN_SERVICE_MODE_ADHOC   = 2,
	CONNMAN_SERVICE_MODE_GPRS    = 3,
	CONNMAN_SERVICE_MODE_EDGE    = 4,
	CONNMAN_SERVICE_MODE_UMTS    = 5,
};

enum connman_service_security {
	CONNMAN_SERVICE_SECURITY_UNKNOWN = 0,
	CONNMAN_SERVICE_SECURITY_NONE    = 1,
	CONNMAN_SERVICE_SECURITY_WEP     = 2,
	CONNMAN_SERVICE_SECURITY_PSK     = 3,
	CONNMAN_SERVICE_SECURITY_8021X   = 4,
	CONNMAN_SERVICE_SECURITY_WPA     = 8,
	CONNMAN_SERVICE_SECURITY_RSN     = 9,
};

enum connman_service_state {
	CONNMAN_SERVICE_STATE_UNKNOWN       = 0,
	CONNMAN_SERVICE_STATE_IDLE          = 1,
	CONNMAN_SERVICE_STATE_ASSOCIATION   = 2,
	CONNMAN_SERVICE_STATE_CONFIGURATION = 3,
	CONNMAN_SERVICE_STATE_READY         = 4,
	CONNMAN_SERVICE_STATE_ONLINE        = 5,
	CONNMAN_SERVICE_STATE_DISCONNECT    = 6,
	CONNMAN_SERVICE_STATE_FAILURE       = 7,
};

enum connman_service_error {
	CONNMAN_SERVICE_ERROR_UNKNOWN        = 0,
	CONNMAN_SERVICE_ERROR_OUT_OF_RANGE   = 1,
	CONNMAN_SERVICE_ERROR_PIN_MISSING    = 2,
	CONNMAN_SERVICE_ERROR_DHCP_FAILED    = 3,
	CONNMAN_SERVICE_ERROR_CONNECT_FAILED = 4,
};

enum connman_service_proxy_method {
	CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN     = 0,
	CONNMAN_SERVICE_PROXY_METHOD_DIRECT      = 1,
	CONNMAN_SERVICE_PROXY_METHOD_MANUAL      = 2,
	CONNMAN_SERVICE_PROXY_METHOD_AUTO        = 3,
};

struct connman_service;

struct connman_service *connman_service_create(void);
struct connman_service *connman_service_ref(struct connman_service *service);
void connman_service_unref(struct connman_service *service);

enum connman_service_type connman_service_get_type(struct connman_service *service);
char *connman_service_get_interface(struct connman_service *service);

const char *connman_service_get_domainname(struct connman_service *service);
const char *connman_service_get_nameserver(struct connman_service *service);
enum connman_service_proxy_method connman_service_get_proxy_method(struct connman_service *service);
char **connman_service_get_proxy_servers(struct connman_service *service);
char **connman_service_get_proxy_excludes(struct connman_service *service);
const char *connman_service_get_proxy_url(struct connman_service *service);
const char *connman_service_get_proxy_autoconfig(struct connman_service *service);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_SERVICE_H */
