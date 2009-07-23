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
	CONNMAN_SERVICE_TYPE_ETHERNET  = 1,
	CONNMAN_SERVICE_TYPE_WIFI      = 2,
	CONNMAN_SERVICE_TYPE_WIMAX     = 3,
	CONNMAN_SERVICE_TYPE_BLUETOOTH = 4,
	CONNMAN_SERVICE_TYPE_CELLULAR  = 5,
};

enum connman_service_mode {
	CONNMAN_SERVICE_MODE_UNKNOWN = 0,
	CONNMAN_SERVICE_MODE_MANAGED = 1,
	CONNMAN_SERVICE_MODE_ADHOC   = 2,
};

enum connman_service_security {
	CONNMAN_SERVICE_SECURITY_UNKNOWN = 0,
	CONNMAN_SERVICE_SECURITY_NONE    = 1,
	CONNMAN_SERVICE_SECURITY_WEP     = 2,
	CONNMAN_SERVICE_SECURITY_WPA     = 3,
	CONNMAN_SERVICE_SECURITY_RSN     = 4,
};

enum connman_service_state {
	CONNMAN_SERVICE_STATE_UNKNOWN       = 0,
	CONNMAN_SERVICE_STATE_IDLE          = 1,
	CONNMAN_SERVICE_STATE_CARRIER       = 2,
	CONNMAN_SERVICE_STATE_ASSOCIATION   = 3,
	CONNMAN_SERVICE_STATE_CONFIGURATION = 4,
	CONNMAN_SERVICE_STATE_READY         = 5,
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

struct connman_service;

struct connman_service *connman_service_create(void);
struct connman_service *connman_service_ref(struct connman_service *service);
void connman_service_unref(struct connman_service *service);

int connman_service_set_favorite(struct connman_service *service,
						connman_bool_t favorite);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_SERVICE_H */
