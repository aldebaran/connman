/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007  Intel Corporation. All rights reserved.
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

#include <stdio.h>

#define DBG(fmt, arg...)  printf("%s: " fmt "\n" , __FUNCTION__ , ## arg)
//#define DBG(fmt, arg...)

#include <dbus/dbus.h>

#define CONNMAN_SERVICE  "org.freedesktop.connman"

#define CONNMAN_MANAGER_PATH "/"
#define CONNMAN_MANAGER_INTERFACE  CONNMAN_SERVICE ".Manager"

#define CONNMAN_IFACE_BASEPATH  "/interface"
#define CONNMAN_IFACE_INTERFACE  CONNMAN_SERVICE ".Interface"

int __connman_manager_init(DBusConnection *conn);
void __connman_manager_cleanup(void);

#include <connman/plugin.h>

int __connman_plugin_init(void);
void __connman_plugin_cleanup(void);

#include <connman/iface.h>

int __connman_iface_init(DBusConnection *conn);
void __connman_iface_cleanup(void);

#include <connman/rtnl.h>

int __connman_rtnl_init(void);
void __connman_rtnl_cleanup(void);

#include <connman/dhcp.h>

int __connman_dhcp_request(struct connman_iface *iface);
int __connman_dhcp_release(struct connman_iface *iface);
