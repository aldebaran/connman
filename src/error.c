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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <gdbus.h>

#include "connman.h"

DBusMessage *__connman_error_failed(DBusMessage *msg)
{
	return g_dbus_create_error(msg, CONNMAN_ERROR_INTERFACE
							".Failed", NULL);
}

DBusMessage *__connman_error_invalid_arguments(DBusMessage *msg)
{
	return g_dbus_create_error(msg, CONNMAN_ERROR_INTERFACE
						".InvalidArguments", NULL);
}

DBusMessage *__connman_error_permission_denied(DBusMessage *msg)
{
	return g_dbus_create_error(msg, CONNMAN_ERROR_INTERFACE
						".PermissionDenied", NULL);
}
