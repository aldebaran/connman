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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dbus/dbus.h>

#define UDHCPC_INTF  "net.busybox.udhcpc"
#define UDHCPC_PATH  "/net/busybox/udhcpc"

int main(int argc, char *argv[])
{
	DBusConnection *conn;
	DBusError error;
	DBusMessage *msg;
	char *busname, *interface, *address, *netmask, *broadcast;
	char *gateway, *dns;

	if (argc < 2)
		return 0;

	if (strcmp(argv[1], "bound") != 0 && strcmp(argv[1], "renew") != 0)
		return 0;

	busname = "org.moblin.connman";

	interface = getenv("interface");

	address = getenv("ip");
	if (address == NULL)
		address = "";

	netmask = getenv("subnet");
	if (netmask == NULL)
		netmask = "";

	broadcast = getenv("broadcast");
	if (broadcast == NULL)
		broadcast = "";

	gateway = getenv("router");
	if (gateway == NULL)
		gateway = "";

	dns = getenv("dns");
	if (dns == NULL)
		dns = "";

	dbus_error_init(&error);

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
	if (conn == NULL) {
		if (dbus_error_is_set(&error) == TRUE) {
			fprintf(stderr, "%s\n", error.message);
			dbus_error_free(&error);
		} else
			fprintf(stderr, "Failed to get on system bus\n");
		return 0;
	}

	msg = dbus_message_new_method_call(busname, UDHCPC_PATH,
						UDHCPC_INTF, argv[1]);
	if (msg == NULL) {
		dbus_connection_unref(conn);
		fprintf(stderr, "Failed to allocate method call\n");
		return 0;
	}

	dbus_message_set_no_reply(msg, TRUE);

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &interface,
					DBUS_TYPE_STRING, &address,
					DBUS_TYPE_STRING, &netmask,
					DBUS_TYPE_STRING, &broadcast,
					DBUS_TYPE_STRING, &gateway,
					DBUS_TYPE_STRING, &dns,
							DBUS_TYPE_INVALID);

	if (dbus_connection_send(conn, msg, NULL) == FALSE)
		fprintf(stderr, "Failed to send message\n");

	dbus_connection_flush(conn);

	dbus_message_unref(msg);

	dbus_connection_unref(conn);

	return 0;
}
