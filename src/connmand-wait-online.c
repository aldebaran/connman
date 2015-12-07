/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2015  Intel Corporation. All rights reserved.
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
#include <glib.h>
#include <errno.h>

#include <gdbus.h>

static DBusConnection *connection;
static GMainLoop *main_loop;

int main(int argc, char *argv[])
{
	int err = 0;
	DBusError dbus_err;

	dbus_error_init(&dbus_err);
	connection = g_dbus_setup_bus(DBUS_BUS_SYSTEM, NULL, &dbus_err);

	if (dbus_error_is_set(&dbus_err)) {
		fprintf(stderr, "Error: %s\n", dbus_err.message);

		err = -ENOPROTOOPT;
		goto fail;
	}

	main_loop = g_main_loop_new(NULL, FALSE);

	g_main_loop_run(main_loop);

	dbus_connection_unref(connection);
	g_main_loop_unref(main_loop);

fail:
	dbus_error_free(&dbus_err);

	return -err;
}
