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

#include "connman.h"

static int connection_probe(struct connman_element *element)
{
	DBG("element %p name %s", element, element->name);

	return 0;
}

static void connection_remove(struct connman_element *element)
{
	DBG("element %p name %s", element, element->name);
}

static struct connman_driver connection_driver = {
	.name		= "connection",
	.type		= CONNMAN_ELEMENT_TYPE_CONNECTION,
	.priority	= CONNMAN_DRIVER_PRIORITY_LOW,
	.probe		= connection_probe,
	.remove		= connection_remove,
};

static DBusConnection *connection;

int __connman_connection_init(void)
{
	DBG("");

	connection = connman_dbus_get_connection();

	return connman_driver_register(&connection_driver);
}

void __connman_connection_cleanup(void)
{
	DBG("");

	connman_driver_unregister(&connection_driver);

	dbus_connection_unref(connection);
}
