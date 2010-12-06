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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/device.h>
#include <connman/log.h>

static void create_network(struct connman_device *device, const char *name)
{
	struct connman_network *network;

	network = connman_network_create(name, CONNMAN_NETWORK_TYPE_VENDOR);
	if (network == NULL)
		return;

	connman_device_add_network(device, network);
	connman_network_unref(network);
}

static int device_probe(struct connman_device *device)
{
	DBG("");

	return 0;
}

static void device_remove(struct connman_device *device)
{
	DBG("");
}

static int device_enable(struct connman_device *device)
{
	DBG("");

	create_network(device, "network_one");
	create_network(device, "network_two");

	return 0;
}

static int device_disable(struct connman_device *device)
{
	DBG("");

	return 0;
}

static struct connman_device_driver device_driver = {
	.name		= "fake",
	.type		= CONNMAN_DEVICE_TYPE_VENDOR,
	.probe		= device_probe,
	.remove		= device_remove,
	.enable		= device_enable,
	.disable	= device_disable,
};

static void create_device(const char *name)
{
	struct connman_device *device;

	device = connman_device_create(name, CONNMAN_DEVICE_TYPE_VENDOR);
	if (device == NULL)
		return;

	connman_device_register(device);
	connman_device_unref(device);
}

static int fake_init(void)
{
	create_device("fake");

	return connman_device_driver_register(&device_driver);
}

static void fake_exit(void)
{
	connman_device_driver_unregister(&device_driver);
}

CONNMAN_PLUGIN_DEFINE(fake, "Tesing plugin", VERSION,
		CONNMAN_PLUGIN_PRIORITY_DEFAULT, fake_init, fake_exit)
