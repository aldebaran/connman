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

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/device.h>
#include <connman/log.h>

static int hso_probe(struct connman_device *device)
{
	DBG("device %p", device);

	return 0;
}

static void hso_remove(struct connman_device *device)
{
	DBG("device %p", device);
}

static struct connman_device_driver hso_driver = {
	.name		= "hso",
	.type		= CONNMAN_DEVICE_TYPE_HSO,
	.probe		= hso_probe,
	.remove		= hso_remove,
};

static int hso_init(void)
{
	return connman_device_driver_register(&hso_driver);
}

static void hso_exit(void)
{
	connman_device_driver_unregister(&hso_driver);
}

CONNMAN_PLUGIN_DEFINE(hso, "Option HSO device plugin", VERSION,
						hso_init, hso_exit)
