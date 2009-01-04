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

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/device.h>
#include <connman/log.h>

#include "modem.h"

static int novatel_probe(struct connman_device *device)
{
	DBG("device %p", device);

	return 0;
}

static void novatel_remove(struct connman_device *device)
{
	DBG("device %p", device);
}

static int novatel_enable(struct connman_device *device)
{
	DBG("device %p", device);

	connman_device_set_powered(device, TRUE);

	return 0;
}

static int novatel_disable(struct connman_device *device)
{
	DBG("device %p", device);

	connman_device_set_powered(device, FALSE);

	return 0;
}

static struct connman_device_driver novatel_driver = {
	.name		= "novatel",
	.type		= CONNMAN_DEVICE_TYPE_NOVATEL,
	.probe		= novatel_probe,
	.remove		= novatel_remove,
	.enable		= novatel_enable,
	.disable	= novatel_disable,
};

static int novatel_init(void)
{
	return connman_device_driver_register(&novatel_driver);
}

static void novatel_exit(void)
{
	connman_device_driver_unregister(&novatel_driver);
}

CONNMAN_PLUGIN_DEFINE(novatel, "Novatel Wireless device plugin", VERSION,
						novatel_init, novatel_exit)
