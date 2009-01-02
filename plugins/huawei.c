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

static int huawei_probe(struct connman_device *device)
{
	DBG("device %p", device);

	return 0;
}

static void huawei_remove(struct connman_device *device)
{
	DBG("device %p", device);
}

static int huawei_enable(struct connman_device *device)
{
	DBG("device %p", device);

	connman_device_set_powered(device, TRUE);

	return 0;
}

static int huawei_disable(struct connman_device *device)
{
	DBG("device %p", device);

	connman_device_set_powered(device, FALSE);

	return 0;
}

static struct connman_device_driver huawei_driver = {
	.name		= "huawei-device",
	.type		= CONNMAN_DEVICE_TYPE_HUAWEI,
	.probe		= huawei_probe,
	.remove		= huawei_remove,
	.enable		= huawei_enable,
	.disable	= huawei_disable,
};

static int huawei_init(void)
{
	return connman_device_driver_register(&huawei_driver);
}

static void huawei_exit(void)
{
	connman_device_driver_unregister(&huawei_driver);
}

CONNMAN_PLUGIN_DEFINE(huawei, "Option HUAWEI device plugin", VERSION,
						huawei_init, huawei_exit)
