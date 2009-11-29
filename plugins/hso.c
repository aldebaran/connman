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
#include <errno.h>
#include <string.h>

#include <glib.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/device.h>
#include <connman/log.h>

struct hso_data {
	int index;
};

static int hso_probe(struct connman_device *device)
{
	struct hso_data *data;

	DBG("device %p", device);

	data = g_try_new0(struct hso_data, 1);
	if (data == NULL)
		return -ENOMEM;

	data->index = connman_device_get_index(device);

	connman_device_set_data(device, data);

	return 0;
}

static void hso_remove(struct connman_device *device)
{
	struct hso_data *data = connman_device_get_data(device);

	DBG("device %p", device);

	connman_device_set_data(device, NULL);

	g_free(data);
}

static int hso_enable(struct connman_device *device)
{
	DBG("device %p", device);

	connman_device_set_powered(device, TRUE);

	return 0;
}

static int hso_disable(struct connman_device *device)
{
	DBG("device %p", device);

	connman_device_set_powered(device, FALSE);

	return 0;
}

static struct connman_device_driver hso_driver = {
	.name		= "hso",
	.type		= CONNMAN_DEVICE_TYPE_HSO,
	.probe		= hso_probe,
	.remove		= hso_remove,
	.enable		= hso_enable,
	.disable	= hso_disable,
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
		CONNMAN_PLUGIN_PRIORITY_DEFAULT, hso_init, hso_exit)
