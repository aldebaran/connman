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

#include <errno.h>

#include "connman.h"

static GSList *driver_list = NULL;

static gboolean match_driver(struct connman_device *device,
					struct connman_device_driver *driver)
{
	if (device->element->subtype == driver->type ||
			driver->type == CONNMAN_DEVICE_TYPE_UNKNOWN)
		return TRUE;

	return FALSE;
}

static int device_probe(struct connman_element *element)
{
	struct connman_device *device;
	GSList *list;

	DBG("element %p name %s", element, element->name);

	device = g_try_new0(struct connman_device, 1);
	if (device == NULL)
		return -ENOMEM;

	device->element = element;

	for (list = driver_list; list; list = list->next) {
		struct connman_device_driver *driver = list->data;

		if (match_driver(device, driver) == FALSE)
			continue;

		DBG("driver %p name %s", driver, driver->name);

		if (driver->probe(device) == 0) {
			device->driver = driver;
			connman_element_set_data(element, device);
			return 0;
		}
	}

	g_free(device);

	return -ENODEV;
}

static void device_remove(struct connman_element *element)
{
	struct connman_device *device = connman_element_get_data(element);

	DBG("element %p name %s", element, element->name);

	if (device->driver && device->driver->remove)
		device->driver->remove(device);

	connman_element_set_data(element, NULL);

	g_free(device);
}

static struct connman_driver device_driver = {
	.name		= "device",
	.type		= CONNMAN_ELEMENT_TYPE_DEVICE,
	.priority	= CONNMAN_DRIVER_PRIORITY_LOW,
	.probe		= device_probe,
	.remove		= device_remove,
};

int __connman_device_init(void)
{
	DBG("");

	return connman_driver_register(&device_driver);
}

void __connman_device_cleanup(void)
{
	DBG("");

	connman_driver_unregister(&device_driver);
}

static gint compare_priority(gconstpointer a, gconstpointer b)
{
	const struct connman_device_driver *driver1 = a;
	const struct connman_device_driver *driver2 = b;

	return driver2->priority - driver1->priority;
}

/**
 * connman_device_driver_register:
 * @driver: device driver definition
 *
 * Register a new device driver
 *
 * Returns: %0 on success
 */
int connman_device_driver_register(struct connman_device_driver *driver)
{
	DBG("driver %p name %s", driver, driver->name);

	driver_list = g_slist_insert_sorted(driver_list, driver,
							compare_priority);

	//__connman_driver_rescan(&device_driver);

	return 0;
}

/**
 * connman_device_driver_unregister:
 * @driver: device driver definition
 *
 * Remove a previously registered device driver
 */
void connman_device_driver_unregister(struct connman_device_driver *driver)
{
	DBG("driver %p name %s", driver, driver->name);

	driver_list = g_slist_remove(driver_list, driver);
}
