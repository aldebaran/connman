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

#include <connman/plugin.h>
#include <connman/driver.h>
#include <connman/log.h>

#include "supplicant.h"

static void scan_result(struct connman_element *element,
					struct supplicant_network *network)
{
	DBG("element %p name %s", element, element->name);

	DBG("network %p identifier %s", network, network->identifier);
}

static struct supplicant_callback wifi_callback = {
	.scan_result	= scan_result,
};

static int wifi_probe(struct connman_element *element)
{
	int err;

	DBG("element %p name %s", element, element->name);

	err = __supplicant_start(element, &wifi_callback);
	if (err < 0)
		return err;

	__supplicant_scan(element);

	return 0;
}

static void wifi_remove(struct connman_element *element)
{
	DBG("element %p name %s", element, element->name);

	__supplicant_stop(element);
}

static struct connman_driver wifi_driver = {
	.name		= "wifi",
	.type		= CONNMAN_ELEMENT_TYPE_DEVICE,
	.subtype	= CONNMAN_ELEMENT_SUBTYPE_WIFI,
	.probe		= wifi_probe,
	.remove		= wifi_remove,
};

static int wifi_init(void)
{
	return connman_driver_register(&wifi_driver);
}

static void wifi_exit(void)
{
	connman_driver_unregister(&wifi_driver);
}

CONNMAN_PLUGIN_DEFINE("WiFi", "WiFi interface plugin", VERSION,
							wifi_init, wifi_exit)
