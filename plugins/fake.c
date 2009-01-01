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

#include <connman/plugin.h>
#include <connman/driver.h>
#include <connman/element.h>
#include <connman/log.h>

static void create_network(struct connman_element *parent, const char *name)
{
	struct connman_element *element;

	element = connman_element_create(name);
	element->type = CONNMAN_ELEMENT_TYPE_NETWORK;
	element->subtype = CONNMAN_ELEMENT_SUBTYPE_FAKE;

	connman_element_register(element, parent);
	connman_element_unref(element);
}

static int fake_device_probe(struct connman_element *element)
{
	DBG("");

	return 0;
}

static void fake_device_remove(struct connman_element *element)
{
	DBG("");
}

static int fake_device_update(struct connman_element *element)
{
	DBG("");

	create_network(element, "network_new");

	return 0;
}

static int fake_device_enable(struct connman_element *element)
{
	DBG("");

	create_network(element, "network_one");
	create_network(element, "network_two");

	return 0;
}

static int fake_device_disable(struct connman_element *element)
{
	DBG("");

	connman_element_unregister_children(element);

	return 0;
}

static struct connman_driver fake_device_driver = {
	.name		= "fake-device",
	.type		= CONNMAN_ELEMENT_TYPE_DEVICE,
	.subtype	= CONNMAN_ELEMENT_SUBTYPE_FAKE,
	.probe		= fake_device_probe,
	.remove		= fake_device_remove,
	.update		= fake_device_update,
	.enable		= fake_device_enable,
	.disable	= fake_device_disable,
};

static void create_device(const char *name)
{
	struct connman_element *element;

	element = connman_element_create(name);
	element->type = CONNMAN_ELEMENT_TYPE_DEVICE;
	element->subtype = CONNMAN_ELEMENT_SUBTYPE_FAKE;

	//connman_element_define_properties(element,
	//				CONNMAN_PROPERTY_ID_IPV4_METHOD,
	//				CONNMAN_PROPERTY_ID_INVALID);

	connman_element_register(element, NULL);
	connman_element_unref(element);
}

static int fake_init(void)
{
	create_device("fakeone");
	create_device("faketwo");

	return connman_driver_register(&fake_device_driver);
}

static void fake_exit(void)
{
	connman_driver_unregister(&fake_device_driver);
}

CONNMAN_PLUGIN_DEFINE(fake, "Tesing plugin", VERSION, fake_init, fake_exit)
