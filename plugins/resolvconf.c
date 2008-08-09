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

#include <unistd.h>
#include <stdlib.h>

#include <connman/plugin.h>
#include <connman/driver.h>
#include <connman/log.h>

#define RESOLVCONF "/sbin/resolvconf"

static int resolvconf_probe(struct connman_element *element)
{
	const char *nameserver = NULL;
	struct connman_element *internet;
	gchar *cmd;
	int err;

	DBG("element %p name %s", element, element->name);

	if (access(RESOLVCONF, X_OK) < 0)
		return -errno;

	connman_element_get_value(element,
			CONNMAN_PROPERTY_TYPE_IPV4_NAMESERVER, &nameserver);

	if (nameserver == NULL)
		return -EINVAL;

	cmd = g_strdup_printf("echo \"nameserver %s\" | %s -a %s",
						RESOLVCONF, nameserver,
							element->netdev.name);

	DBG("%s", cmd);

	err = system(cmd);

	g_free(cmd);

	internet = connman_element_create();

	internet->type = CONNMAN_ELEMENT_TYPE_INTERNET;

	connman_element_set_data(element, internet);

	connman_element_register(internet, element);

	return 0;
}

static void resolvconf_remove(struct connman_element *element)
{
	struct connman_element *internet = connman_element_get_data(element);
	gchar *cmd;
	int err;

	DBG("element %p name %s", element, element->name);

	connman_element_set_data(element, NULL);

	connman_element_unregister(internet);

	connman_element_unref(internet);

	cmd = g_strdup_printf("%s -d %s", RESOLVCONF, element->netdev.name);

	DBG("%s", cmd);

	err = system(cmd);

	g_free(cmd);
}

static struct connman_driver resolvconf_driver = {
	.name		= "resolvconf",
	.type		= CONNMAN_ELEMENT_TYPE_RESOLVER,
	.priority	= CONNMAN_DRIVER_PRIORITY_HIGH,
	.probe		= resolvconf_probe,
	.remove		= resolvconf_remove,
};

static int resolvconf_init(void)
{
	return connman_driver_register(&resolvconf_driver);
}

static void resolvconf_exit(void)
{
	connman_driver_unregister(&resolvconf_driver);
}

CONNMAN_PLUGIN_DEFINE("resolvconf", "Name resolver plugin", VERSION,
					resolvconf_init, resolvconf_exit)
