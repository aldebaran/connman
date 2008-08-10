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

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

#include <connman/plugin.h>
#include <connman/driver.h>
#include <connman/log.h>

static int resolvfile_probe(struct connman_element *element)
{
	const char *nameserver = NULL;
	struct connman_element *internet;
	gchar *cmd;
	int fd, len, err;

	DBG("element %p name %s", element, element->name);

	connman_element_get_value(element,
			CONNMAN_PROPERTY_TYPE_IPV4_NAMESERVER, &nameserver);

	if (nameserver == NULL)
		return -EINVAL;

	fd = open("/etc/resolv.conf", O_RDWR | O_CREAT,
					S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fd < 0)
		return errno;

	err = ftruncate(fd, 0);

	cmd = g_strdup_printf("nameserver %s\n", nameserver);

	len = write(fd, cmd, strlen(cmd));

	g_free(cmd);

	close(fd);

	internet = connman_element_create();

	internet->type = CONNMAN_ELEMENT_TYPE_INTERNET;

	connman_element_register(internet, element);

	return 0;
}

static void resolvfile_remove(struct connman_element *element)
{
	DBG("element %p name %s", element, element->name);
}

static struct connman_driver resolvfile_driver = {
	.name		= "resolvconf",
	.type		= CONNMAN_ELEMENT_TYPE_RESOLVER,
	.priority	= CONNMAN_DRIVER_PRIORITY_LOW,
	.probe		= resolvfile_probe,
	.remove		= resolvfile_remove,
};

static int resolvfile_init(void)
{
	return connman_driver_register(&resolvfile_driver);
}

static void resolvfile_exit(void)
{
	connman_driver_unregister(&resolvfile_driver);
}

CONNMAN_PLUGIN_DEFINE("resolvfile", "Name resolver plugin", VERSION,
					resolvfile_init, resolvfile_exit)
