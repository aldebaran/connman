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

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/dhcp.h>
#include <connman/log.h>

static int dhcp_request(struct connman_dhcp *dhcp)
{
	DBG("dhcp %p", dhcp);

	return -1;
}

static int dhcp_release(struct connman_dhcp *dhcp)
{
	DBG("dhcp %p", dhcp);

	return -1;
}

static struct connman_dhcp_driver dhcp_driver = {
	.name		= "dhcp",
	.priority	= CONNMAN_DHCP_PRIORITY_LOW,
	.request	= dhcp_request,
	.release	= dhcp_release,
};

static int dhcp_init(void)
{
	return connman_dhcp_driver_register(&dhcp_driver);
}

static void dhcp_exit(void)
{
	connman_dhcp_driver_unregister(&dhcp_driver);
}

CONNMAN_PLUGIN_DEFINE(dhcp, "Generic DHCP plugin", VERSION,
			CONNMAN_PLUGIN_PRIORITY_LOW, dhcp_init, dhcp_exit)
