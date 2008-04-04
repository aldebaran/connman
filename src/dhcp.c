/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007  Intel Corporation. All rights reserved.
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

#include <arpa/inet.h>

#include <glib.h>

#include "connman.h"

static GSList *drivers = NULL;

int connman_dhcp_register(struct connman_dhcp_driver *driver)
{
	DBG("driver %p", driver);

	drivers = g_slist_append(drivers, driver);

	return 0;
}

void connman_dhcp_unregister(struct connman_dhcp_driver *driver)
{
	DBG("driver %p", driver);

	drivers = g_slist_remove(drivers, driver);
}

int connman_dhcp_update(struct connman_iface *iface,
				enum connman_dhcp_state state,
					struct connman_ipv4 *ipv4)
{
	DBG("iface %p state %d", iface, state);

	if (state == CONNMAN_DHCP_STATE_BOUND) {
		DBG("address %s", inet_ntoa(ipv4->address));
		DBG("netmask %s", inet_ntoa(ipv4->netmask));
		DBG("gateway %s", inet_ntoa(ipv4->gateway));
		DBG("network %s", inet_ntoa(ipv4->network));
		DBG("broadcast %s", inet_ntoa(ipv4->broadcast));
		DBG("nameserver %s", inet_ntoa(ipv4->nameserver));

		ipv4->method = CONNMAN_IPV4_METHOD_DHCP;

		connman_iface_set_ipv4(iface, ipv4);
		iface->ipv4 = *ipv4;

		connman_iface_indicate_configured(iface);
	}

	return 0;
}

int __connman_dhcp_request(struct connman_iface *iface)
{
	struct connman_dhcp_driver *driver = g_slist_nth_data(drivers, 0);

	if (iface->flags & CONNMAN_IFACE_FLAG_DHCP)
		return -1;

	if (driver && driver->request) {
		iface->flags |= CONNMAN_IFACE_FLAG_DHCP;
		return driver->request(iface);
	}

	return -1;
}

int __connman_dhcp_release(struct connman_iface *iface)
{
	struct connman_dhcp_driver *driver = g_slist_nth_data(drivers, 0);

	if (!(iface->flags & CONNMAN_IFACE_FLAG_DHCP))
		return -1;

	if (driver && driver->release) {
		iface->flags &= ~CONNMAN_IFACE_FLAG_DHCP;
		return driver->release(iface);
	}

	return -1;
}
