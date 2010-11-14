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

#include <unistd.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/sockios.h>

#include "connman.h"

#include <gdhcp/gdhcp.h>

#define BRIDGE_NAME "tether"
#define BRIDGE_IP "192.168.218.1"
#define BRIDGE_BCAST "192.168.218.255"
#define BRIDGE_SUBNET "255.255.255.0"
#define BRIDGE_IP_START "192.168.218.100"
#define BRIDGE_IP_END "192.168.218.200"
#define BRIDGE_DNS "8.8.8.8"

static connman_bool_t tethering_status = FALSE;
static const char *default_interface = NULL;
static volatile gint tethering_enabled;
static GDHCPServer *tethering_dhcp_server = NULL;

connman_bool_t __connman_tethering_get_status(void)
{
	return tethering_status;
}


static void dhcp_server_debug(const char *str, void *data)
{
	connman_info("%s: %s\n", (const char *) data, str);
}

static void dhcp_server_error(GDHCPServerError error)
{
	switch (error) {
	case G_DHCP_SERVER_ERROR_NONE:
		connman_error("OK");
		break;
	case G_DHCP_SERVER_ERROR_INTERFACE_UNAVAILABLE:
		connman_error("Interface unavailable");
		break;
	case G_DHCP_SERVER_ERROR_INTERFACE_IN_USE:
		connman_error("Interface in use");
		break;
	case G_DHCP_SERVER_ERROR_INTERFACE_DOWN:
		connman_error("Interface down");
		break;
	case G_DHCP_SERVER_ERROR_NOMEM:
		connman_error("No memory");
		break;
	case G_DHCP_SERVER_ERROR_INVALID_INDEX:
		connman_error("Invalid index");
		break;
	case G_DHCP_SERVER_ERROR_INVALID_OPTION:
		connman_error("Invalid option");
		break;
	case G_DHCP_SERVER_ERROR_IP_ADDRESS_INVALID:
		connman_error("Invalid address");
		break;
	}
}

static GDHCPServer *dhcp_server_start(const char *bridge,
				const char *router, const char* subnet,
				const char *start_ip, const char *end_ip,
				unsigned int lease_time, const char *dns)
{
	GDHCPServerError error;
	GDHCPServer *dhcp_server;
	int index;

	DBG("");

	index = connman_inet_ifindex(bridge);
	if (index < 0)
		return NULL;

	dhcp_server = g_dhcp_server_new(G_DHCP_IPV4, index, &error);
	if (dhcp_server == NULL) {
		dhcp_server_error(error);
		return NULL;
	}

	g_dhcp_server_set_debug(dhcp_server, dhcp_server_debug, "DHCP server");

	g_dhcp_server_set_lease_time(dhcp_server, lease_time);
	g_dhcp_server_set_option(dhcp_server, G_DHCP_SUBNET, subnet);
	g_dhcp_server_set_option(dhcp_server, G_DHCP_ROUTER, router);
	g_dhcp_server_set_option(dhcp_server, G_DHCP_DNS_SERVER, dns);
	g_dhcp_server_set_ip_range(dhcp_server, start_ip, end_ip);

	g_dhcp_server_start(dhcp_server);

	return dhcp_server;
}

static void dhcp_server_stop(GDHCPServer *server)
{
	if (server == NULL)
		return;

	g_dhcp_server_unref(server);
}

static int create_bridge(const char *name)
{
	int sk, err;

	DBG("name %s", name);

	sk = socket(AF_INET, SOCK_STREAM, 0);
	if (sk < 0)
		return -EOPNOTSUPP;

	err = ioctl(sk, SIOCBRADDBR, name);

	close(sk);

	if (err < 0)
		return -EOPNOTSUPP;

	return 0;
}

static int remove_bridge(const char *name)
{
	int sk, err;

	DBG("name %s", name);

	sk = socket(AF_INET, SOCK_STREAM, 0);
	if (sk < 0)
		return -EOPNOTSUPP;

	err = ioctl(sk, SIOCBRDELBR, name);

	close(sk);

	if (err < 0)
		return -EOPNOTSUPP;

	return 0;
}

static int enable_bridge(const char *name)
{
	int err, index;

	index = connman_inet_ifindex(name);
	if (index < 0)
		return index;

	err = __connman_inet_modify_address(RTM_NEWADDR,
			NLM_F_REPLACE | NLM_F_ACK, index, AF_INET,
					    BRIDGE_IP, NULL, 24, BRIDGE_BCAST);
	if (err < 0)
		return err;

	return connman_inet_ifup(index);
}

static int disable_bridge(const char *name)
{
	int index;

	index = connman_inet_ifindex(name);
	if (index < 0)
		return index;

	return connman_inet_ifdown(index);
}

static int enable_ip_forward(connman_bool_t enable)
{

	FILE *f;

	f = fopen("/proc/sys/net/ipv4/ip_forward", "r+");
	if (f == NULL)
		return -errno;

	if (enable == TRUE)
		fprintf(f, "1");
	else
		fprintf(f, "0");

	fclose(f);

	return 0;
}

static int enable_nat(const char *interface)
{
	int err;

	if (interface == NULL)
		return 0;

	/* Enable IPv4 forwarding */
	err = enable_ip_forward(TRUE);
	if (err < 0)
		return err;

	/* POSTROUTING flush */
	err = __connman_iptables_command("-t nat -F POSTROUTING");
	if (err < 0)
		return err;

	/* Enable masquerading */
	err = __connman_iptables_command("-t nat -A POSTROUTING "
					"-o %s -j MASQUERADE", interface);
	if (err < 0)
		return err;

	return __connman_iptables_commit("nat");
}

static void disable_nat(const char *interface)
{
	int err;

	/* Disable IPv4 forwarding */
	enable_ip_forward(FALSE);

	/* POSTROUTING flush */
	err = __connman_iptables_command("-t nat -F POSTROUTING");
	if (err < 0)
		return;

	__connman_iptables_commit("nat");
}

void __connman_tethering_set_enabled(void)
{
	int err;

	if (tethering_status == FALSE)
		return;

	DBG("enabled %d", tethering_enabled + 1);

	if (g_atomic_int_exchange_and_add(&tethering_enabled, 1) == 0) {
		err = enable_bridge(BRIDGE_NAME);
		if (err < 0)
			return;

		tethering_dhcp_server =
			dhcp_server_start(BRIDGE_NAME,
						BRIDGE_IP, BRIDGE_SUBNET,
						BRIDGE_IP_START, BRIDGE_IP_END,
							24 * 3600, BRIDGE_DNS);
		if (tethering_dhcp_server == NULL) {
			disable_bridge(BRIDGE_NAME);
			return;
		}

		enable_nat(default_interface);

		DBG("tethering started");
	}
}

void __connman_tethering_set_disabled(void)
{
	if (tethering_status == TRUE)
		return;

	DBG("enabled %d", tethering_enabled - 1);

	if (g_atomic_int_dec_and_test(&tethering_enabled) == 0) {
		disable_nat(default_interface);

		dhcp_server_stop(tethering_dhcp_server);

		disable_bridge(BRIDGE_NAME);

		DBG("tethering stopped");
	}
}

int __connman_tethering_set_status(connman_bool_t status)
{
	if (status == tethering_status)
		return -EALREADY;

	if (status == TRUE) {
		create_bridge(BRIDGE_NAME);
		__connman_technology_enable_tethering(BRIDGE_NAME);
	} else {
		__connman_technology_disable_tethering(BRIDGE_NAME);
		remove_bridge(BRIDGE_NAME);
	}

	tethering_status = status;

	return 0;
}

void __connman_tethering_update_interface(const char *interface)
{
	DBG("interface %s", interface);

	default_interface = interface;

	if (interface == NULL) {
		disable_nat(interface);

		return;
	}

	if (tethering_status == FALSE ||
			!g_atomic_int_get(&tethering_enabled))
		return;

	enable_nat(interface);
}

int __connman_tethering_init(void)
{
	DBG("");

	tethering_enabled = 0;

	return 0;
}

void __connman_tethering_cleanup(void)
{
	DBG("");

	if (tethering_status == TRUE) {
		if (tethering_dhcp_server)
			dhcp_server_stop(tethering_dhcp_server);
		disable_bridge(BRIDGE_NAME);
		remove_bridge(BRIDGE_NAME);
	}
}
