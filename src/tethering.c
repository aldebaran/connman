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

#define BRIDGE_NAME "tether"

static connman_bool_t tethering_status = FALSE;
static const char *default_interface = NULL;
static volatile gint tethering_enabled;

connman_bool_t __connman_tethering_get_status(void)
{
	return tethering_status;
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

static int enable_ip_forward(connman_bool_t enable)
{

	FILE *f;
	int ip_forward = enable ? 1 : 0;

	f = fopen("/proc/sys/net/ipv4/ip_forward", "r+");

	fprintf(f, "%d", ip_forward);

	fclose(f);

	return 0;
}

static int enable_nat(const char *interface)
{
	int ret;

	if (interface == NULL)
		return 0;

	/* Enable IPv4 forwarding */
	ret = enable_ip_forward(TRUE);
	if (ret < 0)
		return ret;

	/* TODO: Flush nat POSTROUTING chain */
	/* Enable masquerading */
	ret = __connman_iptables_command("-t nat -A POSTROUTING -o %s -j MASQUERADE", interface);
	if (ret < 0)
		return ret;

	return __connman_iptables_commit("nat");
}

static void disable_nat(const char *interface)
{
	/* Disable IPv4 forwarding */
	enable_ip_forward(FALSE);

	/* TODO: Flush nat POSTROUTING chain */
}

void __connman_tethering_set_enabled(void)
{
	if (tethering_status == FALSE)
		return;

	DBG("enabled %d", tethering_enabled + 1);

	if (g_atomic_int_exchange_and_add(&tethering_enabled, 1) == 0) {
		/* TODO Start DHCP server and DNS proxy on the bridge */

		enable_nat(default_interface);
		DBG("tethering started");
	}
}

void __connman_tethering_set_disabled(void)
{
	if (tethering_status == FALSE)
		return;

	DBG("enabled %d", tethering_enabled - 1);

	if (g_atomic_int_dec_and_test(&tethering_enabled) == 0) {
		/* TODO Stop DHCP server and DNS proxy on the bridge */

		disable_nat(default_interface);
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

	if (tethering_status == TRUE)
		remove_bridge(BRIDGE_NAME);
}
