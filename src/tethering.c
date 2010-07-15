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
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/sockios.h>

#include "connman.h"

#define BRIDGE_NAME "tether"

static connman_bool_t tethering_status = FALSE;

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

int __connman_tethering_set_status(connman_bool_t status)
{
	if (status == tethering_status)
		return -EALREADY;

	if (status == TRUE) {
		create_bridge(BRIDGE_NAME);
		__connman_technology_enable_tethering();
	} else {
		__connman_technology_disable_tethering();
		remove_bridge(BRIDGE_NAME);
	}

	tethering_status = status;

	return 0;
}

void __connman_tethering_update_interface(const char *interface)
{
	DBG("interface %s", interface);
}

int __connman_tethering_init(void)
{
	DBG("");

	return 0;
}

void __connman_tethering_cleanup(void)
{
	DBG("");

	if (tethering_status == TRUE)
		remove_bridge(BRIDGE_NAME);
}
