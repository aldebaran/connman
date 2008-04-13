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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>

#include <connman/plugin.h>
#include <connman/resolver.h>
#include <connman/log.h>

static int resolvconf_append(struct connman_iface *iface, const char *nameserver)
{
	struct ifreq ifr;
	char cmd[128];
	int sk, err;

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = iface->index;

	err = ioctl(sk, SIOCGIFNAME, &ifr);

	close(sk);

	if (err < 0)
		return -1;

	DBG("ifname %s", ifr.ifr_name);

	snprintf(cmd, sizeof(cmd), "echo \"nameserver %s\" | resolvconf -a %s",
						nameserver, ifr.ifr_name);

	DBG("%s", cmd);

	err = system(cmd);

	return 0;
}

static int resolvconf_remove(struct connman_iface *iface)
{
	struct ifreq ifr;
	char cmd[128];
	int sk, err;

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = iface->index;

	err = ioctl(sk, SIOCGIFNAME, &ifr);

	close(sk);

	if (err < 0)
		return -1;

	DBG("ifname %s", ifr.ifr_name);

	snprintf(cmd, sizeof(cmd), "resolvconf -d %s", ifr.ifr_name);

	DBG("%s", cmd);

	err = system(cmd);

	return 0;
}

static struct connman_resolver_driver resolvconf_driver = {
	.name		= "resolvconf",
	.append		= resolvconf_append,
	.remove		= resolvconf_remove,
};

static int resolvconf_init(void)
{
	return connman_resolver_register(&resolvconf_driver);
}

static void resolvconf_exit(void)
{
	connman_resolver_unregister(&resolvconf_driver);
}

CONNMAN_PLUGIN_DEFINE("resolvconf", "Name resolver plugin", VERSION,
					resolvconf_init, resolvconf_exit)
