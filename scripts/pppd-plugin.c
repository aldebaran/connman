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

#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pppd/pppd.h>
#include <pppd/fsm.h>
#include <pppd/ipcp.h>

static void notifier_phasechange(void *data, int arg)
{
	printf("phasechange: data %p arg %d\n", data, arg);
}

static void notifier_exit(void *data, int arg)
{
	printf("exitnotify: data %p arg %d\n", data, arg);
}

static void notifier_ipup(void *data, int arg)
{
	ipcp_options opts = ipcp_gotoptions[0];
	ipcp_options peer = ipcp_hisoptions[0];
	struct in_addr ouraddr, hisaddr;

	printf("ipup: data %p arg %d\n", data, arg);

	memcpy(&ouraddr, &opts.ouraddr, sizeof(ouraddr));
	memcpy(&hisaddr, &peer.hisaddr, sizeof(hisaddr));

	printf("%s: %s -> %s\n",
			ifname, inet_ntoa(ouraddr), inet_ntoa(hisaddr));

	script_unsetenv("USEPEERDNS");
	script_unsetenv("DNS1");
	script_unsetenv("DNS2");
}

static void notifier_ipdown(void *data, int arg)
{
	printf("ipdown: data %p arg %d\n", data, arg);
}

char pppd_version[] = VERSION;

int plugin_init(void);

int plugin_init(void)
{
#if 0
	path_ipup[0] = '\0';
	path_ipdown[0] = '\0';
#endif

	add_notifier(&phasechange, notifier_phasechange, NULL);
	add_notifier(&exitnotify, notifier_exit, NULL);

	add_notifier(&ip_up_notifier, notifier_ipup, NULL);
	add_notifier(&ip_down_notifier, notifier_ipdown, NULL);

	return 0;
}
