/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2013  BWM CarIT GmbH. All rights reserved.
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

#include <glib.h>

#include "../src/connman.h"

static void test_iptables_basic0(void)
{
	int err;

	err = __connman_iptables_command("-t filter -A INPUT "
					"-m mark --mark 1 -j LOG");
	g_assert(err == 0);

	err = __connman_iptables_commit("filter");
	g_assert(err == 0);

	err = __connman_iptables_command("-t filter -D INPUT "
					"-m mark --mark 1 -j LOG");
	g_assert(err == 0);

	err = __connman_iptables_commit("filter");
	g_assert(err == 0);
}

static void test_iptables_basic1(void)
{
	int err;

	/* Test if we can do NAT stuff */

	err = __connman_iptables_command("-t nat -A POSTROUTING "
				"-s 10.10.1.0/24 -o eth0 -j MASQUERADE");

	err = __connman_iptables_commit("nat");
	g_assert(err == 0);

	err = __connman_iptables_command("-t nat -D POSTROUTING "
				"-s 10.10.1.0/24 -o eth0 -j MASQUERADE");

	err = __connman_iptables_commit("nat");
	g_assert(err == 0);
}

static void test_iptables_basic2(void)
{
	int err;

	/* Test if the right rule is removed */

	err = __connman_iptables_command("-t filter -A INPUT "
					"-m mark --mark 1 -j LOG");
	g_assert(err == 0);

	err = __connman_iptables_commit("filter");
	g_assert(err == 0);

	err = __connman_iptables_command("-t filter -A INPUT "
					"-m mark --mark 2 -j LOG");
	g_assert(err == 0);

	err = __connman_iptables_commit("filter");
	g_assert(err == 0);

	err = __connman_iptables_command("-t filter -D INPUT "
					"-m mark --mark 2 -j LOG");
	g_assert(err == 0);

	err = __connman_iptables_commit("filter");
	g_assert(err == 0);

	err = __connman_iptables_command("-t filter -D INPUT "
					"-m mark --mark 1 -j LOG");
	g_assert(err == 0);

	err = __connman_iptables_commit("filter");
	g_assert(err == 0);
}

int main(int argc, char *argv[])
{
	int err;

	g_test_init(&argc, &argv, NULL);

	__connman_log_init(argv[0], "*", FALSE, FALSE,
			"Unit Tests Connection Manager", VERSION);
	__connman_iptables_init();

	g_test_add_func("/iptables/basic0", test_iptables_basic0);
	g_test_add_func("/iptables/basic1", test_iptables_basic1);
	g_test_add_func("/iptables/basic2", test_iptables_basic2);

	err = g_test_run();

	__connman_iptables_cleanup();

	return err;
}
