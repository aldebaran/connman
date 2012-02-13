/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2012  BWM CarIT GmbH. All rights reserved.
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

/* #define DEBUG */
#ifdef DEBUG
#include <stdio.h>

#define LOG(fmt, arg...) do { \
	fprintf(stdout, "%s:%s() " fmt "\n", \
			__FILE__, __func__ , ## arg); \
} while (0)
#else
#define LOG(fmt, arg...)
#endif

struct connman_notifier *nat_notifier;

struct connman_service {
	char *dummy;
};

char *connman_service_get_interface(struct connman_service *service)
{
	return "eth0";
}

int connman_notifier_register(struct connman_notifier *notifier)
{
	nat_notifier = notifier;

	return 0;
}

void connman_notifier_unregister(struct connman_notifier *notifier)
{
	nat_notifier = NULL;
}


static void test_iptables_basic0(void)
{
	int err;

	err = __connman_iptables_command("-C INPUT -i session-bridge -j ACCEPT");
	g_assert(err != 0);
	err = __connman_iptables_commit("filter");
	g_assert(err == 0);

	err = __connman_iptables_command("-I INPUT -i session-bridge -j ACCEPT");
	g_assert(err == 0);
	err = __connman_iptables_commit("filter");
	g_assert(err == 0);

	err = __connman_iptables_command("-C INPUT -i session-bridge -j ACCEPT");
	g_assert(err == 0);
	err = __connman_iptables_commit("filter");
	g_assert(err == 0);

	err = __connman_iptables_command("-D INPUT -i session-bridge -j ACCEPT");
	g_assert(err == 0);
	err = __connman_iptables_commit("filter");
	g_assert(err == 0);

	err = __connman_iptables_command("-C INPUT -i session-bridge -j ACCEPT");
	g_assert(err != 0);
	err = __connman_iptables_commit("filter");
	g_assert(err == 0);
}

static void test_nat_basic0(void)
{
	int err;

	err = __connman_nat_enable("bridge", "192.168.2.1", 24);
	g_assert(err == 0);

	/* test that table is empty */
	err = __connman_iptables_command("-t nat -C POSTROUTING "
					"-s 192.168.2.1/24 -o eth0 -j MASQUERADE");
	g_assert(err != 0);
	err = __connman_iptables_commit("nat");
	g_assert(err == 0);


	__connman_nat_disable("bridge");
}

static void test_nat_basic1(void)
{
	struct connman_service *service;
	int err;

	service = g_try_new0(struct connman_service, 1);
	g_assert(service);

	nat_notifier->default_changed(service);

	err = __connman_nat_enable("bridge", "192.168.2.1", 24);
	g_assert(err == 0);

	/* test that table is not empty */
	err = __connman_iptables_command("-t nat -C POSTROUTING "
					"-s 192.168.2.1/24 -o eth0 -j MASQUERADE");
	g_assert(err == 0);
	err = __connman_iptables_commit("nat");
	g_assert(err == 0);

	__connman_nat_disable("bridge");

	/* test that table is empty again */
	err = __connman_iptables_command("-t nat -C POSTROUTING "
					"-s 192.168.2.1/24 -o eth0 -j MASQUERADE");
	g_assert(err != 0);
	err = __connman_iptables_commit("nat");
	g_assert(err == 0);
}

int main(int argc, char *argv[])
{
	int err;

	g_test_init(&argc, &argv, NULL);

	__connman_log_init(argv[0], "*", FALSE);
	__connman_iptables_init();
	__connman_nat_init();

	g_test_add_func("/iptables/basic0", test_iptables_basic0);
	g_test_add_func("/nat/basic0", test_nat_basic0);
	g_test_add_func("/nat/basic1", test_nat_basic1);

	err = g_test_run();

	__connman_nat_cleanup();
	__connman_iptables_cleanup();
	__connman_log_cleanup();

	return err;
}
