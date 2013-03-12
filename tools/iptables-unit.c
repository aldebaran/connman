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

static void test_iptables_chain0(void)
{
	int err;

	err = __connman_iptables_new_chain("filter", "foo");
	g_assert(err == 0);

	err = __connman_iptables_commit("filter");
	g_assert(err == 0);

	err = __connman_iptables_delete_chain("filter", "foo");
	g_assert(err == 0);

	err = __connman_iptables_commit("filter");
	g_assert(err == 0);
}

static void test_iptables_chain1(void)
{
	int err;

	err = __connman_iptables_new_chain("filter", "foo");
	g_assert(err == 0);

	err = __connman_iptables_commit("filter");
	g_assert(err == 0);

	err = __connman_iptables_flush_chain("filter", "foo");
	g_assert(err == 0);

	err = __connman_iptables_commit("filter");
	g_assert(err == 0);

	err = __connman_iptables_delete_chain("filter", "foo");
	g_assert(err == 0);

	err = __connman_iptables_commit("filter");
	g_assert(err == 0);
}

static void test_iptables_chain2(void)
{
	int err;

	err = __connman_iptables_change_policy("filter", "INPUT", "DROP");
	g_assert(err == 0);

	err = __connman_iptables_commit("filter");
	g_assert(err == 0);

	err = __connman_iptables_change_policy("filter", "INPUT", "ACCEPT");
	g_assert(err == 0);

	err = __connman_iptables_commit("filter");
	g_assert(err == 0);
}

static void test_iptables_chain3(void)
{
	int err;

	err = __connman_iptables_new_chain("filter", "user-chain-0");
	g_assert(err == 0);

	err = __connman_iptables_commit("filter");
	g_assert(err == 0);

	err = __connman_iptables_new_chain("filter", "user-chain-1");
	g_assert(err == 0);

	err = __connman_iptables_commit("filter");
	g_assert(err == 0);

	err = __connman_iptables_delete_chain("filter", "user-chain-1");
	g_assert(err == 0);

	err = __connman_iptables_commit("filter");
	g_assert(err == 0);

	err = __connman_iptables_delete_chain("filter", "user-chain-0");
	g_assert(err == 0);

	err = __connman_iptables_commit("filter");
	g_assert(err == 0);
}

static void test_iptables_rule0(void)
{
	int err;

	/* Test simple appending and removing a rule */

	err = __connman_iptables_append("filter", "INPUT",
					"-m mark --mark 1 -j LOG");
	g_assert(err == 0);

	err = __connman_iptables_commit("filter");
	g_assert(err == 0);

	err = __connman_iptables_delete("filter", "INPUT",
					"-m mark --mark 1 -j LOG");
	g_assert(err == 0);

	err = __connman_iptables_commit("filter");
	g_assert(err == 0);
}


static void test_iptables_rule1(void)
{
	int err;

	/* Test if we can do NAT stuff */

	err = __connman_iptables_append("nat", "POSTROUTING",
				"-s 10.10.1.0/24 -o eth0 -j MASQUERADE");

	err = __connman_iptables_commit("nat");
	g_assert(err == 0);

	err = __connman_iptables_delete("nat", "POSTROUTING",
				"-s 10.10.1.0/24 -o eth0 -j MASQUERADE");

	err = __connman_iptables_commit("nat");
	g_assert(err == 0);
}

static void test_iptables_rule2(void)
{
	int err;

	/* Test if the right rule is removed */

	err = __connman_iptables_append("filter", "INPUT",
					"-m mark --mark 1 -j LOG");
	g_assert(err == 0);

	err = __connman_iptables_commit("filter");
	g_assert(err == 0);

	err = __connman_iptables_append("filter", "INPUT",
					"-m mark --mark 2 -j LOG");
	g_assert(err == 0);

	err = __connman_iptables_commit("filter");
	g_assert(err == 0);

	err = __connman_iptables_delete("filter", "INPUT",
					"-m mark --mark 2 -j LOG");
	g_assert(err == 0);

	err = __connman_iptables_commit("filter");
	g_assert(err == 0);

	err = __connman_iptables_delete("filter", "INPUT",
					"-m mark --mark 1 -j LOG");
	g_assert(err == 0);

	err = __connman_iptables_commit("filter");
	g_assert(err == 0);
}

static void test_iptables_target0(void)
{
	int err;

	/* Test if 'fallthrough' targets work */

	err = __connman_iptables_append("filter", "INPUT",
					"-m mark --mark 1");
	g_assert(err == 0);

	err = __connman_iptables_append("filter", "INPUT",
					"-m mark --mark 2");
	g_assert(err == 0);

	err = __connman_iptables_commit("filter");
	g_assert(err == 0);

	err = __connman_iptables_delete("filter", "INPUT",
					"-m mark --mark 1");
	g_assert(err == 0);

	err = __connman_iptables_commit("filter");
	g_assert(err == 0);

	err = __connman_iptables_delete("filter", "INPUT",
					"-m mark --mark 2");
	g_assert(err == 0);

	err = __connman_iptables_commit("filter");
	g_assert(err == 0);
}

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

static void test_nat_basic0(void)
{
	int err;

	err = __connman_nat_enable("bridge", "192.168.2.1", 24);
	g_assert(err == 0);

	/* test that table is empty */
	err = __connman_iptables_append("nat", "POSTROUTING",
					"-s 192.168.2.1/24 -o eth0 -j MASQUERADE");
	g_assert(err == 0);

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
	err = __connman_iptables_append("nat", "POSTROUTING",
					"-s 192.168.2.1/24 -o eth0 -j MASQUERADE");
	g_assert(err == 0);

	err = __connman_iptables_commit("nat");
	g_assert(err == 0);

	__connman_nat_disable("bridge");

	/* test that table is empty again */
	err = __connman_iptables_delete("nat", "POSTROUTING",
					"-s 192.168.2.1/24 -o eth0 -j MASQUERADE");
	g_assert(err == 0);

	err = __connman_iptables_commit("nat");
	g_assert(err == 0);

	g_free(service);
}

int main(int argc, char *argv[])
{
	int err;

	g_test_init(&argc, &argv, NULL);

	__connman_log_init(argv[0], "*", FALSE, FALSE,
			"Unit Tests Connection Manager", VERSION);
	__connman_iptables_init();
	__connman_nat_init();

	g_test_add_func("/iptables/chain0", test_iptables_chain0);
	g_test_add_func("/iptables/chain1", test_iptables_chain1);
	g_test_add_func("/iptables/chain2", test_iptables_chain2);
	g_test_add_func("/iptables/chain3", test_iptables_chain3);
	g_test_add_func("/iptables/rule0",  test_iptables_rule0);
	g_test_add_func("/iptables/rule1",  test_iptables_rule1);
	g_test_add_func("/iptables/rule2",  test_iptables_rule2);
	g_test_add_func("/iptables/target0", test_iptables_target0);
	g_test_add_func("/nat/basic0", test_nat_basic0);
	g_test_add_func("/nat/basic1", test_nat_basic1);

	err = g_test_run();

	__connman_nat_cleanup();
	__connman_iptables_cleanup();

	return err;
}
