/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2012  Intel Corporation. All rights reserved.
 *  Copyright (C) 2012  BMW Car IT GmbH. All rights reserved.
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

#include <errno.h>
#include <stdio.h>

#include "connman.h"

static char *default_interface;
static GHashTable *nat_hash;

struct connman_nat {
	char *address;
	unsigned char prefixlen;

	char *interface;
};

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

static void flush_nat(void)
{
	int err;

	err = __connman_iptables_command("-t nat -F POSTROUTING");
	if (err < 0) {
		DBG("Flushing the nat table failed");

		return;
	}

	__connman_iptables_commit("nat");
}

static int enable_nat(struct connman_nat *nat)
{
	int err;

	g_free(nat->interface);
	nat->interface = g_strdup(default_interface);

	if (nat->interface == NULL)
		return 0;

	/* Enable masquerading */
	err = __connman_iptables_command("-t nat -A POSTROUTING "
					"-s %s/%d -o %s -j MASQUERADE",
					nat->address,
					nat->prefixlen,
					nat->interface);
	if (err < 0)
		return err;

	return __connman_iptables_commit("nat");
}

static void disable_nat(struct connman_nat *nat)
{
	int err;

	if (nat->interface == NULL)
		return;

	/* Disable masquerading */
	err = __connman_iptables_command("-t nat -D POSTROUTING "
					"-s %s/%d -o %s -j MASQUERADE",
					nat->address,
					nat->prefixlen,
					nat->interface);
	if (err < 0)
		return;

	__connman_iptables_commit("nat");
}

int __connman_nat_enable(const char *name, const char *address,
				unsigned char prefixlen)
{
	struct connman_nat *nat;
	int err;

	if (g_hash_table_size(nat_hash) == 0) {
		err = enable_ip_forward(TRUE);
		if (err < 0)
			return err;
	}

	nat = g_try_new0(struct connman_nat, 1);
	if (nat == NULL) {
		if (g_hash_table_size(nat_hash) == 0)
			enable_ip_forward(FALSE);

		return -ENOMEM;
	}

	nat->address = g_strdup(address);
	nat->prefixlen = prefixlen;

	g_hash_table_replace(nat_hash, g_strdup(name), nat);

	return enable_nat(nat);
}

void __connman_nat_disable(const char *name)
{
	struct connman_nat *nat;

	nat = g_hash_table_lookup(nat_hash, name);
	if (nat == NULL)
		return;

	disable_nat(nat);

	g_hash_table_remove(nat_hash, name);

	if (g_hash_table_size(nat_hash) == 0)
		enable_ip_forward(FALSE);
}

static void update_default_interface(struct connman_service *service)
{
	GHashTableIter iter;
	gpointer key, value;
	char *interface;
	int err;

	interface = connman_service_get_interface(service);

	DBG("interface %s", interface);

	g_free(default_interface);
	default_interface = interface;

	g_hash_table_iter_init(&iter, nat_hash);

	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		const char *name = key;
		struct connman_nat *nat = value;

		disable_nat(nat);
		err = enable_nat(nat);
		if (err < 0)
			DBG("Failed to enable nat for %s", name);
	}
}

static void shutdown_nat(gpointer key, gpointer value, gpointer user_data)
{
	const char *name = key;

	__connman_nat_disable(name);
}

static void cleanup_nat(gpointer data)
{
	struct connman_nat *nat = data;

	g_free(nat->address);
	g_free(nat->interface);
}

static struct connman_notifier nat_notifier = {
	.name			= "nat",
	.default_changed	= update_default_interface,
};

int __connman_nat_init(void)
{
	int err;

	DBG("");

	err = connman_notifier_register(&nat_notifier);
	if (err < 0)
		return err;

	nat_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						g_free, cleanup_nat);

	flush_nat();

	return 0;
}

void __connman_nat_cleanup(void)
{
	DBG("");

	g_hash_table_foreach(nat_hash, shutdown_nat, NULL);
	g_hash_table_destroy(nat_hash);
	nat_hash = NULL;

	flush_nat();

	connman_notifier_unregister(&nat_notifier);
}
