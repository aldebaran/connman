/*
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/errno.h>
#include <libiptc/libiptc.h>
#include <libiptc/libip6tc.h>
#include <xtables.h>

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_quota.h>

static void print_match(const struct ipt_entry *e)
{
	struct xt_entry_match *match;
	struct xtables_match *xt_match;

	match = (struct xt_entry_match *)e->elems;
	if (match == NULL)
		return;

	xt_match = xtables_find_match(match->u.user.name, XTF_TRY_LOAD, NULL);
	if (xt_match == NULL)
		return;

	printf("\tMATCH:%s\n", xt_match->m->u.user.name);
}

static void print_target(const struct ipt_entry *e)
{
	struct xt_entry_target *target;
	struct xtables_target *xt_target;

	target = (void *)e + e->target_offset;
	if (target == NULL)
		return;

	xt_target = xtables_find_target(target->u.user.name, XTF_TRY_LOAD);
	if (xt_target == NULL)
		return;

	printf("\tTARGET: %s\n", xt_target->t->u.user.name);
}


static void print_rule(const struct ipt_entry *e, const char *chain)
{
	/* print chain name */
	printf("CHAIN %s:\n", chain);

	print_match(e);
	print_target(e);
}

static void print_tables(struct iptc_handle *h)
{
	const char *chain;
	const struct ipt_entry *rule;

	chain = iptc_first_chain(h);

	while(chain) {
		rule = iptc_first_rule(chain, h);
		while (rule) {
			print_rule(rule, chain);

			rule = iptc_next_rule(rule, h);
		}

		chain = iptc_next_chain(h);
	}
}

static struct ipt_entry *build_quota_drop_entry(void)
{
	struct ipt_entry *e;
	size_t match_size, target_size;
	struct xtables_target *t;
	struct xtables_match *m;
	struct xtables_rule_match *matches = NULL;

	m = xtables_find_match("quota", XTF_LOAD_MUST_SUCCEED, &matches);
	if (m == NULL)
		return NULL;

	match_size = IPT_ALIGN(sizeof(struct ipt_entry_match)) + m->size;

	m->m = xtables_calloc(1, match_size);
	if (m->m == NULL)
		return NULL;
	m->m->u.match_size = match_size;
	strcpy(m->m->u.user.name, m->name);
	m->m->u.user.revision = m->revision;
	if (m->init != NULL)
		m->init(m->m);

	t = xtables_find_target("DROP", XTF_TRY_LOAD);
	if (t == NULL) {
		free(m->m);
		return NULL;
	}

	target_size = IPT_ALIGN(sizeof(struct ipt_entry_target)) + t->size;

	t->t = xtables_calloc(1, target_size);
	t->t->u.target_size = target_size;
	strcpy(t->t->u.user.name, "DROP");
	t->t->u.user.revision = t->revision;
	if (t->init != NULL)
		t->init(t->t);

	e = calloc(1, sizeof(struct ipt_entry) + match_size + target_size);
	if (e == NULL) {
		free(m->m);
		free(t->t);
	}

	e->target_offset = sizeof(struct ipt_entry) + match_size;
	e->next_offset = sizeof(struct ipt_entry) + match_size + target_size;

	memcpy(e->elems, m->m, match_size);
	memcpy(e->elems + match_size, t->t, target_size);

	return e;
}

static int add_rule(const ipt_chainlabel chain, struct ipt_entry *e,
			struct iptc_handle *h)
{
	if (!iptc_create_chain(chain, h)) {
		printf("Chain creation error (%s)\n", iptc_strerror(errno));
		return -1;
	}

	if (!iptc_insert_entry(chain, e, 0, h)) {
		printf("Entry insertion error (%s)\n", iptc_strerror(errno));
		return -1;
	}

	if (!iptc_commit(h)) {
		printf("Commit error (%s)\n", iptc_strerror(errno));
		return -1;
	}

	return 0;
}

static void remove_rule(const ipt_chainlabel chain, struct iptc_handle *h)
{
	iptc_flush_entries(chain, h);
	iptc_delete_chain(chain, h);
	iptc_commit(h);
}


int main(int argc, char *argv[])
{
	struct iptc_handle *h;
	struct ipt_entry *e;

	if (argc < 2) {
		printf("Usage: iptables-test [chain-name]\n");
		return -1;
	}

	h = iptc_init("filter");
	if (!h) {
		printf("libiptc initialization error (%s)\n",
			iptc_strerror(errno));
		exit(errno);
	}

	xtables_init();
	xtables_set_nfproto(NFPROTO_IPV4);

	e = build_quota_drop_entry();
	if (e == NULL)
		return -1;

	add_rule(argv[1], e, h);

	print_tables(h);

	remove_rule(argv[1], h);

	return 0;
}
