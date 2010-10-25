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

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <xtables.h>

#include <linux/netfilter_ipv4/ip_tables.h>

#include <glib.h>

static const char *hooknames[] = {
	[NF_IP_PRE_ROUTING]	= "PREROUTING",
	[NF_IP_LOCAL_IN]	= "INPUT",
	[NF_IP_FORWARD]		= "FORWARD",
	[NF_IP_LOCAL_OUT]	= "OUTPUT",
	[NF_IP_POST_ROUTING]	= "POSTROUTING",
};

#define LABEL_ACCEPT  "ACCEPT"
#define LABEL_DROP    "DROP"
#define LABEL_QUEUE   "QUEUE"
#define LABEL_RETURN  "RETURN"

/* fn returns 0 to continue iteration */
#define _XT_ENTRY_ITERATE_CONTINUE(type, entries, size, n, fn, args...) \
({								\
	unsigned int __i;					\
	int __n;						\
	int __ret = 0;						\
	type *__entry;						\
								\
	for (__i = 0, __n = 0; __i < (size);			\
	     __i += __entry->next_offset, __n++) { 		\
		__entry = (void *)(entries) + __i;		\
		if (__n < n)					\
			continue;				\
								\
		__ret = fn(__entry,  ## args);			\
		if (__ret != 0)					\
			break;					\
	}							\
	__ret;							\
})

/* fn returns 0 to continue iteration */
#define _XT_ENTRY_ITERATE(type, entries, size, fn, args...) \
	_XT_ENTRY_ITERATE_CONTINUE(type, entries, size, 0, fn, args)

#define ENTRY_ITERATE(entries, size, fn, args...) \
	_XT_ENTRY_ITERATE(struct ipt_entry, entries, size, fn, ## args)

#define MIN_ALIGN (__alignof__(struct ipt_entry))

#define ALIGN(s) (((s) + ((MIN_ALIGN)-1)) & ~((MIN_ALIGN)-1))

struct ipt_error_target {
	struct xt_entry_target t;
	char error[IPT_TABLE_MAXNAMELEN];
};

struct connman_iptables_entry {
	int builtin;
	int std_target;
	int jump_offset;

	struct ipt_entry *entry;
};

struct connman_iptables {
	int ipt_sock;

	struct ipt_getinfo *info;
	struct ipt_get_entries *blob_entries;

	unsigned int num_entries;
	unsigned int old_entries;
	unsigned int size;

	GList *entries;
};


static struct ipt_entry *get_entry(struct connman_iptables *table,
					unsigned int offset)
{
	return (struct ipt_entry *)((char *)table->blob_entries->entrytable +
									offset);
}

static int is_hook_entry(struct connman_iptables *table,
				struct ipt_entry *entry)
{
	unsigned int i;

	for (i = 0; i < NF_INET_NUMHOOKS; i++) {
		if ((table->info->valid_hooks & (1 << i))
		&& get_entry(table, table->info->hook_entry[i]) == entry)
			return i;
	}

	return -1;
}

static unsigned long entry_to_offset(struct connman_iptables *table,
					struct ipt_entry *entry)
{
	return (void *)entry - (void *)table->blob_entries->entrytable;
}

static int target_to_verdict(char *target_name)
{
	if (!strcmp(target_name, LABEL_ACCEPT))
		return -NF_ACCEPT - 1;

	if (!strcmp(target_name, LABEL_DROP))
		return -NF_DROP - 1;

	if (!strcmp(target_name, LABEL_QUEUE))
		return -NF_QUEUE - 1;

	if (!strcmp(target_name, LABEL_RETURN))
		return XT_RETURN;

	return 0;
}

static gboolean is_builtin_target(char *target_name)
{
	if (!strcmp(target_name, LABEL_ACCEPT) ||
		!strcmp(target_name, LABEL_DROP) ||
		!strcmp(target_name, LABEL_QUEUE) ||
		!strcmp(target_name, LABEL_RETURN))
		return TRUE;

	return FALSE;
}

static gboolean is_chain(struct connman_iptables *table,
				struct connman_iptables_entry *e)
{
	int builtin;
	struct ipt_entry *entry;
	struct xt_entry_target *target;

	entry = e->entry;
	builtin = is_hook_entry(table, entry);
	if (builtin >= 0)
		return TRUE;

	target = ipt_get_target(entry);
	if (!strcmp(target->u.user.name, IPT_ERROR_TARGET))
		return TRUE;

	return FALSE;
}

static GList *find_chain_tail(struct connman_iptables *table,
				char *chain_name)
{
	GList *chain_head, *list;
	struct connman_iptables_entry *head, *tail;
	struct ipt_entry *entry;
	struct xt_entry_target *target;
	int builtin;

	/* First we look for the head */
	for (list = table->entries; list; list = list->next) {
		head = list->data;
		entry = head->entry;

		/* Buit-in chain */
		builtin = is_hook_entry(table, entry);
		if (builtin >= 0 && !strcmp(hooknames[builtin], chain_name))
			break;

		/* User defined chain */
		target = ipt_get_target(entry);
		if (!strcmp(target->u.user.name, IPT_ERROR_TARGET) &&
		    !strcmp((char *)target->data, chain_name))
			break;
	}

	if (list == NULL)
		return NULL;

	chain_head = list;

	/* Then we look for the next chain */
	for (list = chain_head->next; list; list = list->next) {
		tail = list->data;
		entry = tail->entry;

		if (is_chain(table, tail))
			return list;
	}

	/* Nothing found, we return the table end */
	return g_list_last(table->entries);
}

static int connman_add_entry(struct connman_iptables *table,
				struct ipt_entry *entry, GList *before)
{
	struct connman_iptables_entry *e;

	if (table == NULL)
		return -1;

	e = g_try_malloc0(sizeof(struct connman_iptables_entry));
	if (e == NULL)
		return -1;

	e->entry = entry;

	table->entries = g_list_insert_before(table->entries, before, e);
	table->num_entries++;
	table->size += entry->next_offset;

	return 0;
}

static int connman_iptables_add_chain(struct connman_iptables *table,
					char *name)
{
	GList *last;
	struct ipt_entry *entry_head;
	struct ipt_entry *entry_return;
	struct ipt_error_target *error;
	struct ipt_standard_target *standard;
	u_int16_t entry_head_size, entry_return_size;

	last = g_list_last(table->entries);

	/*
	 * An empty chain is composed of:
	 * - A head entry, with no match and an error target.
	 *   The error target data is the chain name.
	 * - A tail entry, with no match and a standard target.
	 *   The standard target verdict is XT_RETURN (return to the
	 *   caller).
	 */

	/* head entry */
	entry_head_size = sizeof(struct ipt_entry) +
				sizeof(struct ipt_error_target);
	entry_head = g_try_malloc0(entry_head_size);
	if (entry_head == NULL)
		goto err;

	memset(entry_head, 0, entry_head_size);

	entry_head->target_offset = sizeof(struct ipt_entry);
	entry_head->next_offset = entry_head_size;

	error = (struct ipt_error_target *) entry_head->elems;
	strcpy(error->t.u.user.name, IPT_ERROR_TARGET);
	error->t.u.user.target_size = ALIGN(sizeof(struct ipt_error_target));
	strcpy(error->error, name);

	if (connman_add_entry(table, entry_head, last) < 0)
		goto err;

	/* tail entry */
	entry_return_size = sizeof(struct ipt_entry) +
				sizeof(struct ipt_standard_target);
	entry_return = g_try_malloc0(entry_return_size);
	if (entry_return == NULL)
		goto err;

	memset(entry_return, 0, entry_return_size);

	entry_return->target_offset = sizeof(struct ipt_entry);
	entry_return->next_offset = entry_return_size;

	standard = (struct ipt_standard_target *) entry_return->elems;
	standard->target.u.user.target_size =
				ALIGN(sizeof(struct ipt_standard_target));
	standard->verdict = XT_RETURN;

	if (connman_add_entry(table, entry_return, last) < 0)
		goto err;

	return 0;

err:
	g_free(entry_head);
	g_free(entry_return);

	return -ENOMEM;
}

static struct ipt_entry *
new_builtin_rule(char *target_name, struct xtables_match *xt_m)
{
	struct ipt_entry *new_entry;
	size_t match_size, target_size;
	struct xt_entry_match *entry_match;
	struct xt_standard_target *target;


	if (xt_m)
		match_size = xt_m->m->u.match_size;
	else
		match_size = 0;

	target_size = ALIGN(sizeof(struct xt_standard_target));

	new_entry = g_try_malloc0(sizeof(struct ipt_entry) + target_size +
								match_size);
	if (new_entry == NULL)
		return NULL;

	new_entry->target_offset = sizeof(struct ipt_entry) + match_size;
	new_entry->next_offset = sizeof(struct ipt_entry) + target_size +
								match_size;

	if (xt_m) {
		entry_match = (struct xt_entry_match *)new_entry->elems;
		memcpy(entry_match, xt_m->m, match_size);
	}

	target = (struct xt_standard_target *)(new_entry->elems + match_size);
	strcpy(target->target.u.user.name, IPT_STANDARD_TARGET);
	target->target.u.user.target_size =
				ALIGN(sizeof(struct ipt_standard_target));
	target->verdict = target_to_verdict(target_name);

	return new_entry;
}

static struct ipt_entry *
new_custom_rule(struct xtables_target *xt_t, struct xtables_match *xt_m)
{
	return NULL;
}

static struct ipt_entry *
new_rule(char *target_name, struct xtables_target *xt_t,
		char *match_name, struct xtables_match *xt_m)
{
	struct ipt_entry *new_entry;

	if (is_builtin_target(target_name))
		new_entry = new_builtin_rule(target_name, xt_m);
	else
		new_entry = new_custom_rule(xt_t, xt_m);

	return new_entry;
}

static int
connman_iptables_add_rule(struct connman_iptables *table, char *chain_name,
				char *target_name, struct xtables_target *xt_t,
				char *match_name, struct xtables_match *xt_m)
{
	GList *chain_tail;
	struct ipt_entry *new_entry;

	chain_tail = find_chain_tail(table, chain_name);
	if (chain_tail == NULL)
		return -EINVAL;

	new_entry = new_rule(target_name, xt_t,
				match_name, xt_m);
	if (new_entry == NULL)
		return -EINVAL;

	return connman_add_entry(table, new_entry, chain_tail->prev);
}

static struct ipt_replace *
connman_iptables_blob(struct connman_iptables *table)
{
	struct ipt_replace *r;
	GList *list;
	struct connman_iptables_entry *e;
	unsigned char *entry_index;

	r = g_try_malloc0(sizeof(struct ipt_replace) + table->size);
	if (r == NULL)
		return NULL;

	memset(r, 0, sizeof(*r) + table->size);

	r->counters = g_try_malloc0(sizeof(struct xt_counters)
				* table->num_entries);
	if (r->counters == NULL) {
		g_free(r);
		return NULL;
	}

	strcpy(r->name, table->info->name);
	r->num_entries = table->num_entries;
	r->size = table->size;

	r->num_counters = table->old_entries;
	r->valid_hooks  = table->info->valid_hooks;

	memcpy(r->hook_entry, table->info->hook_entry,
				sizeof(table->info->hook_entry));
	memcpy(r->underflow, table->info->underflow,
				sizeof(table->info->underflow));

	entry_index = (unsigned char *)r->entries;
	for (list = table->entries; list; list = list->next) {
		e = list->data;

		memcpy(entry_index, e->entry, e->entry->next_offset);
		entry_index += e->entry->next_offset;
	}

	return r;
}

static void dump_target(struct connman_iptables *table,
				struct ipt_entry *entry)

{
	struct xtables_target *xt_t;
	struct xt_entry_target *target;

	target = ipt_get_target(entry);

	if (!strcmp(target->u.user.name, IPT_STANDARD_TARGET)) {
		struct xt_standard_target *t;

		t = (struct xt_standard_target *)target;

		switch (t->verdict) {
		case XT_RETURN:
			printf("\ttarget RETURN\n");
			break;

		case -NF_ACCEPT - 1:
			printf("\ttarget ACCEPT\n");
			break;

		case -NF_DROP - 1:
			printf("\ttarget DROP\n");
			break;

		case -NF_QUEUE - 1:
			printf("\ttarget QUEUE\n");
			break;

		case -NF_STOP - 1:
			printf("\ttarget STOP\n");
			break;

		default:
			printf("\tJUMP @%p (0x%x)\n",
				(char*)table->blob_entries->entrytable +
				t->verdict, t->verdict);
			break;
		}

		xt_t = xtables_find_target(IPT_STANDARD_TARGET,
						XTF_LOAD_MUST_SUCCEED);

		if(xt_t->print != NULL)
			xt_t->print(NULL, target, 1);
	} else {
		printf("\ttarget %s\n", target->u.user.name);

		xt_t = xtables_find_target(target->u.user.name, XTF_TRY_LOAD);
		if (xt_t == NULL)
			return;

		if(xt_t->print != NULL)
			xt_t->print(NULL, target, 1);
	}
}

static void dump_match(struct connman_iptables *table, struct ipt_entry *entry)
{
	struct xtables_match *xt_m;
	struct xt_entry_match *match;

	match = (struct xt_entry_match *) entry->elems;

	if (!strlen(match->u.user.name))
		return;

	xt_m = xtables_find_match(match->u.user.name, XTF_TRY_LOAD, NULL);
	if (xt_m == NULL)
		goto out;

	if(xt_m->print != NULL) {
		printf("\tmatch ");
		xt_m->print(NULL, match, 1);
		printf("\n");

		return;
	}

out:
	printf("\tmatch %s\n", match->u.user.name);

}

static int connman_iptables_dump_entry(struct ipt_entry *entry,
					struct connman_iptables *table)
{
	struct xt_entry_target *target;
	unsigned int offset;
	int builtin;

	offset = (char *)entry - (char *)table->blob_entries->entrytable;
	target = ipt_get_target(entry);
	builtin = is_hook_entry(table, entry);

	if (entry_to_offset(table, entry) + entry->next_offset ==
					table->blob_entries->size) {
		printf("End of CHAIN 0x%x\n", offset);
		return 0;
	}

	if (!strcmp(target->u.user.name, IPT_ERROR_TARGET)) {
		printf("USER CHAIN (%s) %p  match %p  target %p  size %d\n",
			target->data, entry, entry->elems,
			(char *)entry + entry->target_offset,
				entry->next_offset);

		return 0;
	} else if (builtin >= 0) {
		printf("CHAIN (%s) %p  match %p  target %p  size %d\n",
			hooknames[builtin], entry, entry->elems,
			(char *)entry + entry->target_offset,
				entry->next_offset);
	} else {
		printf("RULE %p  match %p  target %p  size %d\n", entry,
			entry->elems,
			(char *)entry + entry->target_offset,
				entry->next_offset);
	}

	dump_match(table, entry);
	dump_target(table, entry);

	return 0;
}

static void connman_iptables_dump(struct connman_iptables *table)
{
	printf("%s valid_hooks=0x%08x, num_entries=%u, size=%u\n",
		table->info->name,
		table->info->valid_hooks, table->info->num_entries,
		table->info->size);

	ENTRY_ITERATE(table->blob_entries->entrytable,
			table->blob_entries->size,
			connman_iptables_dump_entry, table);

}

static int connman_iptables_get_entries(struct connman_iptables *table)
{
	socklen_t entry_size;

	entry_size = sizeof(struct ipt_get_entries) + table->info->size;

	return getsockopt(table->ipt_sock, IPPROTO_IP, IPT_SO_GET_ENTRIES,
				table->blob_entries, &entry_size);
}

static int connman_iptables_replace(struct connman_iptables *table,
					struct ipt_replace *r)
{
	return setsockopt(table->ipt_sock, IPPROTO_IP, IPT_SO_SET_REPLACE, r,
			 sizeof(*r) + r->size);
}

static void connman_iptables_cleanup(struct connman_iptables *table)
{
	close(table->ipt_sock);
	g_free(table->info);
	g_free(table->blob_entries);
	g_free(table);

	xtables_free_opts(1);
}

static int connman_iptables_commit(struct connman_iptables *table)
{
	struct ipt_replace *repl;

	repl = connman_iptables_blob(table);

	return connman_iptables_replace(table, repl);
}

static int add_entry(struct ipt_entry *entry, struct connman_iptables *table)
{
	return connman_add_entry(table, entry, NULL);
}

static struct connman_iptables *connman_iptables_init(const char *table_name)
{
	struct connman_iptables *table;
	socklen_t s;

	table =  g_try_new0(struct connman_iptables, 1);
	if (table == NULL)
		return NULL;

	table->info =  g_try_new0(struct ipt_getinfo, 1);
	if (table->info == NULL)
		goto err;

	table->ipt_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (table->ipt_sock < 0)
		goto err;

	s = sizeof(*table->info);
	strcpy(table->info->name, table_name);
	if (getsockopt(table->ipt_sock, IPPROTO_IP, IPT_SO_GET_INFO,
						table->info, &s) < 0)
		goto err;

	table->blob_entries = g_try_malloc0(sizeof(struct ipt_get_entries) +
						table->info->size);
	if (table->blob_entries == NULL)
		goto err;

	strcpy(table->blob_entries->name, table_name);
	table->blob_entries->size = table->info->size;

	if (connman_iptables_get_entries(table) < 0)
		goto err;

	table->num_entries = 0;
	table->old_entries = table->info->num_entries;
	table->size = 0;

	ENTRY_ITERATE(table->blob_entries->entrytable,
			table->blob_entries->size,
				add_entry, table);


	return table;

err:

	connman_iptables_cleanup(table);

	return NULL;
}


static struct option connman_iptables_opts[] = {
	{.name = "append",        .has_arg = 1, .val = 'A'},
	{.name = "list",          .has_arg = 2, .val = 'L'},
	{.name = "new-chain",     .has_arg = 1, .val = 'N'},
	{.name = "in-interface",  .has_arg = 1, .val = 'i'},
	{.name = "jump",          .has_arg = 1, .val = 'j'},
	{.name = "match",         .has_arg = 1, .val = 'm'},
	{.name = "out-interface", .has_arg = 1, .val = 'o'},
	{.name = "table",         .has_arg = 1, .val = 't'},
	{NULL},
};

struct xtables_globals connman_iptables_globals = {
	.option_offset = 0,
	.opts = connman_iptables_opts,
	.orig_opts = connman_iptables_opts,
};

int main(int argc, char *argv[])
{
	struct connman_iptables *table;
	struct xtables_match *xt_m;
	struct xtables_target *xt_t;
	char *table_name, *chain, *new_chain, *match_name, *target_name;
	int c;
	size_t size;
	gboolean dump;

	xtables_init_all(&connman_iptables_globals, NFPROTO_IPV4);

	dump = FALSE;
	table_name = chain = new_chain = match_name = target_name = NULL;
	table = NULL;
	xt_m = NULL;
	xt_t = NULL;

	while ((c = getopt_long(argc, argv,
	   "-A:L::N:j:i:m:o:t:", connman_iptables_globals.opts, NULL)) != -1) {
		switch (c) {
		case 'A':
			chain = optarg;
			break;

		case 'L':
			dump = TRUE;
			break;

		case 'N':
			new_chain = optarg;
			break;

		case 'j':
			target_name = optarg;
			xt_t = xtables_find_target(target_name, XTF_TRY_LOAD);

			if (xt_t == NULL)
				break;

			size = ALIGN(sizeof(struct ipt_entry_target)) + xt_t->size;

			xt_t->t = g_try_malloc0(size);
			if (xt_t->t == NULL)
				goto out;
			xt_t->t->u.target_size = size;
			strcpy(xt_t->t->u.user.name, target_name);
			xt_t->t->u.user.revision = xt_t->revision;
			if (xt_t->init != NULL)
				xt_t->init(xt_t->t);
			connman_iptables_globals.opts =
				xtables_merge_options(connman_iptables_globals.opts,
						     xt_t->extra_opts,
						     &xt_t->option_offset);
			if (connman_iptables_globals.opts == NULL)
				goto out;

			break;

		case 'i':
			break;

		case 'm':
			match_name = optarg;

			xt_m = xtables_find_match(optarg, XTF_LOAD_MUST_SUCCEED, NULL);
			size = ALIGN(sizeof(struct ipt_entry_match)) + xt_m->size;
			xt_m->m = g_try_malloc0(size);
			if (xt_m == NULL)
				goto out;
			xt_m->m->u.match_size = size;
			strcpy(xt_m->m->u.user.name, xt_m->name);
			xt_m->m->u.user.revision = xt_m->revision;
			if (xt_m->init != NULL)
				xt_m->init(xt_m->m);
			if (xt_m != xt_m->next) {
				connman_iptables_globals.opts =
					xtables_merge_options(connman_iptables_globals.opts,
						xt_m->extra_opts,
						&xt_m->option_offset);
				if (connman_iptables_globals.opts == NULL)
					goto out;
			}

			break;

		case 'o':
			break;

		case 't':
			table_name = optarg;
			break;

		default:
			if (xt_t == NULL || xt_t->parse == NULL ||
			    !xt_t->parse(c - xt_t->option_offset, argv, 0, &xt_t->tflags, NULL, &xt_t->t)) {
				if (xt_m == NULL || xt_m->parse == NULL)
					break;

				xt_m->parse(c - xt_m->option_offset, argv, 0, &xt_m->mflags, NULL, &xt_m->m);
			}

			break;
		}
	}

	if (table_name == NULL)
		table_name = "filter";

	table = connman_iptables_init(table_name);
	if (table == NULL)
		return -1;

	if (dump) {
		connman_iptables_dump(table);

		return 0;
	}

	if (chain && new_chain)
		return -1;

	if (new_chain) {
		printf("New chain %s\n", new_chain);

		connman_iptables_add_chain(table, new_chain);

		goto commit;
	}

	if (chain) {
		if (target_name == NULL)
			return -1;

		printf("Adding %s to %s (match %s)\n", target_name, chain, match_name);

		connman_iptables_add_rule(table, chain,
					target_name, xt_t,
					match_name, xt_m);

		goto commit;
	}

commit:

	connman_iptables_commit(table);

out:
	connman_iptables_cleanup(table);

	if (xt_t)
		g_free(xt_t->t);

	if (xt_m)
		g_free(xt_m->m);

	return 0;
}
