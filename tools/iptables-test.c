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
new_builtin_rule(char *target_name,
		char *match_name, int match_argc, char **match_argv)
{
	struct ipt_entry *new_entry;
	size_t match_size, target_size;
	struct xtables_match *xt_m;
	struct xt_standard_target *target;

	xt_m = NULL;
	match_size = 0;

	if (match_name) {
		xt_m = xtables_find_match(match_name, XTF_TRY_LOAD, NULL);
		if (xt_m == NULL)
			return NULL;

		match_size = ALIGN(sizeof(struct xt_entry_match)) + xt_m->size;
	}

	target_size = ALIGN(sizeof(struct xt_standard_target));

	new_entry = g_try_malloc0(sizeof(struct ipt_entry) + target_size +
								match_size);
	if (new_entry == NULL)
		return NULL;

	new_entry->target_offset = sizeof(struct ipt_entry) + match_size;
	new_entry->next_offset = sizeof(struct ipt_entry) + target_size +
								match_size;

	if (xt_m) {
		struct xt_entry_match *entry_match;

		entry_match = (struct xt_entry_match *)new_entry->elems;
		entry_match->u.match_size = match_size;
		strcpy(entry_match->u.user.name, xt_m->name);
		entry_match->u.user.revision = xt_m->revision;
		if (xt_m->init != NULL)
			xt_m->init(entry_match);
	}

	target = (struct xt_standard_target *)(new_entry->elems + match_size);
	strcpy(target->target.u.user.name, IPT_STANDARD_TARGET);
	target->target.u.user.target_size =
				ALIGN(sizeof(struct ipt_standard_target));
	target->verdict = target_to_verdict(target_name);

	return new_entry;
}

static struct ipt_entry *
new_custom_rule(char *target_name, int target_argc, char **target_argv,
		char *match_name, int match_argc, char **match_argv)
{
	return NULL;
}

static struct ipt_entry *
new_rule(char *target_name, int target_argc, char **target_argv,
		char *match_name, int match_argc, char **match_argv)
{
	struct ipt_entry *new_entry;

	if (is_builtin_target(target_name))
		new_entry = new_builtin_rule(target_name,
					match_name, match_argc, match_argv);
	else
		new_entry = new_custom_rule(target_name,
					target_argc, target_argv,
					match_name, match_argc, match_argv);

	return new_entry;
}

static int
connman_iptables_add_rule(struct connman_iptables *table, char *chain_name,
			char *target_name, int target_argc, char **target_argv,
			char *match_name, int match_argc, char **match_argv)
{
	GList *chain_tail;
	struct ipt_entry *new_entry;

	chain_tail = find_chain_tail(table, chain_name);
	if (chain_tail == NULL)
		return -EINVAL;

	printf("Chains found\n");

	new_entry = new_rule(target_name, target_argc, target_argv,
				match_name, match_argc, match_argv);
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

int main(int argc, char *argv[])
{
	struct ipt_replace *repl;
	struct connman_iptables *table;

	xtables_init();
	xtables_set_nfproto(NFPROTO_IPV4);

	table = connman_iptables_init("filter");
	if (table == NULL)
		return -1;

	connman_iptables_dump(table);

	if (argv[1]) {
		connman_iptables_add_chain(table, argv[1]);

		connman_iptables_add_rule(table, argv[1],
					"ACCEPT", 0, NULL,
					NULL, 0, NULL);

		repl = connman_iptables_blob(table);

		connman_iptables_replace(table, repl);
	}

	connman_iptables_cleanup(table);

	return 0;
}
