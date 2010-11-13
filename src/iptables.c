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

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <xtables.h>

#include <linux/netfilter_ipv4/ip_tables.h>

#include "connman.h"


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
	int offset;
	int builtin;

	struct ipt_entry *entry;
};

struct connman_iptables {
	int ipt_sock;

	struct ipt_getinfo *info;
	struct ipt_get_entries *blob_entries;

	unsigned int num_entries;
	unsigned int old_entries;
	unsigned int size;

	unsigned int underflow[NF_INET_NUMHOOKS];
	unsigned int hook_entry[NF_INET_NUMHOOKS];

	GList *entries;
};

static GHashTable *table_hash = NULL;

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

static gboolean is_jump(struct connman_iptables_entry *e)
{
	struct xt_entry_target *target;

	target = ipt_get_target(e->entry);

	if (!strcmp(target->u.user.name, IPT_STANDARD_TARGET)) {
		struct xt_standard_target *t;

		t = (struct xt_standard_target *)target;

		switch (t->verdict) {
		case XT_RETURN:
		case -NF_ACCEPT - 1:
		case -NF_DROP - 1:
		case -NF_QUEUE - 1:
		case -NF_STOP - 1:
			return false;

		default:
			return true;
		}
	}

	return false;
}

static gboolean is_chain(struct connman_iptables *table,
				struct connman_iptables_entry *e)
{
	struct ipt_entry *entry;
	struct xt_entry_target *target;

	entry = e->entry;
	if (e->builtin >= 0)
		return TRUE;

	target = ipt_get_target(entry);
	if (!strcmp(target->u.user.name, IPT_ERROR_TARGET))
		return TRUE;

	return FALSE;
}

static GList *find_chain_head(struct connman_iptables *table,
				char *chain_name)
{
	GList *list;
	struct connman_iptables_entry *head;
	struct ipt_entry *entry;
	struct xt_entry_target *target;
	int builtin;

	for (list = table->entries; list; list = list->next) {
		head = list->data;
		entry = head->entry;

		/* Buit-in chain */
		builtin = head->builtin;
		if (builtin >= 0 && !strcmp(hooknames[builtin], chain_name))
			break;

		/* User defined chain */
		target = ipt_get_target(entry);
		if (!strcmp(target->u.user.name, IPT_ERROR_TARGET) &&
		    !strcmp((char *)target->data, chain_name))
			break;
	}

	return list;
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
		builtin = head->builtin;
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


static void update_offsets(struct connman_iptables *table)
{
	GList *list, *prev;
	struct connman_iptables_entry *entry, *prev_entry;

	for (list = table->entries; list; list = list->next) {
		entry = list->data;

		if (list == table->entries) {
			entry->offset = 0;

			continue;
		}

		prev = list->prev;
		prev_entry = prev->data;

		entry->offset = prev_entry->offset +
					prev_entry->entry->next_offset;
	}
}

static int iptables_add_entry(struct connman_iptables *table,
				struct ipt_entry *entry, GList *before,
					int builtin)
{
	GList *list;
	struct connman_iptables_entry *e, *tmp, *entry_before;
	struct xt_standard_target *t;

	if (table == NULL)
		return -1;

	e = g_try_malloc0(sizeof(struct connman_iptables_entry));
	if (e == NULL)
		return -1;

	e->entry = entry;
	e->builtin = builtin;

	table->entries = g_list_insert_before(table->entries, before, e);
	table->num_entries++;
	table->size += entry->next_offset;

	if (before == NULL) {
		e->offset = table->size - entry->next_offset;

		return 0;
	}

	entry_before = before->data;

	/*
	 * We've just insterted a new entry. All references before it
	 * should be bumped accordingly.
	 */
	for (list = table->entries; list != before; list = list->next) {
		tmp = list->data;

		if (!is_jump(tmp))
			continue;

		t = (struct xt_standard_target *)ipt_get_target(tmp->entry);

		if (t->verdict >= entry_before->offset)
			t->verdict += entry->next_offset;
	}

	update_offsets(table);

	return 0;
}

static int iptables_flush_chain(struct connman_iptables *table,
						char *name)
{
	GList *chain_head, *chain_tail, *list, *next;
	struct connman_iptables_entry *entry;
	int builtin, removed = 0;

	chain_head = find_chain_head(table, name);
	if (chain_head == NULL)
		return -EINVAL;

	chain_tail = find_chain_tail(table, name);
	if (chain_tail == NULL)
		return -EINVAL;

	entry = chain_head->data;
	builtin = entry->builtin;

	if (builtin >= 0)
		list = chain_head;
	else
		list = chain_head->next;

	if (list == chain_tail->prev)
		return 0;

	while (list != chain_tail->prev) {
		entry = list->data;
		next = g_list_next(list);

		table->num_entries--;
		table->size -= entry->entry->next_offset;
		removed += entry->entry->next_offset;

		g_free(entry->entry);

		table->entries = g_list_remove(table->entries, list->data);

		list = next;
	}

	if (builtin >= 0) {
		struct connman_iptables_entry *e;

		entry = list->data;

		entry->builtin = builtin;

		table->underflow[builtin] -= removed;

		for (list = chain_tail; list; list = list->next) {
			e = list->data;

			builtin = e->builtin;
			if (builtin < 0)
				continue;

			table->hook_entry[builtin] -= removed;
			table->underflow[builtin] -= removed;
		}
	}

	update_offsets(table);

	return 0;
}

static int iptables_add_chain(struct connman_iptables *table,
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

	if (iptables_add_entry(table, entry_head, last, -1) < 0)
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

	if (iptables_add_entry(table, entry_return, last, -1) < 0)
		goto err;

	return 0;

err:
	g_free(entry_head);
	g_free(entry_return);

	return -ENOMEM;
}

static struct ipt_entry *
new_rule(struct connman_iptables *table, struct ipt_ip *ip,
		char *target_name, struct xtables_target *xt_t,
		char *match_name, struct xtables_match *xt_m)
{
	struct ipt_entry *new_entry;
	size_t match_size, target_size;
	int is_builtin = is_builtin_target(target_name);

	if (xt_m)
		match_size = xt_m->m->u.match_size;
	else
		match_size = 0;

	if (xt_t)
		target_size = ALIGN(xt_t->t->u.target_size);
	else
		target_size = ALIGN(sizeof(struct xt_standard_target));

	new_entry = g_try_malloc0(sizeof(struct ipt_entry) + target_size +
								match_size);
	if (new_entry == NULL)
		return NULL;

	memcpy(&new_entry->ip, ip, sizeof(struct ipt_ip));

	new_entry->target_offset = sizeof(struct ipt_entry) + match_size;
	new_entry->next_offset = sizeof(struct ipt_entry) + target_size +
								match_size;
	if (xt_m) {
		struct xt_entry_match *entry_match;

		entry_match = (struct xt_entry_match *)new_entry->elems;
		memcpy(entry_match, xt_m->m, match_size);
	}

	if (xt_t) {
		struct xt_entry_target *entry_target;

		if (is_builtin) {
			struct xt_standard_target *target;

			target = (struct xt_standard_target *)(xt_t->t);
			strcpy(target->target.u.user.name, IPT_STANDARD_TARGET);
			target->verdict = target_to_verdict(target_name);
		}

		entry_target = ipt_get_target(new_entry);
		memcpy(entry_target, xt_t->t, target_size);
	} else {
		struct connman_iptables_entry *target_rule;
		struct xt_standard_target *target;
		GList *chain_head;

		/*
		 * This is a user defined target, i.e. a chain jump.
		 * We search for the chain head, and the target verdict
		 * is the first rule's offset on this chain.
		 * The offset is from the beginning of the table.
		 */

		chain_head = find_chain_head(table, target_name);
		if (chain_head == NULL || chain_head->next == NULL) {
			g_free(new_entry);
			return NULL;
		}

		target_rule = chain_head->next->data;

		target = (struct xt_standard_target *)ipt_get_target(new_entry);
		strcpy(target->target.u.user.name, IPT_STANDARD_TARGET);
		target->target.u.user.target_size = target_size;
		target->verdict = target_rule->offset;
	}

	return new_entry;
}

static void update_hooks(struct connman_iptables *table, GList *chain_head,
				struct ipt_entry *entry)
{
	GList *list;
	struct connman_iptables_entry *head, *e;
	int builtin;

	if (chain_head == NULL)
		return;

	head = chain_head->data;

	builtin = head->builtin;
	if (builtin < 0)
		return;

	table->underflow[builtin] += entry->next_offset;

	for (list = chain_head->next; list; list = list->next) {
		e = list->data;

		builtin = e->builtin;
		if (builtin < 0)
			continue;

		table->hook_entry[builtin] += entry->next_offset;
		table->underflow[builtin] += entry->next_offset;
	}
}

static int
iptables_add_rule(struct connman_iptables *table,
				struct ipt_ip *ip, char *chain_name,
				char *target_name, struct xtables_target *xt_t,
				char *match_name, struct xtables_match *xt_m)
{
	GList *chain_tail, *chain_head;
	struct ipt_entry *new_entry;
	struct connman_iptables_entry *head;
	int builtin = -1;

	DBG("");

	chain_head = find_chain_head(table, chain_name);
	if (chain_head == NULL)
		return -EINVAL;

	chain_tail = find_chain_tail(table, chain_name);
	if (chain_tail == NULL)
		return -EINVAL;

	new_entry = new_rule(table, ip,
				target_name, xt_t,
				match_name, xt_m);
	if (new_entry == NULL)
		return -EINVAL;

	update_hooks(table, chain_head, new_entry);

	/*
	 * If the chain is builtin, and does not have any rule,
	 * then the one that we're inserting is becoming the head
	 * and thus needs the builtin flag.
	 */
	head = chain_head->data;
	if (head->builtin < 0)
		builtin = -1;
	else if (chain_head == chain_tail->prev) {
		builtin = head->builtin;
		head->builtin = -1;
	}

	return iptables_add_entry(table, new_entry, chain_tail->prev, builtin);
}

static struct ipt_replace *
iptables_blob(struct connman_iptables *table)
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
				* table->old_entries);
	if (r->counters == NULL) {
		g_free(r);
		return NULL;
	}

	strcpy(r->name, table->info->name);
	r->num_entries = table->num_entries;
	r->size = table->size;

	r->num_counters = table->old_entries;
	r->valid_hooks  = table->info->valid_hooks;

	memcpy(r->hook_entry, table->hook_entry, sizeof(table->hook_entry));
	memcpy(r->underflow, table->underflow, sizeof(table->underflow));

	entry_index = (unsigned char *)r->entries;
	for (list = table->entries; list; list = list->next) {
		e = list->data;

		memcpy(entry_index, e->entry, e->entry->next_offset);
		entry_index += e->entry->next_offset;
	}

	return r;
}

static void dump_ip(struct ipt_entry *entry)
{
	struct ipt_ip *ip = &entry->ip;
	char ip_string[INET6_ADDRSTRLEN];
	char ip_mask[INET6_ADDRSTRLEN];

	if (strlen(ip->iniface))
		connman_info("\tin %s", ip->iniface);

	if (strlen(ip->outiface))
		connman_info("\tout %s", ip->outiface);

	if (inet_ntop(AF_INET, &ip->src, ip_string, INET6_ADDRSTRLEN) != NULL &&
			inet_ntop(AF_INET, &ip->smsk,
					ip_mask, INET6_ADDRSTRLEN) != NULL)
		connman_info("\tsrc %s/%s", ip_string, ip_mask);

	if (inet_ntop(AF_INET, &ip->dst, ip_string, INET6_ADDRSTRLEN) != NULL &&
			inet_ntop(AF_INET, &ip->dmsk,
					ip_mask, INET6_ADDRSTRLEN) != NULL)
		connman_info("\tdst %s/%s", ip_string, ip_mask);
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
			connman_info("\ttarget RETURN");
			break;

		case -NF_ACCEPT - 1:
			connman_info("\ttarget ACCEPT");
			break;

		case -NF_DROP - 1:
			connman_info("\ttarget DROP");
			break;

		case -NF_QUEUE - 1:
			connman_info("\ttarget QUEUE");
			break;

		case -NF_STOP - 1:
			connman_info("\ttarget STOP");
			break;

		default:
			connman_info("\tJUMP @%p (0x%x)",
				(char*)table->blob_entries->entrytable +
				t->verdict, t->verdict);
			break;
		}

		xt_t = xtables_find_target(IPT_STANDARD_TARGET,
						XTF_LOAD_MUST_SUCCEED);

		if(xt_t->print != NULL)
			xt_t->print(NULL, target, 1);
	} else {
		xt_t = xtables_find_target(target->u.user.name, XTF_TRY_LOAD);
		if (xt_t == NULL) {
			connman_info("\ttarget %s", target->u.user.name);
			return;
		}

		if(xt_t->print != NULL) {
			connman_info("\ttarget ");
			xt_t->print(NULL, target, 1);
		}
	}
}

static void dump_match(struct connman_iptables *table, struct ipt_entry *entry)
{
	struct xtables_match *xt_m;
	struct xt_entry_match *match;

	if (entry->elems == (unsigned char *)entry + entry->target_offset)
		return;

	match = (struct xt_entry_match *) entry->elems;

	if (!strlen(match->u.user.name))
		return;

	xt_m = xtables_find_match(match->u.user.name, XTF_TRY_LOAD, NULL);
	if (xt_m == NULL)
		goto out;

	if(xt_m->print != NULL) {
		connman_info("\tmatch ");
		xt_m->print(NULL, match, 1);

		return;
	}

out:
	connman_info("\tmatch %s", match->u.user.name);

}

static int dump_entry(struct ipt_entry *entry,
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
		connman_info("End of CHAIN 0x%x", offset);
		return 0;
	}

	if (!strcmp(target->u.user.name, IPT_ERROR_TARGET)) {
		connman_info("USER CHAIN (%s) %p  match %p  target %p  size %d",
			target->data, entry, entry->elems,
			(char *)entry + entry->target_offset,
				entry->next_offset);

		return 0;
	} else if (builtin >= 0) {
		connman_info("CHAIN (%s) %p  match %p  target %p  size %d",
			hooknames[builtin], entry, entry->elems,
			(char *)entry + entry->target_offset,
				entry->next_offset);
	} else {
		connman_info("RULE %p  match %p  target %p  size %d", entry,
			entry->elems,
			(char *)entry + entry->target_offset,
				entry->next_offset);
	}

	dump_match(table, entry);
	dump_target(table, entry);
	dump_ip(entry);

	return 0;
}

static void iptables_dump(struct connman_iptables *table)
{
	connman_info("%s valid_hooks=0x%08x, num_entries=%u, size=%u",
			table->info->name,
			table->info->valid_hooks, table->info->num_entries,
				table->info->size);

	ENTRY_ITERATE(table->blob_entries->entrytable,
			table->blob_entries->size,
			dump_entry, table);

}

static int iptables_get_entries(struct connman_iptables *table)
{
	socklen_t entry_size;

	entry_size = sizeof(struct ipt_get_entries) + table->info->size;

	return getsockopt(table->ipt_sock, IPPROTO_IP, IPT_SO_GET_ENTRIES,
				table->blob_entries, &entry_size);
}

static int iptables_replace(struct connman_iptables *table,
					struct ipt_replace *r)
{
	return setsockopt(table->ipt_sock, IPPROTO_IP, IPT_SO_SET_REPLACE, r,
			 sizeof(*r) + r->size);
}

static int add_entry(struct ipt_entry *entry, struct connman_iptables *table)
{
	struct ipt_entry *new_entry;
	int builtin;

	new_entry = g_try_malloc0(entry->next_offset);
	if (new_entry == NULL)
		return -ENOMEM;

	memcpy(new_entry, entry, entry->next_offset);

	builtin = is_hook_entry(table, entry);

	return iptables_add_entry(table, new_entry, NULL, builtin);
}

static void table_cleanup(struct connman_iptables *table)
{
	GList *list;
	struct connman_iptables_entry *entry;

	close(table->ipt_sock);

	for (list = table->entries; list; list = list->next) {
		entry = list->data;

		g_free(entry->entry);
	}

	g_list_free(table->entries);
	g_free(table->info);
	g_free(table->blob_entries);
	g_free(table);
}

static struct connman_iptables *iptables_init(char *table_name)
{
	struct connman_iptables *table;
	socklen_t s;

	DBG("%s", table_name);

	table = g_hash_table_lookup(table_hash, table_name);
	if (table != NULL)
		return table;

	table = g_try_new0(struct connman_iptables, 1);
	if (table == NULL)
		return NULL;

	table->info = g_try_new0(struct ipt_getinfo, 1);
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

	if (iptables_get_entries(table) < 0)
		goto err;

	table->num_entries = 0;
	table->old_entries = table->info->num_entries;
	table->size = 0;

	memcpy(table->underflow, table->info->underflow,
				sizeof(table->info->underflow));
	memcpy(table->hook_entry, table->info->hook_entry,
				sizeof(table->info->hook_entry));

	ENTRY_ITERATE(table->blob_entries->entrytable,
			table->blob_entries->size,
				add_entry, table);

	g_hash_table_insert(table_hash, g_strdup(table_name), table);

	return table;

err:

	table_cleanup(table);

	return NULL;
}

static struct option iptables_opts[] = {
	{.name = "append",        .has_arg = 1, .val = 'A'},
	{.name = "flush-chain",   .has_arg = 1, .val = 'F'},
	{.name = "list",          .has_arg = 2, .val = 'L'},
	{.name = "new-chain",     .has_arg = 1, .val = 'N'},
	{.name = "destination",   .has_arg = 1, .val = 'd'},
	{.name = "in-interface",  .has_arg = 1, .val = 'i'},
	{.name = "jump",          .has_arg = 1, .val = 'j'},
	{.name = "match",         .has_arg = 1, .val = 'm'},
	{.name = "out-interface", .has_arg = 1, .val = 'o'},
	{.name = "source",        .has_arg = 1, .val = 's'},
	{.name = "table",         .has_arg = 1, .val = 't'},
	{NULL},
};

struct xtables_globals iptables_globals = {
	.option_offset = 0,
	.opts = iptables_opts,
	.orig_opts = iptables_opts,
};

static int iptables_command(int argc, char *argv[])
{
	struct connman_iptables *table;
	struct xtables_match *xt_m;
	struct xtables_target *xt_t;
	struct ipt_ip ip;
	char *table_name, *chain, *new_chain, *match_name, *target_name;
	char *flush_chain;
	int c, ret, in_len, out_len;
	size_t size;
	gboolean dump, invert;
	struct in_addr src, dst;

	if (argc == 0)
		return -EINVAL;

	dump = FALSE;
	invert = FALSE;
	table_name = chain = new_chain = match_name = target_name = NULL;
	flush_chain = NULL;
	memset(&ip, 0, sizeof(struct ipt_ip));
	table = NULL;
	xt_m = NULL;
	xt_t = NULL;
	ret = 0;

	optind = 0;

	while ((c = getopt_long(argc, argv,
	   "-A:F:L::N:d:j:i:m:o:s:t:", iptables_globals.opts, NULL)) != -1) {
		switch (c) {
		case 'A':
			chain = optarg;
			break;

		case 'F':
			flush_chain = optarg;
			break;

		case 'L':
			dump = TRUE;
			break;

		case 'N':
			new_chain = optarg;
			break;

		case 'd':
			if (!inet_pton(AF_INET, optarg, &dst))
				break;

			ip.dst = dst;
			inet_pton(AF_INET, "255.255.255.255", &ip.dmsk);

			if (invert)
				ip.invflags |= IPT_INV_DSTIP;

			break;

		case 'i':
			in_len = strlen(optarg);

			if (in_len + 1 > IFNAMSIZ)
				break;

			strcpy(ip.iniface, optarg);
			memset(ip.iniface_mask, 0xff, in_len + 1);

			if (invert)
				ip.invflags |= IPT_INV_VIA_IN;

			break;

		case 'j':
			target_name = optarg;
			xt_t = xtables_find_target(target_name, XTF_TRY_LOAD);

			if (xt_t == NULL)
				break;

			size = ALIGN(sizeof(struct ipt_entry_target)) +
								xt_t->size;

			xt_t->t = g_try_malloc0(size);
			if (xt_t->t == NULL)
				goto out;
			xt_t->t->u.target_size = size;
			strcpy(xt_t->t->u.user.name, target_name);
			xt_t->t->u.user.revision = xt_t->revision;
			if (xt_t->init != NULL)
				xt_t->init(xt_t->t);
			iptables_globals.opts =
				xtables_merge_options(iptables_globals.opts,
						     xt_t->extra_opts,
						     &xt_t->option_offset);
			if (iptables_globals.opts == NULL)
				goto out;

			break;

		case 'm':
			match_name = optarg;

			xt_m = xtables_find_match(optarg, XTF_LOAD_MUST_SUCCEED, NULL);
			size = ALIGN(sizeof(struct ipt_entry_match)) +
								xt_m->size;
			xt_m->m = g_try_malloc0(size);
			if (xt_m == NULL)
				goto out;
			xt_m->m->u.match_size = size;
			strcpy(xt_m->m->u.user.name, xt_m->name);
			xt_m->m->u.user.revision = xt_m->revision;
			if (xt_m->init != NULL)
				xt_m->init(xt_m->m);
			if (xt_m != xt_m->next) {
				iptables_globals.opts =
				xtables_merge_options(iptables_globals.opts,
						xt_m->extra_opts,
						&xt_m->option_offset);
				if (iptables_globals.opts == NULL)
					goto out;
			}

			break;

		case 'o':
			out_len = strlen(optarg);

			if (out_len + 1 > IFNAMSIZ)
				break;

			strcpy(ip.outiface, optarg);
			memset(ip.outiface_mask, 0xff, out_len + 1);

			if (invert)
				ip.invflags |= IPT_INV_VIA_OUT;

			break;

		case 's':
			if (!inet_pton(AF_INET, optarg, &src))
				break;

			ip.src = src;
			inet_pton(AF_INET, "255.255.255.255", &ip.smsk);

			if (invert)
				ip.invflags |= IPT_INV_SRCIP;

			break;

		case 't':
			table_name = optarg;
			break;

		case 1:
			if (optarg[0] == '!' && optarg[1] == '\0') {
				invert = TRUE;
				optarg[0] = '\0';
				continue;
			}

			connman_error("Invalid option");

			ret = -EINVAL;
			goto out;

		default:
			if (xt_t == NULL || xt_t->parse == NULL ||
			    !xt_t->parse(c - xt_t->option_offset, argv, invert,
					&xt_t->tflags, NULL, &xt_t->t)) {
				if (xt_m == NULL || xt_m->parse == NULL)
					break;

				xt_m->parse(c - xt_m->option_offset, argv,
					invert, &xt_m->mflags, NULL, &xt_m->m);
			}

			break;
		}

		invert = FALSE;
	}

	if (table_name == NULL)
		table_name = "filter";

	table = iptables_init(table_name);
	if (table == NULL) {
		ret = -EINVAL;
		goto out;
	}

	if (dump) {
		iptables_dump(table);

		ret = 0;
		goto out;
	}

	if (flush_chain) {
		DBG("Flush chain %s", flush_chain);

		iptables_flush_chain(table, flush_chain);

		goto out;
	}

	if (chain && new_chain) {
		ret = -EINVAL;
		goto out;
	}

	if (new_chain) {
		DBG("New chain %s", new_chain);

		ret = iptables_add_chain(table, new_chain);
		goto out;
	}

	if (chain) {
		if (target_name == NULL)
			return -1;

		DBG("Adding %s to %s (match %s)",
				target_name, chain, match_name);

		ret = iptables_add_rule(table, &ip, chain, target_name, xt_t,
					match_name, xt_m);

		goto out;
	}

out:
	if (xt_t)
		g_free(xt_t->t);

	if (xt_m)
		g_free(xt_m->m);

	return ret;
}

int __connman_iptables_command(const char *format, ...)
{
	char **argv, **arguments, *command;
	int argc, i, ret;
	va_list args;

	if (format == NULL)
		return -EINVAL;

	va_start(args, format);

	command = g_strdup_vprintf(format, args);

	va_end(args);

	if (command == NULL)
		return -ENOMEM;

	arguments = g_strsplit_set(command, " ", -1);

	for (argc = 0; arguments[argc]; argc++);
	++argc;

	DBG("command %s argc %d", command, argc);

	argv = g_try_malloc0(argc * sizeof(char *));
	if (argv == NULL) {
		g_free(command);
		g_strfreev(arguments);
		return -ENOMEM;
	}

	argv[0] = "iptables";
	for (i = 1; i < argc; i++)
		argv[i] = arguments[i - 1];

	ret = iptables_command(argc, argv);

	g_free(command);
	g_strfreev(arguments);
	g_free(argv);

	return ret;
}


int __connman_iptables_commit(const char *table_name)
{
	struct connman_iptables *table;
	struct ipt_replace *repl;

	DBG("%s", table_name);

	table = g_hash_table_lookup(table_hash, table_name);
	if (table == NULL)
		return -EINVAL;

	repl = iptables_blob(table);

	return iptables_replace(table, repl);
}

static void remove_table(gpointer user_data)
{
	struct connman_iptables *table = user_data;

	table_cleanup(table);
}

int __connman_iptables_init(void)
{
	DBG("");

	table_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						g_free, remove_table);

	xtables_init_all(&iptables_globals, NFPROTO_IPV4);

	return 0;

}

void __connman_iptables_cleanup(void)
{
	g_hash_table_destroy(table_hash);

	xtables_free_opts(1);
}
