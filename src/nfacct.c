/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2013  BMW Car IT GmbH. All rights reserved.
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
#include <inttypes.h>

#include "connman.h"
#include "src/shared/nfacct.h"
#include "src/shared/util.h"

static struct nfacct_info *nfacct = NULL;

struct nfacct_rule {
	char *name;
	connman_nfacct_stats_cb_t cb;
	void *user_data;
};

struct nfacct_context {
	struct nfacct_info *nfacct;
	GList *rules;
	unsigned int pending;
	unsigned int error;
};

struct nfacct_flush {
	unsigned int pending;
	unsigned int error;
};

static void cleanup_nfacct_rule(gpointer user_data)
{
	struct nfacct_rule *rule = user_data;

	g_free(rule->name);
	g_free(rule);
}

struct nfacct_context *__connman_nfacct_create_context(void)
{
	struct nfacct_context *ctx;

	ctx = g_new0(struct nfacct_context, 1);

	return ctx;
}

void __connman_nfacct_destroy_context(struct nfacct_context *ctx)
{
	g_list_free_full(ctx->rules, cleanup_nfacct_rule);
	g_free(ctx);
}

int __connman_nfacct_add(struct nfacct_context *ctx, const char *name,
				connman_nfacct_stats_cb_t cb,
				void *user_data)
{
	struct nfacct_rule *rule = g_new0(struct nfacct_rule, 1);

	rule->name = g_strdup(name);
	rule->cb = cb;
	rule->user_data = user_data;

	ctx->rules = g_list_append(ctx->rules, rule);

	return 0;
}

static void nfacct_enable_failed_cb(unsigned int error, void *user_data)
{
	struct cb_data *cbd = user_data;
	connman_nfacct_enable_cb_t cb = cbd->cb;
	struct nfacct_context *ctx = cbd->data;

	DBG("");

	user_data = cbd->user_data;
	g_free(cbd);

	ctx->pending--;

	if (ctx->pending > 0)
		return;

	cb(ctx->error, ctx, user_data);
}

static void nfacct_handle_enable_error(struct nfacct_context *ctx,
					connman_nfacct_enable_cb_t cb,
					void *user_data)
{
	struct cb_data *cbd;
	struct nfacct_rule *rule;
	GList *list;
	unsigned int id;

	DBG("");

	for (list = ctx->rules; list; list = list->next) {
		rule = list->data;

		DBG("%s", rule->name);
		cbd = cb_data_new(cb, user_data);
		cbd->data = ctx;
		id = nfacct_del(nfacct, rule->name,
						nfacct_enable_failed_cb, cbd);
		if (id == 0) {
			g_free(cbd);
			continue;
		}

		ctx->pending++;
	}
}

static void nfacct_enable_cb(unsigned int error, void *user_data)
{
	struct cb_data *cbd = user_data;
	connman_nfacct_enable_cb_t cb = cbd->cb;
	struct nfacct_context *ctx = cbd->data;

	DBG("error %d pending %d", error, ctx->pending);

	user_data = cbd->user_data;
	g_free(cbd);

	ctx->pending--;

	if (error != 0)
		ctx->error = error;

	if (ctx->pending > 0)
		return;

	if (ctx->error != 0) {
		nfacct_handle_enable_error(ctx, cb, user_data);
		return;
	}

	cb(0, ctx, user_data);
}

static void nfacct_disable_cb(unsigned int error, void *user_data)
{
	struct cb_data *cbd = user_data;
	connman_nfacct_disable_cb_t cb = cbd->cb;
	struct nfacct_context *ctx = cbd->data;

	DBG("error %d pending %d", error, ctx->pending);

	user_data = cbd->user_data;
	g_free(cbd);

	ctx->pending--;

	if (error != 0)
		ctx->error = -error;

	if (ctx->pending > 0)
		return;

	cb(ctx->error, ctx, user_data);
}

int __connman_nfacct_enable(struct nfacct_context *ctx,
				connman_nfacct_enable_cb_t cb,
				void *user_data)
{
	struct cb_data *cbd = NULL;
	struct nfacct_rule *rule;
	GList *list;
	unsigned int id;

	DBG("");

	if (!nfacct)
		nfacct = nfacct_new();
	if (!nfacct)
		goto err;

	for (list = ctx->rules; list; list = list->next) {
		rule = list->data;

		DBG("%s", rule->name);

		cbd = cb_data_new(cb, user_data);
		cbd->data = ctx;
		id = nfacct_add(nfacct, rule->name, nfacct_enable_cb,
							cbd);
		if (id == 0)
			goto err;

		ctx->pending++;
	}

	return 0;

err:
	if (ctx->pending > 0) {
		ctx->error = -ECOMM;
		return 0;
	}

	g_free(cbd);

	return -ECOMM;
}

int __connman_nfacct_disable(struct nfacct_context *ctx,
				connman_nfacct_disable_cb_t cb,
				void *user_data)
{
	struct cb_data *cbd;
	struct nfacct_rule *rule;
	GList *list;
	unsigned int id;
	int err = 0;

	DBG("");

	for (list = ctx->rules; list; list = list->next) {
		rule = list->data;

		DBG("%s", rule->name);
		cbd = cb_data_new(cb, user_data);
		cbd->data = ctx;
		id = nfacct_del(nfacct, rule->name, nfacct_disable_cb,
							cbd);
		if (id == 0) {
			err = -ECOMM;
			g_free(cbd);
			continue;
		}

		ctx->pending++;
	}

	return err;
}

static void nfacct_flush_del_cb(unsigned int error, void *user_data)
{
	struct cb_data *cbd = user_data;
	struct nfacct_flush *nff = cbd->data;
	connman_nfacct_flush_cb_t cb = cbd->cb;

	DBG("error %d pending %d", error, nff->pending);

	nff->pending--;

	if (error != 0)
		nff->error = -error;

	/*
	 * Wait for all pending commands before calling
	 * the callback.
	 */
	if (nff->pending > 0)
		return;

	cb(nff->error, cbd->user_data);

	g_free(nff);
	g_free(cbd);
}

static void nfacct_flush_cb(unsigned int error, const char *name,
				uint64_t packets, uint64_t bytes,
				void *user_data)
{
	struct cb_data *cbd = user_data;
	struct nfacct_flush *nff = cbd->data;
	connman_nfacct_flush_cb_t cb = cbd->cb;
	unsigned int id;

	if (error != 0) {
		/*
		 * We will only be called once with an error and
		 * will be the first call.
		 */

		/*
		 * EINVAL tells us that there is no NFACCT sysbstem
		 * that means we are probably running on a pre 3.2
		 * kernel. Just ignore this.
		 */
		if (error != EINVAL)
			nff->error = -error;
		goto out;
	}

	if (!name) {
		/* last call */

		/*
		 * If we have one command pending, let that one
		 * report back the error.
		 */
		if (nff->pending > 0)
			return;

		/*
		 * Either all __connman_netfilter_acct_del() failed
		 * or the dump was empty. In both cases just
		 * call the cb.
		 */
		goto out;
	}

	DBG("name %s packets %" PRIu64 " bytes %" PRIu64, name, packets, bytes);

	if (!g_str_has_prefix(name, "session-"))
		return;

	id = nfacct_del(nfacct, name, nfacct_flush_del_cb, cbd);
	if (id == 0) {
		nff->error = -ECOMM;
		return;
	}

	nff->pending++;
	return;

out:
	cb(nff->error, cbd->user_data);

	g_free(nff);
	g_free(cbd);
}

int __connman_nfacct_flush(connman_nfacct_flush_cb_t cb, void *user_data)
{
	struct cb_data *cbd = cb_data_new(cb, user_data);
	struct nfacct_flush *nff = g_new0(struct nfacct_flush, 1);
	unsigned int id;

	DBG("nfacct %p", nfacct);

	if (nfacct) {
		cbd->data = nff;

		id = nfacct_dump(nfacct, false, nfacct_flush_cb, cbd);
		if (id > 0)
			return id;
	}

	g_free(nff);
	g_free(cbd);

	return -ECOMM;
}

void __connman_nfacct_cleanup(void)
{
	nfacct_destroy(nfacct);
	nfacct = NULL;
}
