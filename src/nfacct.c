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

#include "connman.h"
#include "src/shared/nfacct.h"

static struct nfacct_info *nfacct;

struct nfacct_flush {
	unsigned int pending;
	int error;
};

static void nfacct_flush_del_cb(int error, void *user_data)
{
	struct cb_data *cbd = user_data;
	struct nfacct_flush *nff = cbd->data;
	connman_nfacct_flush_cb_t cb = cbd->cb;

	DBG("error %d pending %d", error, nff->pending);

	nff->pending--;

	if (error < 0)
		nff->error = error;

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

static void nfacct_flush_cb(int error, const char *name,
				uint64_t packets, uint64_t bytes,
				void *user_data)
{
	struct cb_data *cbd = user_data;
	struct nfacct_flush *nff = cbd->data;
	connman_nfacct_flush_cb_t cb = cbd->cb;
	unsigned int id;

	DBG("name %s packets %lu bytes %lu", name, packets, bytes);

	if (error < 0) {
		/*
		 * We will only be called once with an error and
		 * will be the first call.
		 */
		nff->error = error;
		goto out;
	}

	if (name == NULL) {
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

	if (g_str_has_prefix(name, "session-") == FALSE)
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

	DBG("");

	cbd->data = nff;

	id = nfacct_dump(nfacct, false, nfacct_flush_cb, cbd);
	if (id > 0)
		return id;

	g_free(nff);
	g_free(cbd);

	return -ECOMM;
}

int __connman_nfacct_init(void)
{
	DBG("");

	nfacct = nfacct_new();
	if (nfacct == NULL)
		return -ENOMEM;

	return 0;
}

void __connman_nfacct_cleanup(void)
{
	nfacct_destroy(nfacct);
	nfacct = NULL;
}
