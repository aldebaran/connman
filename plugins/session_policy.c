/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2012  BMW Car IT GbmH. All rights reserved.
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
#include <string.h>

#include <glib.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/log.h>
#include <connman/session.h>

static GHashTable *config_hash;

static int policy_create(struct connman_session *session,
				connman_session_config_cb callback,
				void *user_data)
{
	struct connman_session_config *config;

	DBG("session %p", session);

	if (callback == NULL)
		return -EINVAL;

	config = connman_session_create_default_config();
	if (config == NULL)
		return -ENOMEM;

	g_hash_table_replace(config_hash, session, config);

	(*callback)(session, config, user_data, 0);

	return 0;
}

static void policy_destroy(struct connman_session *session)
{
	DBG("session %p", session);

	g_hash_table_remove(config_hash, session);
}

static struct connman_session_policy session_policy = {
	.name = "session policy configuration",
	.priority = CONNMAN_SESSION_POLICY_PRIORITY_LOW,
	.create = policy_create,
	.destroy = policy_destroy,
};

static int session_policy_init(void)
{
	int err;

	err = connman_session_policy_register(&session_policy);
	if (err < 0)
		return err;

	config_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
						g_free);
	if (config_hash == NULL) {
		connman_session_policy_unregister(&session_policy);
		return -ENOMEM;
	}

	return 0;
}

static void session_policy_exit(void)
{
	g_hash_table_destroy(config_hash);

	connman_session_policy_unregister(&session_policy);
}

CONNMAN_PLUGIN_DEFINE(session_policy, "Session policy configuration plugin",
		VERSION, CONNMAN_PLUGIN_PRIORITY_DEFAULT,
		session_policy_init, session_policy_exit)
