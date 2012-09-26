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

static struct connman_session_config *policy_create(
					struct connman_session *session)
{
	struct connman_session_config *config;

	DBG("session %p", session);

	config = g_try_new0(struct connman_session_config, 1);
	if (config == NULL)
		return NULL;

	config->priority = FALSE;
	config->roaming_policy = CONNMAN_SESSION_ROAMING_POLICY_DEFAULT;
	config->type = CONNMAN_SESSION_TYPE_ANY;
	config->ecall = FALSE;
	config->allowed_bearers = connman_session_allowed_bearers_any();
	if (config->allowed_bearers == NULL) {
		g_free(config);
		return NULL;
	}

	g_hash_table_replace(config_hash, session, config);

	return config;
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

static void cleanup_bearer(gpointer data, gpointer user_data)
{
	struct connman_session_bearer *info = data;

	g_free(info->name);
	g_free(info);
}

static void cleanup_config(gpointer user_data)
{
	struct connman_session_config *config = user_data;

	g_slist_foreach(config->allowed_bearers, cleanup_bearer, NULL);
	g_slist_free(config->allowed_bearers);
	g_free(config);
}

static int session_policy_init(void)
{
	int err;

	err = connman_session_policy_register(&session_policy);
	if (err < 0)
		return err;

	config_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
						cleanup_config);
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
