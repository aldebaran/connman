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

#include <glib.h>

#include <gdbus.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/log.h>
#include <connman/session.h>
#include <connman/dbus.h>

static DBusConnection *connection;

static GHashTable *policy_hash;
static GHashTable *session_hash;

struct create_data {
	struct connman_session *session;
	connman_session_config_cb callback;
	void *user_data;
};

struct policy_data {
	int refcount;
	char *ident;

	struct connman_session *session;
	struct connman_session_config *config;
};

static void cleanup_policy(gpointer user_data)
{
	struct policy_data *policy = user_data;

	if (policy->config != NULL)
		g_slist_free(policy->config->allowed_bearers);

	g_free(policy->ident);
	g_free(policy->config);
	g_free(policy);
}

static char *parse_ident(const unsigned char *context)
{
	char *str, *ident, **tokens;

	/*
	 * SELinux combines Role-Based Access Control (RBAC), Type
	 * Enforcment (TE) and optionally Multi-Level Security (MLS).
	 *
	 * When SELinux is enabled all processes and files are labeled
	 * with a contex that contains information such as user, role
	 * type (and optionally a level). E.g.
	 *
	 * $ ls -Z
	 * -rwxrwxr-x. wagi wagi unconfined_u:object_r:haifux_exec_t:s0 session_ui.py
	 *
	 * For identifyng application we (ab)using the type
	 * information. In the above example the haifux_exec_t type
	 * will be transfered to haifux_t as defined in the domain
	 * transition and thus we are able to identify the application
	 * as haifux_t.
	 */

	str = g_strdup((const gchar*)context);
	if (str == NULL)
		return NULL;

	DBG("SELinux context %s", str);

	tokens = g_strsplit(str, ":", 0);
	if (tokens == NULL) {
		g_free(str);
		return NULL;
	}

	/* Use the SELinux type as identification token. */
	ident = g_strdup(tokens[2]);

	g_strfreev(tokens);
	g_free(str);

	return ident;
}

static struct policy_data *create_policy(const char *ident)
{
	struct policy_data *policy;

	DBG("ident %s", ident);

	policy = g_try_new0(struct policy_data, 1);
	if (policy == NULL)
		return NULL;

	policy->config = connman_session_create_default_config();
	if (policy->config == NULL) {
		g_free(policy);
		return NULL;
	}

	policy->refcount = 1;
	policy->ident = g_strdup(ident);

	g_hash_table_replace(policy_hash, policy->ident, policy);

	return policy;
}

static struct policy_data *policy_ref(struct policy_data *policy)
{
	DBG("%p %s ref %d", policy, policy->ident, policy->refcount + 1);

	__sync_fetch_and_add(&policy->refcount, 1);

	return policy;
}

static void policy_unref(struct policy_data *policy)
{
	DBG(" %p %s ref %d", policy, policy->ident, policy->refcount - 1);

	if (__sync_fetch_and_sub(&policy->refcount, 1) != 1)
		return;

	g_hash_table_remove(policy_hash, policy->ident);
};

static void selinux_context_reply(const unsigned char *context, void *user_data,
					int err)
{
	struct create_data *data = user_data;
	struct policy_data *policy;
	struct connman_session_config *config = NULL;
	char *ident;

	DBG("session %p", data->session);

	if (err < 0)
		goto done;

	ident = parse_ident(context);
	if (ident == NULL) {
		err = -EINVAL;
		goto done;
	}

	policy = create_policy(ident);
	if (policy == NULL) {
		err = -ENOMEM;
		goto done;
	}

	g_hash_table_replace(session_hash, data->session, policy);
	config = policy->config;

done:
	(*data->callback)(data->session, config, data->user_data, err);

	g_free(data);
	g_free(ident);
}

static int policy_ivi_create(struct connman_session *session,
				connman_session_config_cb callback,
				void *user_data)
{
	struct create_data *data;
	const char *owner;
	int err;

	DBG("session %p", session);

	data = g_try_new0(struct create_data, 1);
	if (data == NULL)
		return -ENOMEM;

	data->session = session;
	data->callback = callback;
	data->user_data = user_data;

	owner = connman_session_get_owner(session);

	err = connman_dbus_get_selinux_context(connection, owner,
					selinux_context_reply,
					data);
	if (err < 0) {
		connman_error("Could not get SELinux context");
		g_free(data);
		return err;
	}

	return 0;
}

static void policy_ivi_destroy(struct connman_session *session)
{
	struct policy_data *policy;

	DBG("session %p", session);

	policy = g_hash_table_lookup(session_hash, session);
	g_hash_table_remove(session_hash, session);

	policy_unref(policy);
}

static struct connman_session_policy session_policy_ivi = {
	.name = "session ivi policy configuration",
	.priority = CONNMAN_SESSION_POLICY_PRIORITY_DEFAULT,
	.create = policy_ivi_create,
	.destroy = policy_ivi_destroy,
};

static int session_policy_ivi_init(void)
{
	int err;

	connection = connman_dbus_get_connection();
	if (connection == NULL)
		return -EIO;

	err = connman_session_policy_register(&session_policy_ivi);
	if (err < 0) {
		dbus_connection_unref(connection);
		return err;
	}

	session_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal,
						NULL, NULL);
	if (session_hash == NULL) {
		err = -ENOMEM;
		goto err;
	}

	policy_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
					NULL, cleanup_policy);
	if (policy_hash == NULL) {
		err = -ENOMEM;
		goto err;
	}

	return 0;

err:
	if (session_hash != NULL)
		g_hash_table_destroy(session_hash);
	if (policy_hash != NULL)
		g_hash_table_destroy(policy_hash);

	connman_session_policy_unregister(&session_policy_ivi);

	dbus_connection_unref(connection);

	return err;
}

static void session_policy_ivi_exit(void)
{
	g_hash_table_destroy(session_hash);
	g_hash_table_destroy(policy_hash);

	connman_session_policy_unregister(&session_policy_ivi);

	dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE(session_policy_ivi,
		"Session IVI policy configuration plugin",
		VERSION, CONNMAN_PLUGIN_PRIORITY_DEFAULT,
		session_policy_ivi_init, session_policy_ivi_exit)
