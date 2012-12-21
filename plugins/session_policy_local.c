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
#include <sys/inotify.h>
#include <sys/stat.h>

#include <glib.h>

#include <gdbus.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/log.h>
#include <connman/session.h>
#include <connman/dbus.h>
#include <connman/inotify.h>

#define POLICYDIR STORAGEDIR "/session_policy_local"

#define MODE		(S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | \
			S_IXGRP | S_IROTH | S_IXOTH)

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
	char *ident = NULL;

	DBG("session %p", data->session);

	if (err < 0)
		goto done;

	ident = parse_ident(context);
	if (ident == NULL) {
		err = -EINVAL;
		goto done;
	}

	policy = g_hash_table_lookup(policy_hash, ident);
	if (policy != NULL) {
		policy_ref(policy);
		policy->session = data->session;
	} else {
		policy = create_policy(ident);
		if (policy == NULL) {
			err = -ENOMEM;
			goto done;
		}
	}

	g_hash_table_replace(session_hash, data->session, policy);
	config = policy->config;

done:
	(*data->callback)(data->session, config, data->user_data, err);

	g_free(data);
	g_free(ident);
}

static int policy_local_create(struct connman_session *session,
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

static void policy_local_destroy(struct connman_session *session)
{
	struct policy_data *policy;

	DBG("session %p", session);

	policy = g_hash_table_lookup(session_hash, session);
	if (policy == NULL)
		return;

	g_hash_table_remove(session_hash, session);
	policy->session = NULL;
	policy_unref(policy);
}

static struct connman_session_policy session_policy_local = {
	.name = "session local policy configuration",
	.priority = CONNMAN_SESSION_POLICY_PRIORITY_DEFAULT,
	.create = policy_local_create,
	.destroy = policy_local_destroy,
};

static int load_keyfile(const char *pathname, GKeyFile **keyfile)
{
	GError *error = NULL;
	int err;

	DBG("Loading %s", pathname);

	*keyfile = g_key_file_new();

	if (g_key_file_load_from_file(*keyfile, pathname, 0, &error) == FALSE)
		goto err;

	return 0;

err:
	/*
	 * The fancy G_FILE_ERROR_* codes are identical to the native
	 * error codes.
	 */
	err = -error->code;

	DBG("Unable to load %s: %s", pathname, error->message);
	g_clear_error(&error);

	g_key_file_free(*keyfile);
	*keyfile = NULL;

	return err;
}

static int load_policy(struct policy_data *policy)
{
	struct connman_session_config *config = policy->config;
	GKeyFile *keyfile;
	char *pathname;
	char *str, **tokens;
	int i, err = 0;

	pathname = g_strdup_printf("%s/%s", POLICYDIR, policy->ident);
	if(pathname == NULL)
		return -ENOMEM;

	err = load_keyfile(pathname, &keyfile);
	if (err < 0) {
		g_free(pathname);

		if (err == -ENOENT) {
			/* Ignore empty files */
			return 0;
		}

		return err;
	}

	config->priority = g_key_file_get_boolean(keyfile, "Default",
						"Priority", NULL);

	str = g_key_file_get_string(keyfile, "Default", "RoamingPolicy",
				NULL);
	if (str != NULL) {
		config->roaming_policy = connman_session_parse_roaming_policy(str);
		g_free(str);
	} else {
		config->roaming_policy = CONNMAN_SESSION_ROAMING_POLICY_DEFAULT;
	}

	str = g_key_file_get_string(keyfile, "Default", "ConnectionType",
				NULL);
	if (str != NULL) {
		config->type = connman_session_parse_connection_type(str);
		g_free(str);
	} else {
		config->type = CONNMAN_SESSION_TYPE_ANY;
	}

	config->ecall = g_key_file_get_boolean(keyfile, "Default",
						"EmergencyCall", NULL);

	g_slist_free(config->allowed_bearers);
	config->allowed_bearers = NULL;

	str = g_key_file_get_string(keyfile, "Default", "AllowedBearers",
				NULL);

	if (str != NULL) {
		tokens = g_strsplit(str, " ", 0);

		for (i = 0; tokens[i] != NULL; i++) {
			err = connman_session_parse_bearers(tokens[i],
					&config->allowed_bearers);
			if (err < 0)
				break;
		}

		g_free(str);
		g_strfreev(tokens);
	} else {
		config->allowed_bearers = g_slist_append(NULL,
				GINT_TO_POINTER(CONNMAN_SERVICE_TYPE_UNKNOWN));
		if (config->allowed_bearers == NULL)
			err = -ENOMEM;
	}

	g_key_file_free(keyfile);
	g_free(pathname);

	return err;
}

static void update_session(struct connman_session *session)
{
	if (connman_session_config_update(session) < 0)
		connman_session_destroy(session);
}

static void remove_policy(struct policy_data *policy)
{
	connman_bool_t update = FALSE;
	int err;

	if (policy->session != NULL)
		update = TRUE;

	policy_unref(policy);

	if (update == FALSE)
		return;

	err = connman_session_set_default_config(policy->config);
	if (err < 0) {
		connman_session_destroy(policy->session);
		return;
	}

	update_session(policy->session);
}

static void notify_handler(struct inotify_event *event,
                                        const char *ident)
{
	struct policy_data *policy;

	if (ident == NULL)
		return;

	policy = g_hash_table_lookup(policy_hash, ident);

	if (event->mask & (IN_CREATE | IN_MOVED_TO)) {
		connman_info("Policy added for '%s'", ident);

		if (policy != NULL)
			policy_ref(policy);
		else
			policy = create_policy(ident);
	}

	if (policy == NULL)
		return;

	if (event->mask & IN_MODIFY) {
		connman_info("Policy modifed for '%s'", ident);

		if (load_policy(policy) < 0) {
			remove_policy(policy);
			return;
		}
	}

	if (event->mask & (IN_DELETE | IN_MOVED_FROM)) {
		connman_info("Policy deleted for '%s'", ident);

		remove_policy(policy);
		return;
	}

	if (policy->session != NULL)
		update_session(policy->session);
}

static int read_policies(void)
{
	GDir *dir;
	int err = 0;

	DBG("");

	dir = g_dir_open(POLICYDIR, 0, NULL);
	if (dir != NULL) {
		const gchar *file;

		while ((file = g_dir_read_name(dir)) != NULL) {
			struct policy_data *policy;

			policy = create_policy(file);
			if (policy == NULL) {
				err = -ENOMEM;
				break;
			}

			err = load_policy(policy);
			if (err < 0)
				break;
		}

		g_dir_close(dir);
	}

	return err;
}

static int session_policy_local_init(void)
{
	int err;

	/* If the dir doesn't exist, create it */
	if (g_file_test(POLICYDIR, G_FILE_TEST_IS_DIR) == FALSE) {
		if (mkdir(POLICYDIR, MODE) < 0) {
			if (errno != EEXIST)
				return -errno;
		}
	}

	connection = connman_dbus_get_connection();
	if (connection == NULL)
		return -EIO;

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

	err = connman_inotify_register(POLICYDIR, notify_handler);
	if (err < 0)
		goto err;

	err = read_policies();
	if (err < 0)
		goto err_notify;

	err = connman_session_policy_register(&session_policy_local);
	if (err < 0)
		goto err_notify;

	return 0;

err_notify:

	connman_inotify_unregister(POLICYDIR, notify_handler);

err:
	if (session_hash != NULL)
		g_hash_table_destroy(session_hash);
	if (policy_hash != NULL)
		g_hash_table_destroy(policy_hash);

	connman_session_policy_unregister(&session_policy_local);

	dbus_connection_unref(connection);

	return err;
}

static void session_policy_local_exit(void)
{
	g_hash_table_destroy(session_hash);
	g_hash_table_destroy(policy_hash);

	connman_session_policy_unregister(&session_policy_local);

	dbus_connection_unref(connection);

	connman_inotify_unregister(POLICYDIR, notify_handler);
}

CONNMAN_PLUGIN_DEFINE(session_policy_local,
		"Session local file policy configuration plugin",
		VERSION, CONNMAN_PLUGIN_PRIORITY_DEFAULT,
		session_policy_local_init, session_policy_local_exit)
