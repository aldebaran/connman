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

struct create_data {
	struct connman_session *session;
	connman_session_config_cb callback;
	void *user_data;
};

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

static void selinux_context_reply(const unsigned char *context, void *user_data,
					int err)
{
	struct create_data *data = user_data;
	char *ident;

	DBG("session %p", data->session);

	if (err < 0)
		goto done;

	ident = parse_ident(context);

	DBG("ident %s", ident);

done:
	(*data->callback)(data->session, NULL, data->user_data, err);

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
	DBG("session %p", session);
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
	if (err < 0)
		goto err;

	return 0;

err:
	dbus_connection_unref(connection);

	return err;
}

static void session_policy_ivi_exit(void)
{
	connman_session_policy_unregister(&session_policy_ivi);

	dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE(session_policy_ivi,
		"Session IVI policy configuration plugin",
		VERSION, CONNMAN_PLUGIN_PRIORITY_DEFAULT,
		session_policy_ivi_init, session_policy_ivi_exit)
