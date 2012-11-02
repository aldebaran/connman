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

static int policy_ivi_create(struct connman_session *session,
				connman_session_config_cb callback,
				void *user_data)
{
	DBG("session %p", session);

	return -ENOMEM;
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
