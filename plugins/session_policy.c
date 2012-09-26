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

static int policy_get_bool(const char *id, const char *key, connman_bool_t *val)
{
	DBG("id %s key %s", id, key);

	if (g_str_equal(key, "Priority") == TRUE)
		*val = FALSE;
	else if (g_str_equal(key, "EmergencyCall") == TRUE)
		*val = FALSE;
	else
		return -EINVAL;

	return 0;
}

static int policy_get_string(const char *id, const char *key, char **val)
{
	DBG("id %s key %s", id, key);

	if (g_str_equal(key, "RoamingPolicy") == TRUE)
		*val = "default";
	else
		return -EINVAL;

	return 0;
}

static struct connman_session_policy session_policy = {
	.name = "session policy configuration",
	.priority = CONNMAN_SESSION_POLICY_PRIORITY_LOW,
	.get_bool = policy_get_bool,
	.get_string = policy_get_string,
};

static int session_policy_init(void)
{
	int err;

	err = connman_session_policy_register(&session_policy);
	if (err < 0)
		return err;

	return 0;
}

static void session_policy_exit(void)
{
	connman_session_policy_unregister(&session_policy);
}

CONNMAN_PLUGIN_DEFINE(session_policy, "Session policy configuration plugin",
		VERSION, CONNMAN_PLUGIN_PRIORITY_DEFAULT,
		session_policy_init, session_policy_exit)
