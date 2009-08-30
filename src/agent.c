/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2009  Intel Corporation. All rights reserved.
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
#include <stdlib.h>
#include <string.h>

#include <gdbus.h>

#include "connman.h"

static DBusConnection *connection = NULL;
static guint agent_watch = 0;
static gchar *agent_path = NULL;
static gchar *agent_sender = NULL;

static void agent_free(void)
{
	agent_watch = 0;

	g_free(agent_sender);
	agent_sender = NULL;

	g_free(agent_path);
	agent_path = NULL;
}

static void agent_disconnect(DBusConnection *connection, void *data)
{
	DBG("data %p", data);

	agent_free();
}

int __connman_agent_register(const char *sender, const char *path)
{
	DBG("sender %s path %s", sender, path);

	if (agent_path != NULL)
		return -EEXIST;

	agent_sender = g_strdup(sender);
	agent_path = g_strdup(path);

	agent_watch = g_dbus_add_disconnect_watch(connection, sender,
						agent_disconnect, NULL, NULL);

	return 0;
}

int __connman_agent_unregister(const char *sender, const char *path)
{
	DBG("sender %s path %s", sender, path);

	if (agent_path == NULL)
		return -ESRCH;

	if (agent_watch > 0)
		g_dbus_remove_watch(connection, agent_watch);

	agent_free();

	return 0;
}

int __connman_agent_request_passphrase(struct connman_service *service,
				passphrase_cb_t callback, void *user_data)
{
	DBusMessage *message;
	const char *path;

	DBG("service %p", service);

	if (agent_path == NULL)
		return -ESRCH;

	message = dbus_message_new_method_call(agent_sender, agent_path,
				CONNMAN_AGENT_INTERFACE, "RequestPassphrase");
	if (message == NULL)
		return -ENOMEM;

	dbus_message_set_no_reply(message, TRUE);

	path = __connman_service_get_path(service);

	dbus_message_append_args(message, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID);

	g_dbus_send_message(connection, message);

	return -EIO;
}

int __connman_agent_init(void)
{
	DBG("");

	connection = connman_dbus_get_connection();
	if (connection == NULL)
		return -1;

	return 0;
}

void __connman_agent_cleanup(void)
{
	DBusMessage *message;

	DBG("");

	if (connection == NULL)
		return;

	if (agent_watch > 0)
		g_dbus_remove_watch(connection, agent_watch);

	if (agent_path == NULL)
		return;

	message = dbus_message_new_method_call(agent_sender, agent_path,
					CONNMAN_AGENT_INTERFACE, "Release");
	if (message == NULL)
		return;

	dbus_message_set_no_reply(message, TRUE);

	g_dbus_send_message(connection, message);

	agent_free();

	dbus_connection_unref(connection);
}
