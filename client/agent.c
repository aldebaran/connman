/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2013  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
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

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>

#include <gdbus.h>

#include "dbus_helpers.h"
#include "agent.h"

static bool agent_registered = false;

#define AGENT_INTERFACE      "net.connman.Agent"

static char *agent_path(void)
{
	static char *path = NULL;

	if (path == NULL)
		path = g_strdup_printf("/net/connman/connmanctl%d", getpid());

	return path;
}

static const GDBusMethodTable agent_methods[] = {
	{ },
};

static int agent_register_return(DBusMessageIter *iter, const char *error,
		void *user_data)
{
	DBusConnection *connection = user_data;

	if (error != NULL) {
		g_dbus_unregister_interface(connection, agent_path(),
				AGENT_INTERFACE);
		fprintf(stderr, "Error registering Agent: %s\n", error);
		return 0;
	}

	agent_registered = true;
	fprintf(stdout, "Agent registered\n");

	return -EINPROGRESS;
}

int __connmanctl_agent_register(DBusConnection *connection)
{
	char *path = agent_path();
	int result;

	if (agent_registered == true) {
		fprintf(stderr, "Agent already registered\n");
		return -EALREADY;
	}

	if (g_dbus_register_interface(connection, path,
					AGENT_INTERFACE, agent_methods,
					NULL, NULL, NULL, NULL) == FALSE) {
		fprintf(stderr, "Error: Failed to register Agent callbacks\n");
		return 0;
	}

	result = __connmanctl_dbus_method_call(connection, "/",
			"net.connman.Manager", "RegisterAgent",
			agent_register_return, connection,
			DBUS_TYPE_OBJECT_PATH, &path, DBUS_TYPE_INVALID);

	if (result != -EINPROGRESS) {
		g_dbus_unregister_interface(connection, agent_path(),
				AGENT_INTERFACE);

		fprintf(stderr, "Error: Failed to register Agent\n");
	}

	return result;
}

static int agent_unregister_return(DBusMessageIter *iter, const char *error,
		void *user_data)
{
	if (error != NULL) {
		fprintf(stderr, "Error unregistering Agent: %s\n", error);
		return 0;
	}

	agent_registered = false;
	fprintf(stdout, "Agent unregistered\n");

	return 0;
}

int __connmanctl_agent_unregister(DBusConnection *connection)
{
	char *path = agent_path();
	int result;

	if (agent_registered == false) {
		fprintf(stderr, "Agent not registered\n");
		return -EALREADY;
	}

	g_dbus_unregister_interface(connection, agent_path(), AGENT_INTERFACE);

	result = __connmanctl_dbus_method_call(connection, "/",
			"net.connman.Manager", "UnregisterAgent",
			agent_unregister_return, NULL,
			DBUS_TYPE_OBJECT_PATH, &path, DBUS_TYPE_INVALID);

	if (result != -EINPROGRESS)
		fprintf(stderr, "Error: Failed to unregister Agent\n");

	return result;
}
