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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dbus/dbus.h>

#define DHCLIENT_INTF "org.isc.dhclient"
#define DHCLIENT_PATH "/org/isc/dhclient"

extern char **environ;

static void append(DBusMessageIter *dict, const char *pattern)
{
	DBusMessageIter entry;
	const char *key, *value;
	char *delim;

	delim = strchr(pattern, '=');
	*delim = '\0';

	key = pattern;
	value = delim + 1;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
							NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &value);

	dbus_message_iter_close_container(dict, &entry);
}

int main(int argc, char *argv[])
{
	DBusConnection *conn;
	DBusError error;
	DBusMessage *msg;
	DBusMessageIter iter, dict;
	dbus_uint32_t pid;
	char **envp, *busname, *reason, *interface;

	busname = getenv("BUSNAME");

	pid = atoi(getenv("pid"));
	reason = getenv("reason");
	interface = getenv("interface");

	dbus_error_init(&error);

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
	if (conn == NULL) {
		if (dbus_error_is_set(&error) == TRUE) {
			fprintf(stderr, "%s\n", error.message);
			dbus_error_free(&error);
		} else
			fprintf(stderr, "Failed to get on system bus\n");
		return 0;
	}

	msg = dbus_message_new_method_call(busname, DHCLIENT_PATH,
						DHCLIENT_INTF, "notify");
	if (msg == NULL) {
		dbus_connection_unref(conn);
		fprintf(stderr, "Failed to allocate method call\n");
		return 0;
	}

	dbus_message_set_no_reply(msg, TRUE);

	dbus_message_append_args(msg, DBUS_TYPE_UINT32, &pid,
				DBUS_TYPE_STRING, &reason, DBUS_TYPE_INVALID);

	dbus_message_iter_init_append(msg, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_STRING_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	for (envp = environ; envp && *envp; envp++) {
		if (strlen(*envp) < 5)
			continue;

		if (strncmp(*envp, "new_", 4) == 0 ||
				strncmp(*envp, "old_", 4) == 0 ||
					strncmp(*envp, "alia", 4) == 0)
			append(&dict, *envp);
	}

	dbus_message_iter_close_container(&iter, &dict);

	if (dbus_connection_send(conn, msg, NULL) == FALSE)
		fprintf(stderr, "Failed to send message\n");

	dbus_connection_flush(conn);

	dbus_message_unref(msg);

	dbus_connection_unref(conn);

	return 0;
}
