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

#include <stdio.h>
#include <errno.h>
#include <glib.h>

#include "dbus_helpers.h"

#define TIMEOUT         60000

void __connmanctl_dbus_print(DBusMessageIter *iter, const char *pre,
		const char *dict, const char *sep)
{
	int arg_type;
	dbus_bool_t b;
	unsigned char c;
	unsigned int i;
	double d;

	char *str;
	DBusMessageIter entry;

	if (pre == NULL)
		pre = "";

	while ((arg_type = dbus_message_iter_get_arg_type(iter))
			!= DBUS_TYPE_INVALID) {

		fprintf(stdout, "%s", pre);

		switch (arg_type) {
		case DBUS_TYPE_STRUCT:
			fprintf(stdout, "{ ");
			dbus_message_iter_recurse(iter, &entry);
			__connmanctl_dbus_print(&entry, "", "=", " ");
			fprintf(stdout, " }");
			break;

		case DBUS_TYPE_ARRAY:
			fprintf(stdout, "[ ");

			dbus_message_iter_recurse(iter, &entry);
			__connmanctl_dbus_print(&entry, "", "=", ", ");

			fprintf(stdout, " ]");
			break;

		case DBUS_TYPE_DICT_ENTRY:

			dbus_message_iter_recurse(iter, &entry);
			__connmanctl_dbus_print(&entry, "", dict, dict);
			break;

		case DBUS_TYPE_STRING:
		case DBUS_TYPE_OBJECT_PATH:
			dbus_message_iter_get_basic(iter, &str);
			fprintf(stdout, "%s", str);
			break;

		case DBUS_TYPE_VARIANT:
			dbus_message_iter_recurse(iter, &entry);
			__connmanctl_dbus_print(&entry, pre, dict, sep);
			break;

		case DBUS_TYPE_BOOLEAN:
			dbus_message_iter_get_basic(iter, &b);
			if (b == FALSE)
				fprintf(stdout, "False");
			else
				fprintf(stdout, "True");
			break;

		case DBUS_TYPE_BYTE:
			dbus_message_iter_get_basic(iter, &c);
			fprintf(stdout, "%d", c);
			break;

		case DBUS_TYPE_UINT16:
		case DBUS_TYPE_UINT32:
			dbus_message_iter_get_basic(iter, &i);
			fprintf(stdout, "%d", i);
			break;

		case DBUS_TYPE_DOUBLE:
			dbus_message_iter_get_basic(iter, &d);
			fprintf(stdout, "%f", d);
			break;

		default:
			fprintf(stdout, "<type %c>", arg_type);
			break;
		}

		if (dbus_message_iter_has_next(iter) == TRUE)
			fprintf(stdout, "%s", sep);

		dbus_message_iter_next(iter);
	}
}

struct dbus_callback {
	connmanctl_dbus_method_return_func_t cb;
	void *user_data;
};

static void dbus_method_reply(DBusPendingCall *call, void *user_data)
{
	struct dbus_callback *callback = user_data;
	DBusMessage *reply;
	DBusMessageIter iter;

	reply = dbus_pending_call_steal_reply(call);
	if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR) {
		DBusError err;

		dbus_error_init(&err);
		dbus_set_error_from_message(&err, reply);

		callback->cb(NULL, err.message, callback->user_data);

		dbus_error_free(&err);
		goto end;
	}

	dbus_message_iter_init(reply, &iter);
	callback->cb(&iter, NULL, callback->user_data);

end:
	g_free(callback);
	dbus_message_unref(reply);
}

int __connmanctl_dbus_method_call(DBusConnection *connection, const char *path,
		const char *interface, const char *method,
		connmanctl_dbus_method_return_func_t cb, void * user_data,
		int arg1, ...)
{
	int res = -ENXIO;
	DBusMessage *message;
	va_list args;
	DBusPendingCall *call;
	struct dbus_callback *callback;

	message = dbus_message_new_method_call("net.connman", path,
			interface, method);

	if (message == NULL)
		return -ENOMEM;

	va_start(args, arg1);
	dbus_message_append_args_valist(message, arg1, args);
	va_end(args);

	if (dbus_connection_send_with_reply(connection, message, &call,
					TIMEOUT) == FALSE)
		goto end;

        if (call == NULL)
                goto end;

	if (cb != NULL) {
		callback = g_new0(struct dbus_callback, 1);
		callback->cb = cb;
		callback->user_data = user_data;
		dbus_pending_call_set_notify(call, dbus_method_reply,
				callback, NULL);
		res = -EINPROGRESS;
	}

end:
        dbus_message_unref(message);
	return res;
}
