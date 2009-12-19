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

#include <string.h>
#include <gdbus.h>

#include "connman.h"

dbus_bool_t connman_dbus_validate_ident(const char *ident)
{
	unsigned int i;

	if (ident == NULL)
		return FALSE;

	for (i = 0; i < strlen(ident); i++) {
		if (ident[i] >= '0' && ident[i] <= '9')
			continue;
		if (ident[i] >= 'a' && ident[i] <= 'z')
			continue;
		if (ident[i] >= 'A' && ident[i] <= 'Z')
			continue;
		return FALSE;
	}

	return TRUE;
}

char *connman_dbus_encode_string(const char *value)
{
	GString *str;
	unsigned int i, size;

	if (value == NULL)
		return NULL;

	size = strlen(value);

	str = g_string_new(NULL);
	if (str == NULL)
		return NULL;

	for (i = 0; i < size; i++) {
		const char tmp = value[i];
		if ((tmp < '0' || tmp > '9') && (tmp < 'A' || tmp > 'Z') &&
						(tmp < 'a' || tmp > 'z'))
			g_string_append_printf(str, "_%02x", tmp);
		else
			str = g_string_append_c(str, tmp);
	}

	return g_string_free(str, FALSE);
}

void connman_dbus_property_append_variant(DBusMessageIter *iter,
					const char *key, int type, void *val)
{
	DBusMessageIter value;
	const char *signature;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &key);

	switch (type) {
	case DBUS_TYPE_BOOLEAN:
		signature = DBUS_TYPE_BOOLEAN_AS_STRING;
		break;
	case DBUS_TYPE_STRING:
		signature = DBUS_TYPE_STRING_AS_STRING;
		break;
	case DBUS_TYPE_BYTE:
		signature = DBUS_TYPE_BYTE_AS_STRING;
		break;
	case DBUS_TYPE_UINT16:
		signature = DBUS_TYPE_UINT16_AS_STRING;
		break;
	case DBUS_TYPE_INT16:
		signature = DBUS_TYPE_INT16_AS_STRING;
		break;
	case DBUS_TYPE_UINT32:
		signature = DBUS_TYPE_UINT32_AS_STRING;
		break;
	case DBUS_TYPE_INT32:
		signature = DBUS_TYPE_INT32_AS_STRING;
		break;
	case DBUS_TYPE_OBJECT_PATH:
		signature = DBUS_TYPE_OBJECT_PATH_AS_STRING;
		break;
	default:
		signature = DBUS_TYPE_VARIANT_AS_STRING;
		break;
	}

	dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT,
							signature, &value);
	dbus_message_iter_append_basic(&value, type, val);
	dbus_message_iter_close_container(iter, &value);
}

void connman_dbus_property_append_dict(DBusMessageIter *iter, const char *key,
			connman_dbus_append_cb_t function, void *user_data)
{
	DBusMessageIter value, dict;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &key);

	dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT,
			DBUS_TYPE_ARRAY_AS_STRING
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &value);

	connman_dbus_dict_open(&value, &dict);
	if (function)
		function(&dict, user_data);
	connman_dbus_dict_close(&value, &dict);

	dbus_message_iter_close_container(iter, &value);
}

void connman_dbus_property_append_fixed_array(DBusMessageIter *iter,
				const char *key, int type, void *val, int len)
{
	DBusMessageIter value, array;
	const char *variant_sig, *array_sig;

	switch (type) {
	case DBUS_TYPE_BYTE:
		variant_sig = DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_BYTE_AS_STRING;
		array_sig = DBUS_TYPE_BYTE_AS_STRING;
		break;
	default:
		return;
	}

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &key);

	dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT,
							variant_sig, &value);

	dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY,
							array_sig, &array);
	dbus_message_iter_append_fixed_array(&array, type, val, len);
	dbus_message_iter_close_container(&value, &array);

	dbus_message_iter_close_container(iter, &value);
}

void connman_dbus_property_append_variable_array(DBusMessageIter *iter,
		const char *key, int type, connman_dbus_append_cb_t function)
{
	DBusMessageIter value, array;
	const char *variant_sig, *array_sig;

	switch (type) {
	case DBUS_TYPE_STRING:
		variant_sig = DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_STRING_AS_STRING;
		array_sig = DBUS_TYPE_STRING_AS_STRING;
		break;
	case DBUS_TYPE_OBJECT_PATH:
		variant_sig = DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_OBJECT_PATH_AS_STRING;
		array_sig = DBUS_TYPE_OBJECT_PATH_AS_STRING;
		break;
	default:
		return;
	}

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &key);

	dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT,
							variant_sig, &value);

	dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY,
							array_sig, &array);
	if (function)
		function(&array, NULL);
	dbus_message_iter_close_container(&value, &array);

	dbus_message_iter_close_container(iter, &value);
}

static DBusConnection *connection = NULL;

dbus_bool_t connman_dbus_property_changed_basic(const char *path,
				const char *interface, const char *key,
							int type, void *val)
{
	DBusMessage *signal;
	DBusMessageIter iter;

	if (path == NULL)
		return FALSE;

	signal = dbus_message_new_signal(path, interface, "PropertyChanged");
	if (signal == NULL)
		return FALSE;

	dbus_message_iter_init_append(signal, &iter);
	connman_dbus_property_append_variant(&iter, key, type, val);

	g_dbus_send_message(connection, signal);

	return TRUE;
}

dbus_bool_t connman_dbus_property_changed_dict(const char *path,
				const char *interface, const char *key,
			connman_dbus_append_cb_t function, void *user_data)
{
	DBusMessage *signal;
	DBusMessageIter iter;

	if (path == NULL)
		return FALSE;

	signal = dbus_message_new_signal(path, interface, "PropertyChanged");
	if (signal == NULL)
		return FALSE;

	dbus_message_iter_init_append(signal, &iter);
	connman_dbus_property_append_dict(&iter, key, function, user_data);

	g_dbus_send_message(connection, signal);

	return TRUE;
}

DBusConnection *connman_dbus_get_connection(void)
{
	if (connection == NULL)
		return NULL;

	return dbus_connection_ref(connection);
}

int __connman_dbus_init(DBusConnection *conn)
{
	connection = conn;

	return 0;
}

void __connman_dbus_cleanup(void)
{
	connection = NULL;
}
