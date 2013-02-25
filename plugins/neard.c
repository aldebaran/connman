/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2013  Intel Corporation. All rights reserved.
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
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#include <glib.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/dbus.h>
#include <connman/technology.h>

#include <gdbus.h>

#define NEARD_SERVICE "org.neard"
#define NEARD_PATH "/"
#define NEARD_MANAGER_INTERFACE "org.neard.Manager"
#define NEARD_AGENT_INTERFACE "org.neard.HandoverAgent"
#define NEARD_ERROR_INTERFACE "org.neard.HandoverAgent.Error"

#define AGENT_PATH "/net/connman/neard_handover_agent"
#define AGENT_TYPE "wifi"

struct data_elements {
	unsigned int value;
	unsigned int length;
	gboolean fixed_length;
};

typedef enum {
	DE_AUTHENTICATION_TYPE = 0,
	DE_NETWORK_KEY         = 1,
	DE_SSID                = 2,
	DE_MAX                 = 3,
} DEid;

static const struct data_elements  DEs[DE_MAX] = {
	{ 0x1003, 2,  TRUE  },
	{ 0x1027, 64, FALSE },
	{ 0x1045, 32, FALSE },
};

#define DE_VAL_OPEN                 0x0001
#define DE_VAL_PSK                  0x0022


static DBusConnection *connection = NULL;
DBusPendingCall *register_call = NULL;
gboolean agent_registered = FALSE;
static guint watch_id = 0;

static int set_2b_into_tlv(uint8_t *tlv_msg, uint16_t val)
{
	uint16_t ne_val;
	uint8_t *ins;

	ins = (uint8_t *) &ne_val;

	ne_val = htons(val);
	tlv_msg[0] = ins[0];
	tlv_msg[1] = ins[1];

	return 2;
}

static int set_byte_array_into_tlv(uint8_t *tlv_msg,
					uint8_t *array, int length)
{
	memcpy((void *)tlv_msg, (void *)array, length);
	return length;
}

static uint8_t *encode_to_tlv(const char *ssid, const char *psk, int *length)
{
	uint16_t ssid_len, psk_len;
	uint8_t *tlv_msg;
	int pos = 0;

	if (ssid == NULL || length == NULL)
		return NULL;

	ssid_len = strlen(ssid);

	*length = 6 + 4 + ssid_len;
	if (psk != NULL) {
		psk_len = strlen(psk);
		*length += 4 + psk_len;
	} else
		psk_len = 0;

	tlv_msg = g_try_malloc0(sizeof(uint8_t) * (*length));
	if (tlv_msg == NULL)
		return NULL;

	pos += set_2b_into_tlv(tlv_msg+pos, DEs[DE_SSID].value);
	pos += set_2b_into_tlv(tlv_msg+pos, ssid_len);
	pos += set_byte_array_into_tlv(tlv_msg+pos, (uint8_t *)ssid, ssid_len);

	pos += set_2b_into_tlv(tlv_msg+pos, DEs[DE_AUTHENTICATION_TYPE].value);
	pos += set_2b_into_tlv(tlv_msg+pos,
					DEs[DE_AUTHENTICATION_TYPE].length);
	if (psk != NULL) {
		pos += set_2b_into_tlv(tlv_msg+pos, DE_VAL_PSK);
		pos += set_2b_into_tlv(tlv_msg+pos, DEs[DE_NETWORK_KEY].value);
		pos += set_2b_into_tlv(tlv_msg+pos, psk_len);
		pos += set_byte_array_into_tlv(tlv_msg+pos,
						(uint8_t *)psk, psk_len);
	} else
		pos += set_2b_into_tlv(tlv_msg+pos, DE_VAL_OPEN);

	return tlv_msg;
}

static int parse_request_oob_params(DBusMessage *message)
{
	DBusMessageIter iter;
	DBusMessageIter array;

	dbus_message_iter_init(message, &iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY)
		return -EINVAL;

	dbus_message_iter_recurse(&iter, &array);
	if (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_DICT_ENTRY)
		return -EINVAL;

	return 0;
}

static DBusMessage *create_request_oob_reply(DBusMessage *message)
{
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;
	const char *ssid, *psk;
	uint8_t *tlv_msg;
	int length;

	if (connman_technology_get_wifi_tethering(&ssid, &psk) == FALSE)
		return g_dbus_create_error(message,
					NEARD_ERROR_INTERFACE ".NotSupported",
					"Operation is not supported");

	tlv_msg = encode_to_tlv(ssid, psk, &length);
	if (tlv_msg == NULL)
		return g_dbus_create_error(message,
					NEARD_ERROR_INTERFACE ".NotSupported",
					"Operation is not supported");

	reply = dbus_message_new_method_return(message);
	if (reply == NULL)
		goto out;

	dbus_message_iter_init_append(reply, &iter);

	connman_dbus_dict_open(&iter, &dict);

	connman_dbus_dict_append_fixed_array(&dict, "WSC",
					DBUS_TYPE_BYTE, &tlv_msg, length);

	dbus_message_iter_close_container(&iter, &dict);

out:
	g_free(tlv_msg);

	return reply;
}

static DBusMessage *request_oob_method(DBusConnection *dbus_conn,
					DBusMessage *message, void *user_data)
{
	DBG("");

	if (parse_request_oob_params(message) != 0)
		return g_dbus_create_error(message,
					NEARD_ERROR_INTERFACE ".Failed",
					"Invalid parameters");

	return create_request_oob_reply(message);
}

static DBusMessage *push_oob_method(DBusConnection *dbus_conn,
					DBusMessage *message, void *user_data)
{
	DBG("");

	return g_dbus_create_error(message,
				NEARD_ERROR_INTERFACE ".NotSupported",
				"Operation is not supported");
}

static DBusMessage *release_method(DBusConnection *dbus_conn,
					DBusMessage *message, void *user_data)
{
	DBG("");

	agent_registered = FALSE;
	g_dbus_unregister_interface(connection,
					AGENT_PATH, NEARD_AGENT_INTERFACE);

	return g_dbus_create_reply(message, DBUS_TYPE_INVALID);
}

static const GDBusMethodTable neard_methods[] = {
{ GDBUS_ASYNC_METHOD("RequestOOB",
		GDBUS_ARGS({ "data", "a{sv}" }),
		GDBUS_ARGS({ "data", "a{sv}" }), request_oob_method) },
	{ GDBUS_ASYNC_METHOD("PushOOB",
		GDBUS_ARGS({ "data", "a{sv}"}), NULL, push_oob_method) },
	{ GDBUS_METHOD("Release", NULL, NULL, release_method) },
	{ },
};

static void cleanup_register_call(void)
{
	if (register_call != NULL) {
		dbus_pending_call_cancel(register_call);
		dbus_pending_call_unref(register_call);
		register_call = NULL;
	}
}

static void register_agent_cb(DBusPendingCall *pending, void *user_data)
{
	DBusMessage *reply;

	if (dbus_pending_call_get_completed(pending) == FALSE)
		return;

	register_call = NULL;

	reply = dbus_pending_call_steal_reply(pending);
	if (reply == NULL)
		goto out;

	if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR) {
		g_dbus_unregister_interface(connection,
					AGENT_PATH, NEARD_AGENT_INTERFACE);
	} else
		agent_registered = TRUE;

	dbus_message_unref(reply);
out:
	dbus_pending_call_unref(pending);
}

static void register_agent(void)
{
	const char *path = AGENT_PATH;
	const char *type = AGENT_TYPE;
	DBusMessage *message;

	message = dbus_message_new_method_call(NEARD_SERVICE, NEARD_PATH,
						NEARD_MANAGER_INTERFACE,
						"RegisterHandoverAgent");
	if (message == NULL)
		return;

	dbus_message_append_args(message, DBUS_TYPE_OBJECT_PATH,
			&path, DBUS_TYPE_STRING, &type, DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(connection, message,
			&register_call, DBUS_TIMEOUT_USE_DEFAULT) == FALSE) {
		dbus_message_unref(message);
		goto out;
	}

	if (dbus_pending_call_set_notify(register_call, register_agent_cb,
							NULL, NULL) == FALSE)
		cleanup_register_call();

out:
	dbus_message_unref(message);
}

static void unregister_agent(void)
{
	const char *path = AGENT_PATH;
	const char *type = AGENT_TYPE;
	DBusMessage *message;

	if (agent_registered == FALSE)
		return cleanup_register_call();

	agent_registered = FALSE;

	message = dbus_message_new_method_call(NEARD_SERVICE, NEARD_PATH,
						NEARD_MANAGER_INTERFACE,
						"UnregisterHandoverAgent");
	if (message != NULL) {
		dbus_message_append_args(message, DBUS_TYPE_OBJECT_PATH,
			&path, DBUS_TYPE_STRING, &type, DBUS_TYPE_INVALID);
		g_dbus_send_message(connection, message);
	}

	g_dbus_unregister_interface(connection,
					AGENT_PATH, NEARD_AGENT_INTERFACE);
}

static void neard_is_present(DBusConnection *conn, void *user_data)
{
	DBG("");

	if (agent_registered == TRUE)
		return;

	if (g_dbus_register_interface(connection, AGENT_PATH,
					NEARD_AGENT_INTERFACE, neard_methods,
					NULL, NULL, NULL, NULL) == TRUE)
		register_agent();
}

static void neard_is_out(DBusConnection *conn, void *user_data)
{
	DBG("");

	if (agent_registered == TRUE) {
		g_dbus_unregister_interface(connection,
					AGENT_PATH, NEARD_AGENT_INTERFACE);
		agent_registered = FALSE;
	}

	cleanup_register_call();
}

static int neard_init(void)
{
	connection = connman_dbus_get_connection();
	if (connection == NULL)
		return -EIO;

	watch_id = g_dbus_add_service_watch(connection, NEARD_SERVICE,
						neard_is_present, neard_is_out,
						NULL, NULL);
	if (watch_id == 0) {
		dbus_connection_unref(connection);
		return -ENOMEM;
	}

	return 0;
}

static void neard_exit(void)
{
	unregister_agent();

	if (watch_id != 0)
		g_dbus_remove_watch(connection, watch_id);
	if (connection != NULL)
		dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE(neard, "Neard handover plugin", VERSION,
		CONNMAN_PLUGIN_PRIORITY_DEFAULT, neard_init, neard_exit)
