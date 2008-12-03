/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2008  Intel Corporation. All rights reserved.
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
#include <dbus/dbus.h>

#include <connman/log.h>
#include <connman/dbus.h>

#include "inet.h"
#include "supplicant.h"

#define TIMEOUT 5000

#define IEEE80211_CAP_ESS       0x0001
#define IEEE80211_CAP_IBSS      0x0002
#define IEEE80211_CAP_PRIVACY   0x0010

struct supplicant_task {
	int ifindex;
	gchar *ifname;
	struct connman_element *element;
	struct supplicant_callback *callback;
	gchar *path;
	gboolean created;
	gchar *network;
	enum supplicant_state state;
};

static GSList *task_list = NULL;

static DBusConnection *connection;

static struct supplicant_task *find_task_by_index(int index)
{
	GSList *list;

	for (list = task_list; list; list = list->next) {
		struct supplicant_task *task = list->data;

		if (task->ifindex == index)
			return task;
	}

	return NULL;
}

static struct supplicant_task *find_task_by_path(const char *path)
{
	GSList *list;

	for (list = task_list; list; list = list->next) {
		struct supplicant_task *task = list->data;

		if (g_str_equal(task->path, path) == TRUE)
			return task;
	}

	return NULL;
}

static int get_interface(struct supplicant_task *task)
{
	DBusMessage *message, *reply;
	DBusError error;
	const char *path;

	DBG("task %p", task);

	message = dbus_message_new_method_call(SUPPLICANT_NAME, SUPPLICANT_PATH,
					SUPPLICANT_INTF, "getInterface");
	if (message == NULL)
		return -ENOMEM;

	dbus_message_append_args(message, DBUS_TYPE_STRING, &task->ifname,
							DBUS_TYPE_INVALID);

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(connection,
							message, -1, &error);
	if (reply == NULL) {
		if (dbus_error_is_set(&error) == TRUE) {
			connman_error("%s", error.message);
			dbus_error_free(&error);
		} else
			connman_error("Failed to get interface");
		dbus_message_unref(message);
		return -EIO;
	}

	dbus_message_unref(message);

	dbus_error_init(&error);

	if (dbus_message_get_args(reply, &error, DBUS_TYPE_OBJECT_PATH, &path,
						DBUS_TYPE_INVALID) == FALSE) {
		if (dbus_error_is_set(&error) == TRUE) {
			connman_error("%s", error.message);
			dbus_error_free(&error);
		} else
			connman_error("Wrong arguments for interface");
		dbus_message_unref(reply);
		return -EIO;
	}

	DBG("path %s", path);

	task->path = g_strdup(path);
	task->created = FALSE;

	dbus_message_unref(reply);

	return 0;
}

static int add_interface(struct supplicant_task *task)
{
	DBusMessage *message, *reply;
	DBusError error;
	const char *path;

	DBG("task %p", task);

	message = dbus_message_new_method_call(SUPPLICANT_NAME, SUPPLICANT_PATH,
					SUPPLICANT_INTF, "addInterface");
	if (message == NULL)
		return -ENOMEM;

	dbus_error_init(&error);

	dbus_message_append_args(message, DBUS_TYPE_STRING, &task->ifname,
							DBUS_TYPE_INVALID);

	reply = dbus_connection_send_with_reply_and_block(connection,
							message, -1, &error);
	if (reply == NULL) {
		if (dbus_error_is_set(&error) == TRUE) {
			connman_error("%s", error.message);
			dbus_error_free(&error);
		} else
			connman_error("Failed to add interface");
		dbus_message_unref(message);
		return -EIO;
	}

	dbus_message_unref(message);

	dbus_error_init(&error);

	if (dbus_message_get_args(reply, &error, DBUS_TYPE_OBJECT_PATH, &path,
						DBUS_TYPE_INVALID) == FALSE) {
		if (dbus_error_is_set(&error) == TRUE) {
			connman_error("%s", error.message);
			dbus_error_free(&error);
		} else
			connman_error("Wrong arguments for interface");
		dbus_message_unref(reply);
		return -EIO;
	}

	DBG("path %s", path);

	task->path = g_strdup(path);
	task->created = TRUE;

	dbus_message_unref(reply);

	return 0;
}

static int remove_interface(struct supplicant_task *task)
{
	DBusMessage *message, *reply;
	DBusError error;

	DBG("task %p", task);

	if (task->created == FALSE)
		return -EINVAL;

	message = dbus_message_new_method_call(SUPPLICANT_NAME, SUPPLICANT_PATH,
					SUPPLICANT_INTF, "removeInterface");
	if (message == NULL)
		return -ENOMEM;

	dbus_message_append_args(message, DBUS_TYPE_OBJECT_PATH, &task->path,
							DBUS_TYPE_INVALID);

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(connection,
							message, -1, &error);
	if (reply == NULL) {
		if (dbus_error_is_set(&error) == TRUE) {
			connman_error("%s", error.message);
			dbus_error_free(&error);
		} else
			connman_error("Failed to remove interface");
		dbus_message_unref(message);
		return -EIO;
	}

	dbus_message_unref(message);

	dbus_message_unref(reply);

	return 0;
}

static int set_ap_scan(struct supplicant_task *task)
{
	DBusMessage *message, *reply;
	DBusError error;
	guint32 ap_scan = 1;

	DBG("task %p", task);

	message = dbus_message_new_method_call(SUPPLICANT_NAME, task->path,
				SUPPLICANT_INTF ".Interface", "setAPScan");
	if (message == NULL)
		return -ENOMEM;

	dbus_message_append_args(message, DBUS_TYPE_UINT32, &ap_scan,
							DBUS_TYPE_INVALID);

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(connection,
							message, -1, &error);
	if (reply == NULL) {
		if (dbus_error_is_set(&error) == TRUE) {
			connman_error("%s", error.message);
			dbus_error_free(&error);
		} else
			connman_error("Failed to set AP scan");
		dbus_message_unref(message);
		return -EIO;
	}

	dbus_message_unref(message);

	dbus_message_unref(reply);

	return 0;
}

static int add_network(struct supplicant_task *task)
{
	DBusMessage *message, *reply;
	DBusError error;
	const char *path;

	DBG("task %p", task);

	if (task->network != NULL)
		return -EALREADY;

	message = dbus_message_new_method_call(SUPPLICANT_NAME, task->path,
				SUPPLICANT_INTF ".Interface", "addNetwork");
	if (message == NULL)
		return -ENOMEM;

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(connection,
							message, -1, &error);
	if (reply == NULL) {
		if (dbus_error_is_set(&error) == TRUE) {
			connman_error("%s", error.message);
			dbus_error_free(&error);
		} else
			connman_error("Failed to add network");
		dbus_message_unref(message);
		return -EIO;
	}

	dbus_message_unref(message);

	dbus_error_init(&error);

	if (dbus_message_get_args(reply, &error, DBUS_TYPE_OBJECT_PATH, &path,
						DBUS_TYPE_INVALID) == FALSE) {
		if (dbus_error_is_set(&error) == TRUE) {
			connman_error("%s", error.message);
			dbus_error_free(&error);
		} else
			connman_error("Wrong arguments for network");
		dbus_message_unref(reply);
		return -EIO;
	}

	DBG("path %s", path);

	task->network = g_strdup(path);

	dbus_message_unref(reply);

	return 0;
}

static int remove_network(struct supplicant_task *task)
{
	DBusMessage *message, *reply;
	DBusError error;

	DBG("task %p", task);

	if (task->network == NULL)
		return -EINVAL;

	message = dbus_message_new_method_call(SUPPLICANT_NAME, task->path,
				SUPPLICANT_INTF ".Interface", "removeNetwork");
	if (message == NULL)
		return -ENOMEM;

	dbus_message_append_args(message, DBUS_TYPE_OBJECT_PATH, &task->network,
							DBUS_TYPE_INVALID);

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(connection,
							message, -1, &error);
	if (reply == NULL) {
		if (dbus_error_is_set(&error) == TRUE) {
			connman_error("%s", error.message);
			dbus_error_free(&error);
		} else
			connman_error("Failed to remove network");
		dbus_message_unref(message);
		return -EIO;
	}

	dbus_message_unref(message);

	dbus_message_unref(reply);

	g_free(task->network);
	task->network = NULL;

	return 0;
}

static int select_network(struct supplicant_task *task)
{
	DBusMessage *message, *reply;
	DBusError error;

	DBG("task %p", task);

	if (task->network == NULL)
		return -EINVAL;

	message = dbus_message_new_method_call(SUPPLICANT_NAME, task->path,
				SUPPLICANT_INTF ".Interface", "selectNetwork");
	if (message == NULL)
		return -ENOMEM;

	dbus_message_append_args(message, DBUS_TYPE_OBJECT_PATH, &task->network,
							DBUS_TYPE_INVALID);

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(connection,
							message, -1, &error);
	if (reply == NULL) {
		if (dbus_error_is_set(&error) == TRUE) {
			connman_error("%s", error.message);
			dbus_error_free(&error);
		} else
			connman_error("Failed to select network");
		dbus_message_unref(message);
		return -EIO;
	}

	dbus_message_unref(message);

	dbus_message_unref(reply);

	return 0;
}

static int enable_network(struct supplicant_task *task)
{
	DBusMessage *message, *reply;
	DBusError error;

	DBG("task %p", task);

	if (task->network == NULL)
		return -EINVAL;

	message = dbus_message_new_method_call(SUPPLICANT_NAME, task->network,
					SUPPLICANT_INTF ".Network", "enable");
	if (message == NULL)
		return -ENOMEM;

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(connection,
							message, -1, &error);
	if (reply == NULL) {
		if (dbus_error_is_set(&error) == TRUE) {
			connman_error("%s", error.message);
			dbus_error_free(&error);
		} else
			connman_error("Failed to enable network");
		dbus_message_unref(message);
		return -EIO;
	}

	dbus_message_unref(message);

	dbus_message_unref(reply);

	return 0;
}

static int disable_network(struct supplicant_task *task)
{
	DBusMessage *message, *reply;
	DBusError error;

	DBG("task %p", task);

	if (task->network == NULL)
		return -EINVAL;

	message = dbus_message_new_method_call(SUPPLICANT_NAME, task->network,
					SUPPLICANT_INTF ".Network", "disable");
	if (message == NULL)
		return -ENOMEM;

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(connection,
							message, -1, &error);
	if (reply == NULL) {
		if (dbus_error_is_set(&error) == TRUE) {
			connman_error("%s", error.message);
			dbus_error_free(&error);
		} else
			connman_error("Failed to disable network");
		dbus_message_unref(message);
		return -EIO;
	}

	dbus_message_unref(message);

	dbus_message_unref(reply);

	return 0;
}

static int set_network(struct supplicant_task *task,
				const unsigned char *network, int len,
				const char *security, const char *passphrase)
{
	DBusMessage *message, *reply;
	DBusMessageIter array, dict;
	DBusError error;

	DBG("task %p", task);

	if (task->network == NULL)
		return -EINVAL;

	message = dbus_message_new_method_call(SUPPLICANT_NAME, task->network,
					SUPPLICANT_INTF ".Network", "set");
	if (message == NULL)
		return -ENOMEM;

	dbus_message_iter_init_append(message, &array);

	dbus_message_iter_open_container(&array, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	connman_dbus_dict_append_array(&dict, "ssid",
					DBUS_TYPE_BYTE, &network, len);

	if (g_ascii_strcasecmp(security, "wpa") == 0 ||
				g_ascii_strcasecmp(security, "wpa2") == 0) {
		const char *key_mgmt = "WPA-PSK";
		connman_dbus_dict_append_variant(&dict, "key_mgmt",
						DBUS_TYPE_STRING, &key_mgmt);

		if (passphrase && strlen(passphrase) > 0)
			connman_dbus_dict_append_variant(&dict, "psk",
						DBUS_TYPE_STRING, &passphrase);
	} else if (g_ascii_strcasecmp(security, "wep") == 0) {
		const char *key_mgmt = "NONE", *index = "0";
		connman_dbus_dict_append_variant(&dict, "key_mgmt",
						DBUS_TYPE_STRING, &key_mgmt);

		if (passphrase && strlen(passphrase) > 0) {
			connman_dbus_dict_append_variant(&dict, "wep_key0",
						DBUS_TYPE_STRING, &passphrase);
			connman_dbus_dict_append_variant(&dict, "wep_tx_keyidx",
						DBUS_TYPE_STRING, &index);
		}
	} else {
		const char *key_mgmt = "NONE";
		connman_dbus_dict_append_variant(&dict, "key_mgmt",
						DBUS_TYPE_STRING, &key_mgmt);
	}

	dbus_message_iter_close_container(&array, &dict);

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(connection,
							message, -1, &error);
	if (reply == NULL) {
		if (dbus_error_is_set(&error) == TRUE) {
			connman_error("%s", error.message);
			dbus_error_free(&error);
		} else
			connman_error("Failed to set network options");
		dbus_message_unref(message);
		return -EIO;
	}

	dbus_message_unref(message);

	dbus_message_unref(reply);

	return 0;
}

static int initiate_scan(struct supplicant_task *task)
{
	DBusMessage *message;
	DBusPendingCall *call;

	DBG("task %p", task);

	message = dbus_message_new_method_call(SUPPLICANT_NAME, task->path,
					SUPPLICANT_INTF ".Interface", "scan");
	if (message == NULL)
		return -ENOMEM;

	if (dbus_connection_send_with_reply(connection, message,
						&call, TIMEOUT) == FALSE) {
		connman_error("Failed to initiate scan");
		dbus_message_unref(message);
		return -EIO;
	}

	dbus_message_unref(message);

	return 0;
}

static void extract_ssid(struct supplicant_network *network,
						DBusMessageIter *value)
{
	DBusMessageIter array;
	unsigned char *ssid;
	int ssid_len;

	dbus_message_iter_recurse(value, &array);
	dbus_message_iter_get_fixed_array(&array, &ssid, &ssid_len);

	if (ssid_len < 1)
		return;

	network->ssid = g_try_malloc(ssid_len);
	if (network->ssid == NULL)
		return;

	memcpy(network->ssid, ssid, ssid_len);
	network->ssid_len = ssid_len;

	network->identifier = g_try_malloc0(ssid_len + 1);
	if (network->identifier == NULL)
		return;

	memcpy(network->identifier, ssid, ssid_len);
}

static void extract_wpaie(struct supplicant_network *network,
						DBusMessageIter *value)
{
	DBusMessageIter array;
	unsigned char *ie;
	int ie_len;

	dbus_message_iter_recurse(value, &array);
	dbus_message_iter_get_fixed_array(&array, &ie, &ie_len);

	if (ie_len > 0)
		network->has_wpa = TRUE;
}

static void extract_rsnie(struct supplicant_network *network,
						DBusMessageIter *value)
{
	DBusMessageIter array;
	unsigned char *ie;
	int ie_len;

	dbus_message_iter_recurse(value, &array);
	dbus_message_iter_get_fixed_array(&array, &ie, &ie_len);

	if (ie_len > 0)
		network->has_rsn = TRUE;
}

static void extract_capabilites(struct supplicant_network *network,
						DBusMessageIter *value)
{
	dbus_message_iter_get_basic(value, &network->capabilities);

	if (network->capabilities & IEEE80211_CAP_PRIVACY)
		network->has_wep = TRUE;
}

static void properties_reply(DBusPendingCall *call, void *user_data)
{
	struct supplicant_task *task = user_data;
	struct supplicant_network *network;
	DBusMessage *reply;
	DBusMessageIter array, dict;

	DBG("task %p", task);

	reply = dbus_pending_call_steal_reply(call);

	network = g_try_new0(struct supplicant_network, 1);
	if (network == NULL)
		goto done;

	dbus_message_iter_init(reply, &array);

	dbus_message_iter_recurse(&array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);

		dbus_message_iter_recurse(&entry, &value);

		//type = dbus_message_iter_get_arg_type(&value);
		//dbus_message_iter_get_basic(&value, &val);

		/* 
		 * bssid        : a (97)
		 * ssid         : a (97)
		 * wpaie        : a (97)
		 * rsnie        : a (97)
		 * frequency    : i (105)
		 * capabilities : q (113)
		 * quality      : i (105)
		 * noise        : i (105)
		 * level        : i (105)
		 * maxrate      : i (105)
		 */

		if (g_str_equal(key, "ssid") == TRUE)
			extract_ssid(network, &value);
		else if (g_str_equal(key, "wpaie") == TRUE)
			extract_wpaie(network, &value);
		else if (g_str_equal(key, "rsnie") == TRUE)
			extract_rsnie(network, &value);
		else if (g_str_equal(key, "capabilities") == TRUE)
			extract_capabilites(network, &value);
		else if (g_str_equal(key, "quality") == TRUE)
			dbus_message_iter_get_basic(&value, &network->quality);
		else if (g_str_equal(key, "noise") == TRUE)
			dbus_message_iter_get_basic(&value, &network->noise);
		else if (g_str_equal(key, "level") == TRUE)
			dbus_message_iter_get_basic(&value, &network->level);
		else if (g_str_equal(key, "maxrate") == TRUE)
			dbus_message_iter_get_basic(&value, &network->maxrate);


		dbus_message_iter_next(&dict);
	}

	if (task->callback && task->callback->scan_result)
		task->callback->scan_result(task->element, network);

	g_free(network->identifier);
	g_free(network->ssid);
	g_free(network);

done:
	dbus_message_unref(reply);
}

static int get_network_properties(struct supplicant_task *task,
							const char *path)
{
	DBusMessage *message;
	DBusPendingCall *call;

	message = dbus_message_new_method_call(SUPPLICANT_NAME, path,
						SUPPLICANT_INTF ".BSSID",
								"properties");
	if (message == NULL)
		return -ENOMEM;

	if (dbus_connection_send_with_reply(connection, message,
						&call, TIMEOUT) == FALSE) {
		connman_error("Failed to get network properties");
		dbus_message_unref(message);
		return -EIO;
	}

	dbus_pending_call_set_notify(call, properties_reply, task, NULL);

	dbus_message_unref(message);

	return 0;
}

static void scan_results_reply(DBusPendingCall *call, void *user_data)
{
	struct supplicant_task *task = user_data;
	DBusMessage *reply;
	DBusError error;
	char **results;
	int i, num_results;

	DBG("task %p", task);

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&error);

	if (dbus_message_get_args(reply, &error,
				DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH,
						&results, &num_results,
						DBUS_TYPE_INVALID) == FALSE) {
		if (dbus_error_is_set(&error) == TRUE) {
			connman_error("%s", error.message);
			dbus_error_free(&error);
		} else
			connman_error("Wrong arguments for scan result");
		goto done;
	}

	for (i = 0; i < num_results; i++)
		get_network_properties(task, results[i]);

	g_strfreev(results);

done:
	dbus_message_unref(reply);
}

static int scan_results_available(struct supplicant_task *task)
{
	DBusMessage *message;
	DBusPendingCall *call;

	DBG("task %p", task);

	message = dbus_message_new_method_call(SUPPLICANT_NAME, task->path,
						SUPPLICANT_INTF ".Interface",
							"scanResults");
	if (message == NULL)
		return -ENOMEM;

	if (dbus_connection_send_with_reply(connection, message,
						&call, TIMEOUT) == FALSE) {
		connman_error("Failed to request scan result");
		dbus_message_unref(message);
		return -EIO;
	}

	dbus_pending_call_set_notify(call, scan_results_reply, task, NULL);

	dbus_message_unref(message);

	return 0;
}

static void state_change(struct supplicant_task *task, DBusMessage *msg)
{
	DBusError error;
	const char *state, *previous;

	dbus_error_init(&error);

	if (dbus_message_get_args(msg, &error, DBUS_TYPE_STRING, &state,
						DBUS_TYPE_STRING, &previous,
						DBUS_TYPE_INVALID) == FALSE) {
		if (dbus_error_is_set(&error) == TRUE) {
			connman_error("%s", error.message);
			dbus_error_free(&error);
		} else
			connman_error("Wrong arguments for state change");
		return;
	}

	DBG("state %s ==> %s", previous, state);

	if (g_str_equal(state, "INACTIVE") == TRUE)
		task->state = STATE_INACTIVE;
	else if (g_str_equal(state, "SCANNING") == TRUE)
		task->state = STATE_SCANNING;
	else if (g_str_equal(state, "ASSOCIATING") == TRUE)
		task->state = STATE_ASSOCIATING;
	else if (g_str_equal(state, "ASSOCIATED") == TRUE)
		task->state = STATE_ASSOCIATED;
	else if (g_str_equal(state, "GROUP_HANDSHAKE") == TRUE)
		task->state = STATE_4WAY_HANDSHAKE;
	else if (g_str_equal(state, "4WAY_HANDSHAKE") == TRUE)
		task->state = STATE_4WAY_HANDSHAKE;
	else if (g_str_equal(state, "COMPLETED") == TRUE)
		task->state = STATE_COMPLETED;
	else if (g_str_equal(state, "DISCONNECTED") == TRUE)
		task->state = STATE_DISCONNECTED;

	if (task->callback && task->callback->state_change)
		task->callback->state_change(task->element, task->state);

	switch (task->state) {
	case STATE_COMPLETED:
		/* carrier on */
		break;
	case STATE_DISCONNECTED:
		/* carrier off */
		break;
	default:
		break;
	}
}

static DBusHandlerResult supplicant_filter(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct supplicant_task *task;
	const char *member, *path;

	if (dbus_message_has_interface(msg,
				SUPPLICANT_INTF ".Interface") == FALSE)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	member = dbus_message_get_member(msg);
	if (member == NULL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	path = dbus_message_get_path(msg);
	if (path == NULL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	task = find_task_by_path(path);
	if (task == NULL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	DBG("task %p member %s", task, member);

	if (g_str_equal(member, "ScanResultsAvailable") == TRUE)
		scan_results_available(task);
	else if (g_str_equal(member, "StateChange") == TRUE)
		state_change(task, msg);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static int add_filter(struct supplicant_task *task)
{
	DBusError error;
	gchar *filter;

	filter = g_strdup_printf("type=signal,interface=%s.Interface,path=%s",
						SUPPLICANT_INTF, task->path);

	DBG("filter %s", filter);

	dbus_error_init(&error);

	dbus_bus_add_match(connection, filter, &error);

	g_free(filter);

	if (dbus_error_is_set(&error) == TRUE) {
		connman_error("Can't add match: %s", error.message);
		dbus_error_free(&error);
	}

	return 0;
}

static int remove_filter(struct supplicant_task *task)
{
	DBusError error;
	gchar *filter;

	filter = g_strdup_printf("type=signal,interface=%s.Interface,path=%s",
						SUPPLICANT_INTF, task->path);

	DBG("filter %s", filter);

	dbus_error_init(&error);

	dbus_bus_remove_match(connection, filter, &error);

	g_free(filter);

	if (dbus_error_is_set(&error) == TRUE) {
		connman_error("Can't add match: %s", error.message);
		dbus_error_free(&error);
	}

	return 0;
}

int __supplicant_start(struct connman_element *element,
					struct supplicant_callback *callback)
{
	struct supplicant_task *task;
	int err;

	DBG("element %p name %s", element, element->name);

	task = g_try_new0(struct supplicant_task, 1);
	if (task == NULL)
		return -ENOMEM;

	task->ifindex = element->index;
	task->ifname = inet_index2name(element->index);
	task->element = element;
	task->callback = callback;

	if (task->ifname == NULL) {
		g_free(task);
		return -ENOMEM;
	}

	task->created = FALSE;
	task->state = STATE_INACTIVE;

	task_list = g_slist_append(task_list, task);

	err = get_interface(task);
	if (err < 0) {
		err = add_interface(task);
		if (err < 0) {
			g_free(task);
			return err;
		}
	}

	add_filter(task);

	set_ap_scan(task);

	return 0;
}

int __supplicant_stop(struct connman_element *element)
{
	struct supplicant_task *task;

	DBG("element %p name %s", element, element->name);

	task = find_task_by_index(element->index);
	if (task == NULL)
		return -ENODEV;

	task_list = g_slist_remove(task_list, task);

	disable_network(task);

	remove_network(task);

	remove_filter(task);

	remove_interface(task);

	g_free(task->ifname);
	g_free(task->path);
	g_free(task);

	return 0;
}

int __supplicant_scan(struct connman_element *element)
{
	struct supplicant_task *task;
	int err;

	DBG("element %p name %s", element, element->name);

	task = find_task_by_index(element->index);
	if (task == NULL)
		return -ENODEV;

	switch (task->state) {
	case STATE_SCANNING:
		return -EALREADY;
	case STATE_ASSOCIATING:
	case STATE_ASSOCIATED:
	case STATE_4WAY_HANDSHAKE:
	case STATE_GROUP_HANDSHAKE:
		return -EBUSY;
	default:
		break;
	}

	err = initiate_scan(task);

	return 0;
}

int __supplicant_connect(struct connman_element *element,
				const unsigned char *ssid, int ssid_len,
				const char *security, const char *passphrase)
{
	struct supplicant_task *task;

	DBG("element %p name %s", element, element->name);

	task = find_task_by_index(element->index);
	if (task == NULL)
		return -ENODEV;

	add_network(task);

	select_network(task);
	disable_network(task);

	set_network(task, ssid, ssid_len, security, passphrase);

	enable_network(task);

	return 0;
}

int __supplicant_disconnect(struct connman_element *element)
{
	struct supplicant_task *task;

	DBG("element %p name %s", element, element->name);

	task = find_task_by_index(element->index);
	if (task == NULL)
		return -ENODEV;

	disable_network(task);

	remove_network(task);

	return 0;
}

int __supplicant_init(DBusConnection *conn)
{
	connection = conn;

	if (dbus_connection_add_filter(connection,
				supplicant_filter, NULL, NULL) == FALSE) {
		dbus_connection_unref(connection);
		return -EIO;
	}

	return 0;
}

void __supplicant_exit(void)
{
	dbus_connection_remove_filter(connection, supplicant_filter, NULL);
}
