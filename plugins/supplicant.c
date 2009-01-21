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

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/device.h>
#include <connman/dbus.h>
#include <connman/log.h>

#include "inet.h"
#include "supplicant.h"

#define TIMEOUT 5000

#define IEEE80211_CAP_ESS       0x0001
#define IEEE80211_CAP_IBSS      0x0002
#define IEEE80211_CAP_PRIVACY   0x0010

#define SUPPLICANT_NAME  "fi.epitest.hostap.WPASupplicant"
#define SUPPLICANT_INTF  "fi.epitest.hostap.WPASupplicant"
#define SUPPLICANT_PATH  "/fi/epitest/hostap/WPASupplicant"

/* Taken from "WPA Supplicant - Common definitions" */
enum supplicant_state {
	/**
	 * WPA_DISCONNECTED - Disconnected state
	 *
	 * This state indicates that client is not associated, but is likely to
	 * start looking for an access point. This state is entered when a
	 * connection is lost.
	 */
	WPA_DISCONNECTED,

	/**
	 * WPA_INACTIVE - Inactive state (wpa_supplicant disabled)
	 *
	 * This state is entered if there are no enabled networks in the
	 * configuration. wpa_supplicant is not trying to associate with a new
	 * network and external interaction (e.g., ctrl_iface call to add or
	 * enable a network) is needed to start association.
	 */
	WPA_INACTIVE,

	/**
	 * WPA_SCANNING - Scanning for a network
	 *
	 * This state is entered when wpa_supplicant starts scanning for a
	 * network.
	 */
	WPA_SCANNING,

	/**
	 * WPA_ASSOCIATING - Trying to associate with a BSS/SSID
	 *
	 * This state is entered when wpa_supplicant has found a suitable BSS
	 * to associate with and the driver is configured to try to associate
	 * with this BSS in ap_scan=1 mode. When using ap_scan=2 mode, this
	 * state is entered when the driver is configured to try to associate
	 * with a network using the configured SSID and security policy.
	 */
	WPA_ASSOCIATING,

	/**
	 * WPA_ASSOCIATED - Association completed
	 *
	 * This state is entered when the driver reports that association has
	 * been successfully completed with an AP. If IEEE 802.1X is used
	 * (with or without WPA/WPA2), wpa_supplicant remains in this state
	 * until the IEEE 802.1X/EAPOL authentication has been completed.
	 */
	WPA_ASSOCIATED,

	/**
	 * WPA_4WAY_HANDSHAKE - WPA 4-Way Key Handshake in progress
	 *
	 * This state is entered when WPA/WPA2 4-Way Handshake is started. In
	 * case of WPA-PSK, this happens when receiving the first EAPOL-Key
	 * frame after association. In case of WPA-EAP, this state is entered
	 * when the IEEE 802.1X/EAPOL authentication has been completed.
	 */
	WPA_4WAY_HANDSHAKE,

	/**
	 * WPA_GROUP_HANDSHAKE - WPA Group Key Handshake in progress
	 *
	 * This state is entered when 4-Way Key Handshake has been completed
	 * (i.e., when the supplicant sends out message 4/4) and when Group
	 * Key rekeying is started by the AP (i.e., when supplicant receives
	 * message 1/2).
	 */
	WPA_GROUP_HANDSHAKE,

	/**
	 * WPA_COMPLETED - All authentication completed
	 *
	 * This state is entered when the full authentication process is
	 * completed. In case of WPA2, this happens when the 4-Way Handshake is
	 * successfully completed. With WPA, this state is entered after the
	 * Group Key Handshake; with IEEE 802.1X (non-WPA) connection is
	 * completed after dynamic keys are received (or if not used, after
	 * the EAP authentication has been completed). With static WEP keys and
	 * plaintext connections, this state is entered when an association
	 * has been completed.
	 *
	 * This state indicates that the supplicant has completed its
	 * processing for the association phase and that data connection is
	 * fully configured.
	 */
	WPA_COMPLETED,

	/**
	 * WPA_INVALID - Invalid state (parsing error)
	 *
	 * This state is returned if the string input is invalid. It is not
	 * an official wpa_supplicant state.
	 */
	WPA_INVALID,
};

struct supplicant_result {
	char *identifier;
	unsigned char *ssid;
	unsigned int ssid_len;
	dbus_uint16_t capabilities;
	gboolean adhoc;
	gboolean has_wep;
	gboolean has_wpa;
	gboolean has_rsn;
	dbus_int32_t quality;
	dbus_int32_t noise;
	dbus_int32_t level;
	dbus_int32_t maxrate;
};

struct supplicant_task {
	int ifindex;
	char *ifname;
	struct connman_device *device;
	struct connman_network *network;
	char *path;
	char *netpath;
	gboolean created;
	enum supplicant_state state;
	gboolean noscan;
	GSList *scan_results;
};

static GSList *task_list = NULL;

static DBusConnection *connection;

static void free_task(struct supplicant_task *task)
{
	DBG("task %p", task);

	g_free(task->ifname);
	g_free(task->path);
	g_free(task);
}

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

static void add_interface_reply(DBusPendingCall *call, void *user_data)
{
	struct supplicant_task *task = user_data;
	DBusMessage *reply;
	DBusError error;
	const char *path;

	DBG("task %p", task);

	reply = dbus_pending_call_steal_reply(call);
	if (reply == NULL)
		return;

	if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR)
		goto done;

	dbus_error_init(&error);

	if (dbus_message_get_args(reply, &error, DBUS_TYPE_OBJECT_PATH, &path,
						DBUS_TYPE_INVALID) == FALSE) {
		if (dbus_error_is_set(&error) == TRUE) {
			connman_error("%s", error.message);
			dbus_error_free(&error);
		} else
			connman_error("Wrong arguments for add interface");
		goto done;
	}

	DBG("path %s", path);

	task->path = g_strdup(path);
	task->created = TRUE;

	connman_device_set_powered(task->device, TRUE);

done:
	dbus_message_unref(reply);
}

static int add_interface(struct supplicant_task *task)
{
	DBusMessage *message;
	DBusPendingCall *call;

	DBG("task %p", task);

	message = dbus_message_new_method_call(SUPPLICANT_NAME, SUPPLICANT_PATH,
					SUPPLICANT_INTF, "addInterface");
	if (message == NULL)
		return -ENOMEM;

	dbus_message_append_args(message, DBUS_TYPE_STRING, &task->ifname,
							DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(connection, message,
						&call, TIMEOUT) == FALSE) {
		connman_error("Failed to add interface");
		dbus_message_unref(message);
		return -EIO;
	}

	dbus_pending_call_set_notify(call, add_interface_reply, task, NULL);

	dbus_message_unref(message);

	return -EINPROGRESS;
}

static void get_interface_reply(DBusPendingCall *call, void *user_data)
{
	struct supplicant_task *task = user_data;
	DBusMessage *reply;
	DBusError error;
	const char *path;

	DBG("task %p", task);

	reply = dbus_pending_call_steal_reply(call);
	if (reply == NULL)
		return;

	if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR) {
		add_interface(task);
		goto done;
	}

	dbus_error_init(&error);

	if (dbus_message_get_args(reply, &error, DBUS_TYPE_OBJECT_PATH, &path,
						DBUS_TYPE_INVALID) == FALSE) {
		if (dbus_error_is_set(&error) == TRUE) {
			connman_error("%s", error.message);
			dbus_error_free(&error);
		} else
			connman_error("Wrong arguments for get interface");
		goto done;
	}

	DBG("path %s", path);

	task->path = g_strdup(path);
	task->created = FALSE;

	connman_device_set_powered(task->device, TRUE);

done:
	dbus_message_unref(reply);
}

static int create_interface(struct supplicant_task *task)
{
	DBusMessage *message;
	DBusPendingCall *call;

	DBG("task %p", task);

	message = dbus_message_new_method_call(SUPPLICANT_NAME, SUPPLICANT_PATH,
					SUPPLICANT_INTF, "getInterface");
	if (message == NULL)
		return -ENOMEM;

	dbus_message_append_args(message, DBUS_TYPE_STRING, &task->ifname,
							DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(connection, message,
						&call, TIMEOUT) == FALSE) {
		connman_error("Failed to get interface");
		dbus_message_unref(message);
		return -EIO;
	}

	dbus_pending_call_set_notify(call, get_interface_reply, task, NULL);

	dbus_message_unref(message);

	return -EINPROGRESS;
}

static void remove_interface_reply(DBusPendingCall *call, void *user_data)
{
	struct supplicant_task *task = user_data;
	DBusMessage *reply;

	DBG("task %p", task);

	reply = dbus_pending_call_steal_reply(call);

	connman_device_set_powered(task->device, FALSE);

	free_task(task);

	dbus_message_unref(reply);
}

static int remove_interface(struct supplicant_task *task)
{
	DBusMessage *message;
	DBusPendingCall *call;

	DBG("task %p", task);

	if (task->created == FALSE) {
		connman_device_set_powered(task->device, FALSE);
		return 0;
	}

	message = dbus_message_new_method_call(SUPPLICANT_NAME, SUPPLICANT_PATH,
					SUPPLICANT_INTF, "removeInterface");
	if (message == NULL)
		return -ENOMEM;

	dbus_message_append_args(message, DBUS_TYPE_OBJECT_PATH, &task->path,
							DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(connection, message,
						&call, TIMEOUT) == FALSE) {
		connman_error("Failed to remove interface");
		dbus_message_unref(message);
		return -EIO;
	}

	dbus_pending_call_set_notify(call, remove_interface_reply, task, NULL);

	dbus_message_unref(message);

	return -EINPROGRESS;
}

#if 0
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
#endif

static int add_network(struct supplicant_task *task)
{
	DBusMessage *message, *reply;
	DBusError error;
	const char *path;

	DBG("task %p", task);

	if (task->netpath != NULL)
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

	task->netpath = g_strdup(path);

	dbus_message_unref(reply);

	return 0;
}

static int remove_network(struct supplicant_task *task)
{
	DBusMessage *message, *reply;
	DBusError error;

	DBG("task %p", task);

	if (task->netpath == NULL)
		return -EINVAL;

	message = dbus_message_new_method_call(SUPPLICANT_NAME, task->path,
				SUPPLICANT_INTF ".Interface", "removeNetwork");
	if (message == NULL)
		return -ENOMEM;

	dbus_message_append_args(message, DBUS_TYPE_OBJECT_PATH, &task->netpath,
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

	g_free(task->netpath);
	task->netpath = NULL;

	return 0;
}

static int select_network(struct supplicant_task *task)
{
	DBusMessage *message, *reply;
	DBusError error;

	DBG("task %p", task);

	if (task->netpath == NULL)
		return -EINVAL;

	message = dbus_message_new_method_call(SUPPLICANT_NAME, task->path,
				SUPPLICANT_INTF ".Interface", "selectNetwork");
	if (message == NULL)
		return -ENOMEM;

	dbus_message_append_args(message, DBUS_TYPE_OBJECT_PATH, &task->netpath,
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

	if (task->netpath == NULL)
		return -EINVAL;

	message = dbus_message_new_method_call(SUPPLICANT_NAME, task->netpath,
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

	if (task->netpath == NULL)
		return -EINVAL;

	message = dbus_message_new_method_call(SUPPLICANT_NAME, task->netpath,
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

	if (task->netpath == NULL)
		return -EINVAL;

	message = dbus_message_new_method_call(SUPPLICANT_NAME, task->netpath,
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

		if (passphrase) {
			int size = strlen(passphrase);
			if (size == 10 || size == 26) {
				unsigned char *key = malloc(13);
				char tmp[3];
				int i;
				memset(tmp, 0, sizeof(tmp));
				if (key == NULL)
					size = 0;
				for (i = 0; i < size / 2; i++) {
					memcpy(tmp, passphrase + (i * 2), 2);
					key[i] = (unsigned char) strtol(tmp,
								NULL, 16);
				}
				connman_dbus_dict_append_array(&dict,
						"wep_key0", DBUS_TYPE_BYTE,
							&key, size / 2);
				free(key);
			} else
				connman_dbus_dict_append_variant(&dict,
						"wep_key0", DBUS_TYPE_STRING,
								&passphrase);
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

static void extract_ssid(DBusMessageIter *value,
					struct supplicant_result *result)
{
	DBusMessageIter array;
	unsigned char *ssid;
	int ssid_len;

	dbus_message_iter_recurse(value, &array);
	dbus_message_iter_get_fixed_array(&array, &ssid, &ssid_len);

	if (ssid_len < 1)
		return;

	result->ssid = g_try_malloc(ssid_len);
	if (result->ssid == NULL)
		return;

	memcpy(result->ssid, ssid, ssid_len);
	result->ssid_len = ssid_len;

	result->identifier = g_try_malloc0(ssid_len + 1);
	if (result->identifier == NULL)
		return;

	memcpy(result->identifier, ssid, ssid_len);
}

static void extract_wpaie(DBusMessageIter *value,
					struct supplicant_result *result)
{
	DBusMessageIter array;
	unsigned char *ie;
	int ie_len;

	dbus_message_iter_recurse(value, &array);
	dbus_message_iter_get_fixed_array(&array, &ie, &ie_len);

	if (ie_len > 0)
		result->has_wpa = TRUE;
}

static void extract_rsnie(DBusMessageIter *value,
					struct supplicant_result *result)
{
	DBusMessageIter array;
	unsigned char *ie;
	int ie_len;

	dbus_message_iter_recurse(value, &array);
	dbus_message_iter_get_fixed_array(&array, &ie, &ie_len);

	if (ie_len > 0)
		result->has_rsn = TRUE;
}

static void extract_capabilites(DBusMessageIter *value,
					struct supplicant_result *result)
{
	dbus_message_iter_get_basic(value, &result->capabilities);

	if (result->capabilities & IEEE80211_CAP_ESS)
		result->adhoc = FALSE;
	else if (result->capabilities & IEEE80211_CAP_IBSS)
		result->adhoc = TRUE;

	if (result->capabilities & IEEE80211_CAP_PRIVACY)
		result->has_wep = TRUE;
}

static void get_properties(struct supplicant_task *task);

static void properties_reply(DBusPendingCall *call, void *user_data)
{
	struct supplicant_task *task = user_data;
	struct supplicant_result result;
	struct connman_network *network;
	DBusMessage *reply;
	DBusMessageIter array, dict;
	char *security, *temp = NULL;
	unsigned char strength;
	unsigned int i;

	DBG("task %p", task);

	reply = dbus_pending_call_steal_reply(call);
	if (reply == NULL) {
		get_properties(task);
		return;
	}

	if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR) {
		dbus_message_unref(reply);
		get_properties(task);
		return;
	}

	memset(&result, 0, sizeof(result));

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
			extract_ssid(&value, &result);
		else if (g_str_equal(key, "wpaie") == TRUE)
			extract_wpaie(&value, &result);
		else if (g_str_equal(key, "rsnie") == TRUE)
			extract_rsnie(&value, &result);
		else if (g_str_equal(key, "capabilities") == TRUE)
			extract_capabilites(&value, &result);
		else if (g_str_equal(key, "quality") == TRUE)
			dbus_message_iter_get_basic(&value, &result.quality);
		else if (g_str_equal(key, "noise") == TRUE)
			dbus_message_iter_get_basic(&value, &result.noise);
		else if (g_str_equal(key, "level") == TRUE)
			dbus_message_iter_get_basic(&value, &result.level);
		else if (g_str_equal(key, "maxrate") == TRUE)
			dbus_message_iter_get_basic(&value, &result.maxrate);

		dbus_message_iter_next(&dict);
	}

	if (result.identifier == NULL)
		goto done;

	if (result.identifier[0] == '\0')
		goto done;

	temp = g_strdup(result.identifier);
	if (temp == NULL)
		goto done;

	for (i = 0; i < strlen(temp); i++) {
		char tmp = temp[i];
		if ((tmp < '0' || tmp > '9') && (tmp < 'A' || tmp > 'Z') &&
						(tmp < 'a' || tmp > 'z'))
			temp[i] = '_';
	}

	strength = result.quality;

	if (result.has_rsn == TRUE)
		security = "wpa2";
	else if (result.has_wpa == TRUE)
		security = "wpa";
	else if (result.has_wep == TRUE)
		security = "wep";
	else
		security = "none";

	network = connman_device_get_network(task->device, temp);
	if (network == NULL) {
		const char *mode;
		int index;

		network = connman_network_create(temp,
						CONNMAN_NETWORK_TYPE_WIFI);
		if (network == NULL)
			goto done;

		index = connman_device_get_index(task->device);
		connman_network_set_index(network, index);

		connman_network_set_protocol(network,
						CONNMAN_NETWORK_PROTOCOL_IP);

		connman_network_set_string(network, "Name", result.identifier);

		connman_network_set_blob(network, "WiFi.SSID",
						result.ssid, result.ssid_len);

		mode = (result.adhoc == TRUE) ? "adhoc" : "managed";
		connman_network_set_string(network, "WiFi.Mode", mode);

		DBG("%s (%s %s) strength %d", result.identifier, mode,
							security, strength);

		if (connman_device_add_network(task->device, network) < 0) {
			connman_network_unref(network);
			goto done;
		}
	}

	connman_network_set_available(network, TRUE);
	connman_network_set_uint8(network, "Strength", strength);

	connman_network_set_string(network, "WiFi.Security", security);

done:
	g_free(result.identifier);
	g_free(result.ssid);
	g_free(temp);

	dbus_message_unref(reply);

	get_properties(task);
}

static void get_properties(struct supplicant_task *task)
{
	DBusMessage *message;
	DBusPendingCall *call;
	char *path;

	path = g_slist_nth_data(task->scan_results, 0);
	if (path == NULL)
		goto noscan;

	message = dbus_message_new_method_call(SUPPLICANT_NAME, path,
						SUPPLICANT_INTF ".BSSID",
								"properties");

	task->scan_results = g_slist_remove(task->scan_results, path);
	g_free(path);

	if (message == NULL)
		goto noscan;

	if (dbus_connection_send_with_reply(connection, message,
						&call, TIMEOUT) == FALSE) {
		connman_error("Failed to get network properties");
		dbus_message_unref(message);
		goto noscan;
	}

	dbus_pending_call_set_notify(call, properties_reply, task, NULL);

	dbus_message_unref(message);

	return;

noscan:
	if (task->noscan == FALSE)
		connman_device_set_scanning(task->device, FALSE);
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
	if (reply == NULL)
		goto noscan;

	if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR)
		goto done;

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

	if (num_results == 0)
		goto done;

	for (i = 0; i < num_results; i++) {
		char *path = g_strdup(results[i]);
		if (path == NULL)
			continue;

		task->scan_results = g_slist_append(task->scan_results, path);
	}

	g_strfreev(results);

	dbus_message_unref(reply);

	get_properties(task);

	return;

done:
	dbus_message_unref(reply);

noscan:
	if (task->noscan == FALSE)
		connman_device_set_scanning(task->device, FALSE);
}

static void scan_results_available(struct supplicant_task *task)
{
	DBusMessage *message;
	DBusPendingCall *call;

	DBG("task %p", task);

	message = dbus_message_new_method_call(SUPPLICANT_NAME, task->path,
						SUPPLICANT_INTF ".Interface",
							"scanResults");
	if (message == NULL)
		return;

	if (dbus_connection_send_with_reply(connection, message,
						&call, TIMEOUT) == FALSE) {
		connman_error("Failed to request scan result");
		goto done;
	}

	if (task->noscan == FALSE)
		connman_device_set_scanning(task->device, TRUE);

	dbus_pending_call_set_notify(call, scan_results_reply, task, NULL);

done:
	dbus_message_unref(message);
}

static enum supplicant_state string2state(const char *state)
{
	if (g_str_equal(state, "INACTIVE") == TRUE)
		return WPA_INACTIVE;
	else if (g_str_equal(state, "SCANNING") == TRUE)
		return WPA_SCANNING;
	else if (g_str_equal(state, "ASSOCIATING") == TRUE)
		return WPA_ASSOCIATING;
	else if (g_str_equal(state, "ASSOCIATED") == TRUE)
		return WPA_ASSOCIATED;
	else if (g_str_equal(state, "GROUP_HANDSHAKE") == TRUE)
		return WPA_GROUP_HANDSHAKE;
	else if (g_str_equal(state, "4WAY_HANDSHAKE") == TRUE)
		return WPA_4WAY_HANDSHAKE;
	else if (g_str_equal(state, "COMPLETED") == TRUE)
		return WPA_COMPLETED;
	else if (g_str_equal(state, "DISCONNECTED") == TRUE)
		return WPA_DISCONNECTED;
	else
		return WPA_INVALID;
}

static void state_change(struct supplicant_task *task, DBusMessage *msg)
{
	DBusError error;
	const char *newstate, *oldstate;
	enum supplicant_state state;

	dbus_error_init(&error);

	if (dbus_message_get_args(msg, &error, DBUS_TYPE_STRING, &newstate,
						DBUS_TYPE_STRING, &oldstate,
						DBUS_TYPE_INVALID) == FALSE) {
		if (dbus_error_is_set(&error) == TRUE) {
			connman_error("%s", error.message);
			dbus_error_free(&error);
		} else
			connman_error("Wrong arguments for state change");
		return;
	}

	DBG("state %s ==> %s", oldstate, newstate);

	state = string2state(newstate);
	if (state == WPA_INVALID)
		return;

	task->state = state;

	switch (task->state) {
	case WPA_SCANNING:
		task->noscan = TRUE;
		connman_device_set_scanning(task->device, TRUE);
		break;
	case WPA_ASSOCIATING:
	case WPA_ASSOCIATED:
	case WPA_4WAY_HANDSHAKE:
	case WPA_GROUP_HANDSHAKE:
		task->noscan = TRUE;
		break;
	case WPA_COMPLETED:
	case WPA_DISCONNECTED:
		task->noscan = FALSE;
		break;
	case WPA_INACTIVE:
		task->noscan = FALSE;
		connman_device_set_scanning(task->device, FALSE);
		break;
	case WPA_INVALID:
		break;
	}

	if (task->network == NULL)
		return;

	switch (task->state) {
	case WPA_COMPLETED:
		/* carrier on */
		connman_network_set_connected(task->network, TRUE);
		connman_device_set_scanning(task->device, FALSE);
		break;
	case WPA_DISCONNECTED:
		/* carrier off */
		connman_network_set_connected(task->network, FALSE);
		connman_device_set_scanning(task->device, FALSE);
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

int supplicant_start(struct connman_device *device)
{
	struct supplicant_task *task;

	DBG("device %p", device);

	task = g_try_new0(struct supplicant_task, 1);
	if (task == NULL)
		return -ENOMEM;

	task->ifindex = connman_device_get_index(device);
	task->ifname = inet_index2name(task->ifindex);
	task->device = device;

	if (task->ifname == NULL) {
		g_free(task);
		return -ENOMEM;
	}

	task->created = FALSE;
	task->noscan = FALSE;
	task->state = WPA_INVALID;

	task_list = g_slist_append(task_list, task);

	return create_interface(task);
}

int supplicant_stop(struct connman_device *device)
{
	int index = connman_device_get_index(device);
	struct supplicant_task *task;

	DBG("device %p", device);

	task = find_task_by_index(index);
	if (task == NULL)
		return -ENODEV;

	task_list = g_slist_remove(task_list, task);

	disable_network(task);

	remove_network(task);

	return remove_interface(task);
}

int supplicant_scan(struct connman_device *device)
{
	int index = connman_device_get_index(device);
	struct supplicant_task *task;
	int err;

	DBG("device %p", device);

	task = find_task_by_index(index);
	if (task == NULL)
		return -ENODEV;

	switch (task->state) {
	case WPA_SCANNING:
		return -EALREADY;
	case WPA_ASSOCIATING:
	case WPA_ASSOCIATED:
	case WPA_4WAY_HANDSHAKE:
	case WPA_GROUP_HANDSHAKE:
		return -EBUSY;
	default:
		break;
	}

	err = initiate_scan(task);

	return 0;
}

int supplicant_connect(struct connman_network *network)
{
	struct supplicant_task *task;
	const char *security, *passphrase;
	const void *ssid;
	unsigned int ssid_len;
	int index;

	DBG("network %p", network);

	security = connman_network_get_string(network, "WiFi.Security");
	passphrase = connman_network_get_string(network, "WiFi.Passphrase");

	ssid = connman_network_get_blob(network, "WiFi.SSID", &ssid_len);

	DBG("security %s passphrase %s", security, passphrase);

	if (security == NULL && passphrase == NULL)
		return -EINVAL;

	if (g_str_equal(security, "none") == FALSE && passphrase == NULL)
		return -EINVAL;

	index = connman_network_get_index(network);

	task = find_task_by_index(index);
	if (task == NULL)
		return -ENODEV;

	task->network = connman_network_ref(network);

	add_network(task);

	select_network(task);
	disable_network(task);

	set_network(task, ssid, ssid_len, security, passphrase);

	enable_network(task);

	return 0;
}

int supplicant_disconnect(struct connman_network *network)
{
	struct supplicant_task *task;
	int index;

	DBG("network %p", network);

	index = connman_network_get_index(network);

	task = find_task_by_index(index);
	if (task == NULL)
		return -ENODEV;

	disable_network(task);

	remove_network(task);

	connman_network_set_connected(task->network, FALSE);

	connman_network_unref(task->network);

	return 0;
}

static void supplicant_activate(DBusConnection *conn)
{
	DBusMessage *message;

	DBG("conn %p", conn);

	message = dbus_message_new_method_call(SUPPLICANT_NAME, "/",
				DBUS_INTERFACE_INTROSPECTABLE, "Introspect");
	if (message == NULL)
		return;

	dbus_message_set_no_reply(message, TRUE);

	dbus_connection_send(conn, message, NULL);

	dbus_message_unref(message);
}

static GSList *driver_list = NULL;

static void supplicant_probe(DBusConnection *conn, void *user_data)
{
	GSList *list;

	DBG("conn %p", conn);

	for (list = driver_list; list; list = list->next) {
		struct supplicant_driver *driver = list->data;

		DBG("driver %p name %s", driver, driver->name);

		if (driver->probe)
			driver->probe();
	}
}

static void supplicant_remove(DBusConnection *conn, void *user_data)
{
	GSList *list;

	DBG("conn %p", conn);

	for (list = driver_list; list; list = list->next) {
		struct supplicant_driver *driver = list->data;

		DBG("driver %p name %s", driver, driver->name);

		if (driver->remove)
			driver->remove();
	}
}

static const char *supplicant_rule = "type=signal,"
				"interface=" SUPPLICANT_INTF ".Interface";
static guint watch;

static int supplicant_create(void)
{
	if (g_slist_length(driver_list) > 0)
		return 0;

	connection = connman_dbus_get_connection();
	if (connection == NULL)
		return -EIO;

	DBG("connection %p", connection);

	if (dbus_connection_add_filter(connection,
				supplicant_filter, NULL, NULL) == FALSE) {
		connection = connman_dbus_get_connection();
		return -EIO;
	}

	dbus_bus_add_match(connection, supplicant_rule, NULL);
	dbus_connection_flush(connection);

	watch = g_dbus_add_service_watch(connection, SUPPLICANT_NAME,
			supplicant_probe, supplicant_remove, NULL, NULL);

	return 0;
}

static void supplicant_destroy(void)
{
	if (g_slist_length(driver_list) > 0)
		return;

	DBG("connection %p", connection);

	if (watch > 0)
		g_dbus_remove_watch(connection, watch);

	dbus_bus_remove_match(connection, supplicant_rule, NULL);
	dbus_connection_flush(connection);

	dbus_connection_remove_filter(connection, supplicant_filter, NULL);

	dbus_connection_unref(connection);
	connection = NULL;
}

int supplicant_register(struct supplicant_driver *driver)
{
	int err;

	DBG("driver %p name %s", driver, driver->name);

	err = supplicant_create();
	if (err < 0)
		return err;

	driver_list = g_slist_append(driver_list, driver);

	if (g_dbus_check_service(connection, SUPPLICANT_NAME) == TRUE)
		supplicant_probe(connection, NULL);
	else
		supplicant_activate(connection);

	return 0;
}

void supplicant_unregister(struct supplicant_driver *driver)
{
	DBG("driver %p name %s", driver, driver->name);

	supplicant_remove(connection, NULL);

	driver_list = g_slist_remove(driver_list, driver);

	supplicant_destroy();
}
