/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007  Intel Corporation. All rights reserved.
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
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <net/if.h>

#include <dbus/dbus.h>
#include <gdbus.h>

#include <connman/log.h>

#include "supplicant.h"

enum supplicant_state {
	STATE_INACTIVE,
	STATE_SCANNING,
	STATE_ASSOCIATING,
	STATE_ASSOCIATED,
	STATE_4WAY_HANDSHAKE,
	STATE_GROUP_HANDSHAKE,
	STATE_COMPLETED,
	STATE_DISCONNECTED,
};

// COMPLETED       ==> ASSOCIATING
// ASSOCIATED      ==> DISCONNECTED
// DISCONNECTED    ==> INACTIVE

// DISCONNECTED    ==> SCANNING
// SCANNING        ==> ASSOCIATED

// ASSOCIATING     ==> ASSOCIATED
// ASSOCIATED      ==> 4WAY_HANDSHAKE
// 4WAY_HANDSHAKE  ==> GROUP_HANDSHAKE
// GROUP_HANDSHAKE ==> COMPLETED

struct supplicant_task {
	DBusConnection *conn;
	int ifindex;
	gchar *ifname;
	struct connman_iface *iface;
	gchar *path;
	gboolean created;
	gchar *network;
	enum supplicant_state state;
};

static GSList *tasks = NULL;

struct supplicant_ap {
	gchar *identifier;
	GByteArray *ssid;
	guint capabilities;
	gboolean has_wep;
	gboolean has_wpa;
	gboolean has_rsn;
};

#define IEEE80211_CAP_ESS       0x0001
#define IEEE80211_CAP_IBSS      0x0002
#define IEEE80211_CAP_PRIVACY   0x0010

static struct supplicant_task *find_task(int ifindex)
{
	GSList *list;

	for (list = tasks; list; list = list->next) {
		struct supplicant_task *task = list->data;

		if (task->ifindex == ifindex) 
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

	reply = dbus_connection_send_with_reply_and_block(task->conn,
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

	reply = dbus_connection_send_with_reply_and_block(task->conn,
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

static int add_network(struct supplicant_task *task)
{
	DBusMessage *message, *reply;
	DBusError error;
	const char *path;

	DBG("task %p", task);

	message = dbus_message_new_method_call(SUPPLICANT_NAME, task->path,
				SUPPLICANT_INTF ".Interface", "addNetwork");
	if (message == NULL)
		return -ENOMEM;

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(task->conn,
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

	message = dbus_message_new_method_call(SUPPLICANT_NAME, task->path,
				SUPPLICANT_INTF ".Interface", "removeNetwork");
	if (message == NULL)
		return -ENOMEM;

	dbus_message_append_args(message, DBUS_TYPE_OBJECT_PATH, &task->network,
							DBUS_TYPE_INVALID);

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(task->conn,
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

	return 0;
}

static int select_network(struct supplicant_task *task)
{
	DBusMessage *message, *reply;
	DBusError error;

	DBG("task %p", task);

	message = dbus_message_new_method_call(SUPPLICANT_NAME, task->path,
				SUPPLICANT_INTF ".Interface", "selectNetwork");
	if (message == NULL)
		return -ENOMEM;

	dbus_message_append_args(message, DBUS_TYPE_OBJECT_PATH, &task->network,
							DBUS_TYPE_INVALID);

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(task->conn,
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

	message = dbus_message_new_method_call(SUPPLICANT_NAME, task->network,
					SUPPLICANT_INTF ".Network", "enable");
	if (message == NULL)
		return -ENOMEM;

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(task->conn,
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

	message = dbus_message_new_method_call(SUPPLICANT_NAME, task->network,
					SUPPLICANT_INTF ".Network", "disable");
	if (message == NULL)
		return -ENOMEM;

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(task->conn,
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

static void append_entry(DBusMessageIter *dict,
				const char *key, int type, void *val)
{
	DBusMessageIter entry, value;
	const char *signature;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
								NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

	switch (type) {
	case DBUS_TYPE_STRING:
		signature = DBUS_TYPE_STRING_AS_STRING;
		break;
	case DBUS_TYPE_UINT16:
		signature = DBUS_TYPE_UINT16_AS_STRING;
		break;
	default:
		signature = DBUS_TYPE_VARIANT_AS_STRING;
		break;
	}

	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
							signature, &value);
	dbus_message_iter_append_basic(&value, type, val);
	dbus_message_iter_close_container(&entry, &value);

	dbus_message_iter_close_container(dict, &entry);
}

static int set_network(struct supplicant_task *task, const char *network,
						const char *passphrase)
{
	DBusMessage *message, *reply;
	DBusMessageIter array, dict;
	DBusError error;

	DBG("task %p", task);

	message = dbus_message_new_method_call(SUPPLICANT_NAME, task->network,
					SUPPLICANT_INTF ".Network", "set");
	if (message == NULL)
		return -ENOMEM;

	dbus_message_iter_init_append(message, &array);

	dbus_message_iter_open_container(&array, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	append_entry(&dict, "ssid", DBUS_TYPE_STRING, &network);

	if (passphrase && strlen(passphrase) > 0) {
		//exec_cmd(task, "SET_NETWORK 0 proto RSN WPA");
		//exec_cmd(task, "SET_NETWORK 0 key_mgmt WPA-PSK");

		append_entry(&dict, "psk", DBUS_TYPE_STRING, &passphrase);
	} else {
		//exec_cmd(task, "SET_NETWORK 0 proto RSN WPA");
		//exec_cmd(task, "SET_NETWORK 0 key_mgmt NONE");
	}

	dbus_message_iter_close_container(&array, &dict);

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(task->conn,
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
	DBusMessage *message, *reply;
	DBusError error;

	DBG("task %p", task);

	message = dbus_message_new_method_call(SUPPLICANT_NAME, task->path,
					SUPPLICANT_INTF ".Interface", "scan");
	if (message == NULL)
		return -ENOMEM;

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(task->conn,
							message, -1, &error);
	if (reply == NULL) {
		if (dbus_error_is_set(&error) == TRUE) {
			connman_error("%s", error.message);
			dbus_error_free(&error);
		} else
			connman_error("Failed to initiate scan");
		dbus_message_unref(message);
		return -EIO;
	}

	dbus_message_unref(message);

	dbus_message_unref(reply);

	return 0;
}

static void extract_ssid(struct supplicant_ap *ap, DBusMessageIter *value)
{
	DBusMessageIter array;
	unsigned char *ssid;
	int ssid_len;

	dbus_message_iter_recurse(value, &array);
	dbus_message_iter_get_fixed_array(&array, &ssid, &ssid_len);

	ap->identifier = g_strdup((char *) ssid);
}

static void extract_wpaie(struct supplicant_ap *ap, DBusMessageIter *value)
{
	DBusMessageIter array;
	unsigned char *ie;
	int ie_len;

	dbus_message_iter_recurse(value, &array);
	dbus_message_iter_get_fixed_array(&array, &ie, &ie_len);

	if (ie_len > 0)
		ap->has_wpa = TRUE;
}

static void extract_rsnie(struct supplicant_ap *ap, DBusMessageIter *value)
{
	DBusMessageIter array;
	unsigned char *ie;
	int ie_len;

	dbus_message_iter_recurse(value, &array);
	dbus_message_iter_get_fixed_array(&array, &ie, &ie_len);

	if (ie_len > 0)
		ap->has_rsn = TRUE;
}

static void extract_capabilites(struct supplicant_ap *ap,
						DBusMessageIter *value)
{
	guint capabilities;

	dbus_message_iter_get_basic(value, &capabilities);

	ap->capabilities = capabilities;

	if (capabilities & IEEE80211_CAP_PRIVACY)
		ap->has_wep = TRUE;
}

static int parse_network_properties(struct supplicant_task *task,
							DBusMessage *message)
{
	DBusMessageIter array, dict;
	struct supplicant_ap *ap;
	int security = 0;

	DBG("task %p", task);

	ap = g_try_new0(struct supplicant_ap, 1);
	if (ap == NULL)
		return -ENOMEM;

	dbus_message_iter_init(message, &array);

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

		if (g_str_equal(key, "ssid") == TRUE)
			extract_ssid(ap, &value);
		else if (g_str_equal(key, "wpaie") == TRUE)
			extract_wpaie(ap, &value);
		else if (g_str_equal(key, "rsnie") == TRUE)
			extract_rsnie(ap, &value);
		else if (g_str_equal(key, "capabilities") == TRUE)
			extract_capabilites(ap, &value);

		dbus_message_iter_next(&dict);
	}

	DBG("SSID %s", ap->identifier);

	if (ap->has_wep)
		security |= 0x01;
	if (ap->has_wpa)
		security |= 0x02;
	if (ap->has_rsn)
		security |= 0x04;

	connman_iface_indicate_station(task->iface,
					ap->identifier, 25, security);

	g_free(ap);

	return 0;
}

static int get_network_properties(struct supplicant_task *task,
							const char *path)
{
	DBusMessage *message, *reply;
	DBusError error;

	DBG("task %p", task);

	message = dbus_message_new_method_call(SUPPLICANT_NAME, path,
						SUPPLICANT_INTF ".BSSID",
								"properties");
	if (message == NULL)
		return -ENOMEM;

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(task->conn,
							message, -1, &error);
	if (reply == NULL) {
		if (dbus_error_is_set(&error) == TRUE) {
			connman_error("%s", error.message);
			dbus_error_free(&error);
		} else
			connman_error("Failed to get network properties");
		dbus_message_unref(message);
		return -EIO;
	}

	dbus_message_unref(message);

	parse_network_properties(task, reply);

	dbus_message_unref(reply);

	return 0;
}

static int scan_results_available(struct supplicant_task *task)
{
	DBusMessage *message, *reply;
	DBusError error;
	char **results;
	int i, num_results;

	DBG("task %p", task);

	message = dbus_message_new_method_call(SUPPLICANT_NAME, task->path,
						SUPPLICANT_INTF ".Interface",
							"scanResults");
	if (message == NULL)
		return -ENOMEM;

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(task->conn,
							message, -1, &error);
	if (reply == NULL) {
		if (dbus_error_is_set(&error) == TRUE) {
			connman_error("%s", error.message);
			dbus_error_free(&error);
		} else
			connman_error("Failed to request scan result");
		dbus_message_unref(message);
		return -EIO;
	}

	dbus_message_unref(message);

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
		dbus_message_unref(reply);
		return -EIO;
	}

	for (i = 0; i < num_results; i++)
		get_network_properties(task, results[i]);

	g_strfreev(results);

	dbus_message_unref(reply);

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
}

static DBusHandlerResult supplicant_filter(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct supplicant_task *task = data;
	const char *member;

	if (dbus_message_has_interface(msg,
				SUPPLICANT_INTF ".Interface") == FALSE)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	member = dbus_message_get_member(msg);
	if (member == NULL)
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

	if (dbus_connection_add_filter(task->conn,
				supplicant_filter, task, NULL) == FALSE)
		return -EIO;

	filter = g_strdup_printf("type=signal,interface=%s.Interface,path=%s",
						SUPPLICANT_INTF, task->path);

	DBG("filter %s", filter);

	dbus_error_init(&error);

	dbus_bus_add_match(task->conn, filter, &error);

	g_free(filter);

	if (dbus_error_is_set(&error) == TRUE) {
		connman_error("Can't add match: %s", error.message);
		dbus_error_free(&error);
	}

	return 0;
}

int __supplicant_start(struct connman_iface *iface)
{
	struct ifreq ifr;
	struct supplicant_task *task;
	int sk, err;

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0)
		return -EIO;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = iface->index;

	err = ioctl(sk, SIOCGIFNAME, &ifr);

	close(sk);

	if (err < 0)
		return -EIO;

	DBG("interface %s", ifr.ifr_name);

	task = g_try_new0(struct supplicant_task, 1);
	if (task == NULL)
		return -ENOMEM;

	task->ifindex = iface->index;
	task->ifname = g_strdup(ifr.ifr_name);
	task->iface = iface;

	if (task->ifname == NULL) {
		g_free(task);
		return -ENOMEM;
	}

	task->conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (task->conn == NULL) {
		g_free(task);
		return -EIO;
	}

	task->created = FALSE;

	err = get_interface(task);
	if (err < 0) {
		err = add_interface(task);
		if (err < 0) {
			g_free(task);
			return err;
		}
	}

	task->state = STATE_INACTIVE;

	tasks = g_slist_append(tasks, task);

	add_filter(task);

	add_network(task);

	select_network(task);
	disable_network(task);

	return 0;
}

int __supplicant_stop(struct connman_iface *iface)
{
	struct supplicant_task *task;

	task = find_task(iface->index);
	if (task == NULL)
		return -ENODEV;

	DBG("interface %s", task->ifname);

	tasks = g_slist_remove(tasks, task);

	remove_network(task);

	dbus_connection_unref(task->conn);

	g_free(task->ifname);
	g_free(task->network);
	g_free(task->path);
	g_free(task);

	return 0;
}

int __supplicant_scan(struct connman_iface *iface)
{
	struct supplicant_task *task;
	int err;

	task = find_task(iface->index);
	if (task == NULL)
		return -ENODEV;

	DBG("interface %s", task->ifname);

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

int __supplicant_connect(struct connman_iface *iface,
				const char *network, const char *passphrase)
{
	struct supplicant_task *task;

	task = find_task(iface->index);
	if (task == NULL)
		return -ENODEV;

	DBG("interface %s", task->ifname);

	set_network(task, network, passphrase);

	enable_network(task);

	return 0;
}

int __supplicant_disconnect(struct connman_iface *iface)
{
	struct supplicant_task *task;

	task = find_task(iface->index);
	if (task == NULL)
		return -ENODEV;

	DBG("interface %s", task->ifname);

	disable_network(task);

	return 0;
}
