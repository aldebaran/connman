/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2010  Intel Corporation. All rights reserved.
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
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_arp.h>
#include <linux/wireless.h>
#include <net/ethernet.h>

#include <gdbus.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/device.h>
#include <connman/option.h>
#include <connman/inet.h>
#include <connman/dbus.h>
#include <connman/wifi.h>
#include <connman/log.h>

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
	char *path;
	char *name;
	unsigned char *addr;
	unsigned int addr_len;
	unsigned char *ssid;
	unsigned int ssid_len;
	dbus_uint16_t capabilities;
	gboolean adhoc;
	gboolean has_wep;
	gboolean has_psk;
	gboolean has_8021x;
	gboolean has_wpa;
	gboolean has_rsn;
	gboolean has_wps;
	dbus_int32_t frequency;
	dbus_int32_t quality;
	dbus_int32_t noise;
	dbus_int32_t level;
	dbus_int32_t maxrate;
};

struct supplicant_block {
	unsigned char *ssid;
	char *netpath;
	gboolean enabled;
	int num_scans;
};

struct supplicant_task {
	int ifindex;
	char *ifname;
	gboolean cfg80211;
	struct connman_device *device;
	struct connman_network *network;
	struct connman_network *pending_network;
	char *path;
	char *netpath;
	gboolean hidden_found;
	GHashTable *hidden_blocks;
	gboolean created;
	enum supplicant_state state;
	gboolean scanning;
	GSList *scan_results;
	DBusPendingCall *scan_call;
	DBusPendingCall *result_call;
	struct iw_range *range;
	gboolean disconnecting;
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

static void remove_block(gpointer user_data)
{
	struct supplicant_block *block = user_data;

	DBG("");

	g_free(block->ssid);
	g_free(block->netpath);
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

		if (g_strcmp0(task->path, path) == 0)
			return task;
	}

	return NULL;
}

static int get_range(struct supplicant_task *task)
{
	struct iwreq wrq;
	int fd, err;

	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	memset(&wrq, 0, sizeof(struct iwreq));
	strncpy(wrq.ifr_name, task->ifname, IFNAMSIZ);
	wrq.u.data.pointer = task->range;
	wrq.u.data.length = sizeof(struct iw_range);

	err = ioctl(fd, SIOCGIWRANGE, &wrq);

	close(fd);

	if (err < 0)
		task->range->max_qual.updated |= IW_QUAL_ALL_INVALID;

	connman_info("%s {scan} capabilities 0x%02x", task->ifname,
						task->range->scan_capa);

	connman_info("%s {quality} flags 0x%02x", task->ifname,
					task->range->max_qual.updated);

	return err;
}

static int get_bssid(struct connman_device *device,
				unsigned char *bssid, unsigned int *bssid_len)
{
	struct iwreq wrq;
	char *ifname;
	int ifindex;
	int fd, err;

	ifindex = connman_device_get_index(device);
	if (ifindex < 0)
		return -EINVAL;

	ifname = connman_inet_ifname(ifindex);
	if (ifname == NULL)
		return -EINVAL;

	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		g_free(ifname);
		return -EINVAL;
	}

	memset(&wrq, 0, sizeof(wrq));
	strncpy(wrq.ifr_name, ifname, IFNAMSIZ);

	err = ioctl(fd, SIOCGIWAP, &wrq);

	g_free(ifname);
	close(fd);

	if (err < 0)
		return -EIO;

	memcpy(bssid, wrq.u.ap_addr.sa_data, ETH_ALEN);
	*bssid_len = ETH_ALEN;

	return 0;
}

static int enable_network(struct supplicant_task *task, const char *netpath,
			  connman_bool_t enable)
{
	DBusMessage *message, *reply;
	DBusError error;
	char *enable_string;

	DBG("enable %d", enable);

	enable_string = enable ? "enable" : "disable";

	message = dbus_message_new_method_call(SUPPLICANT_NAME, netpath,
				SUPPLICANT_INTF ".Network", enable_string);
	if (message == NULL)
		return -ENOMEM;

	dbus_message_set_auto_start(message, FALSE);

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

	dbus_message_unref(reply);

	dbus_message_unref(message);

	return 0;
}

static int set_hidden_network(struct supplicant_task *task, const char *netpath,
				const unsigned char *ssid, int ssid_len)
{
	DBusMessage *message, *reply;
	DBusMessageIter array, dict;
	DBusError error;
	dbus_uint32_t scan_ssid = 1;
	const char *invalid_address = "ff:ff:ff:ff:ff:ff";

	message = dbus_message_new_method_call(SUPPLICANT_NAME, netpath,
					SUPPLICANT_INTF ".Network", "set");
	if (message == NULL)
		return -ENOMEM;

	dbus_message_set_auto_start(message, FALSE);

	dbus_message_iter_init_append(message, &array);

	connman_dbus_dict_open(&array, &dict);

	connman_dbus_dict_append_basic(&dict, "scan_ssid",
					 DBUS_TYPE_UINT32, &scan_ssid);

	connman_dbus_dict_append_fixed_array(&dict, "ssid",
					DBUS_TYPE_BYTE, &ssid, ssid_len);

	/*
	 * We're setting an invalid BSSID to prevent wpa_s from associating
	 * automatically to this block once it's found.
	 */
	connman_dbus_dict_append_basic(&dict, "bssid",
					DBUS_TYPE_STRING, &invalid_address);

	connman_dbus_dict_close(&array, &dict);

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

	dbus_message_unref(reply);

	dbus_message_unref(message);

	return 0;
}

static void block_reset(gpointer key, gpointer value, gpointer user_data)
{
	struct supplicant_block *block = value;
	struct supplicant_task *task = user_data;

	block->num_scans = 0;
	if (block->enabled)
		enable_network(task, block->netpath, FALSE);

	block->enabled = FALSE;
}

#define MAX_BLOCK_SCANS 2
static void hidden_block_enable(struct supplicant_task *task)
{
	GHashTableIter iter;
	gpointer key, value;
	struct supplicant_block *block;

	DBG("network %p", task->network);

	if (g_hash_table_size(task->hidden_blocks) == 0)
		return;

	/*
	 * If we're associated or associating, we no longer need to
	 * look for hidden networks.
	 */
	if (task->network)
		return;

	/*
	 * We go through the block list and:
	 * - If we scanned it more than twice, we disable it and move
	 *   on to the next block.
	 * - If the next block is not enabled, we enable it, start
	 *   the scan counter, and return. This routine will be called
	 *   again when the next scan results are available.
	 * - If we're done with all the blocks there, we just reset them.
	 */
	g_hash_table_iter_init(&iter, task->hidden_blocks);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		block = value;

		DBG("%s num of scans %d enabled %d",
			block->ssid, block->num_scans, block->enabled);

		if (block->num_scans > MAX_BLOCK_SCANS) {
			if (block->enabled == FALSE)
				continue;

			enable_network(task, block->netpath, FALSE);
			block->enabled = FALSE;
			continue;
		}

		if (block->enabled == FALSE) {
			enable_network(task, block->netpath, TRUE);
			block->enabled = TRUE;
		}

		block->num_scans++;

		return;
	}

	g_hash_table_foreach(task->hidden_blocks, block_reset, task);
}

static int add_hidden_network(struct supplicant_task *task,
				const unsigned char *ssid, int ssid_len)
{
	DBusMessage *message, *reply;
	DBusError error;
	const char *path;
	struct supplicant_block *block;
	char *netpath = NULL;
	int ret, i;

	DBG("task %p", task);

	message = dbus_message_new_method_call(SUPPLICANT_NAME, task->path,
				SUPPLICANT_INTF ".Interface", "addNetwork");
	if (message == NULL)
		return -ENOMEM;

	dbus_message_set_auto_start(message, FALSE);

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

	netpath = g_strdup(path);

	ret = set_hidden_network(task, netpath, ssid, ssid_len);
	if (ret < 0)
		goto done;

	block = g_try_new0(struct supplicant_block, 1);
	if (block == NULL)
		goto done;

	block->ssid = g_try_malloc0(ssid_len + 1);
	if (block->ssid == NULL) {
		g_free(block);
		goto done;
	}

	for (i = 0; i < ssid_len; i++) {
		if (g_ascii_isprint(ssid[i]))
			block->ssid[i] = ssid[i];
		else
			block->ssid[i] = ' ';
	}

	block->netpath = netpath;
	block->enabled = FALSE;
	block->num_scans = 0;

	DBG("path %s ssid %s", block->netpath, block->ssid);

	g_hash_table_replace(task->hidden_blocks, block->ssid, block);

	return 0;
done:
	g_free(netpath);

	dbus_message_unref(reply);

	dbus_message_unref(message);

	return ret;
}

static void add_interface_reply(DBusPendingCall *call, void *user_data)
{
	struct supplicant_task *task = user_data;
	DBusMessage *reply;
	DBusError error;
	const char *path;
	char **hex_ssids, *hex_ssid;
	int i;

	DBG("task %p", task);

	reply = dbus_pending_call_steal_reply(call);

	if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR)
		goto failed;

	dbus_error_init(&error);

	if (dbus_message_get_args(reply, &error, DBUS_TYPE_OBJECT_PATH, &path,
						DBUS_TYPE_INVALID) == FALSE) {
		if (dbus_error_is_set(&error) == TRUE) {
			connman_error("%s", error.message);
			dbus_error_free(&error);
		} else
			connman_error("Wrong arguments for add interface");
		goto failed;
	}

	DBG("path %s", path);

	task->path = g_strdup(path);
	task->created = TRUE;

	connman_device_set_powered(task->device, TRUE);

	dbus_message_unref(reply);

	dbus_pending_call_unref(call);

	hex_ssids = connman_wifi_load_ssid();
	if (hex_ssids == NULL)
		return;

	for (i = 0; hex_ssids[i]; i++) {
		unsigned char *ssid;
		unsigned int j, k = 0, hex;
		size_t hex_ssid_len;

		hex_ssid = hex_ssids[i];
		hex_ssid_len = strlen(hex_ssid);

		ssid = g_try_malloc0(hex_ssid_len / 2 + 1);
		if (ssid == NULL)
			break;

		for (j = 0, k = 0; j < hex_ssid_len; j += 2) {
			sscanf(hex_ssid + j, "%02x", &hex);
			ssid[k++] = hex;
		}

		if (add_hidden_network(task, ssid, hex_ssid_len / 2) < 0)
			break;
	}

	g_strfreev(hex_ssids);

	return;

failed:
	dbus_message_unref(reply);

	dbus_pending_call_unref(call);

	task_list = g_slist_remove(task_list, task);

	connman_device_unref(task->device);

	free_task(task);
}

static int add_interface(struct supplicant_task *task)
{
	const char *driver = connman_option_get_string("wifi");
	DBusMessage *message;
	DBusMessageIter array, dict;
	DBusPendingCall *call;

	DBG("task %p", task);

	message = dbus_message_new_method_call(SUPPLICANT_NAME, SUPPLICANT_PATH,
					SUPPLICANT_INTF, "addInterface");
	if (message == NULL)
		return -ENOMEM;

	dbus_message_set_auto_start(message, FALSE);

	dbus_message_iter_init_append(message, &array);

	dbus_message_iter_append_basic(&array,
					DBUS_TYPE_STRING, &task->ifname);

	connman_dbus_dict_open(&array, &dict);

	connman_dbus_dict_append_basic(&dict, "driver",
						DBUS_TYPE_STRING, &driver);

	connman_dbus_dict_close(&array, &dict);

	if (dbus_connection_send_with_reply(connection, message,
						&call, TIMEOUT) == FALSE) {
		connman_error("Failed to add interface");
		dbus_message_unref(message);
		return -EIO;
	}

	if (call == NULL) {
		connman_error("D-Bus connection not available");
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

	dbus_pending_call_unref(call);
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

	dbus_message_set_auto_start(message, FALSE);

	dbus_message_append_args(message, DBUS_TYPE_STRING, &task->ifname,
							DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(connection, message,
						&call, TIMEOUT) == FALSE) {
		connman_error("Failed to get interface");
		dbus_message_unref(message);
		return -EIO;
	}

	if (call == NULL) {
		connman_error("D-Bus connection not available");
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

	connman_device_unref(task->device);

	connman_inet_ifdown(task->ifindex);

	free_task(task);

	dbus_message_unref(reply);

	dbus_pending_call_unref(call);
}

static int remove_interface(struct supplicant_task *task)
{
	DBusMessage *message;
	DBusPendingCall *call;

	DBG("task %p", task);

	if (task->path == NULL)
		return 0;

#if 0
	if (task->created == FALSE) {
		connman_device_set_powered(task->device, FALSE);
		return 0;
	}
#endif

	message = dbus_message_new_method_call(SUPPLICANT_NAME, SUPPLICANT_PATH,
					SUPPLICANT_INTF, "removeInterface");
	if (message == NULL)
		return -ENOMEM;

	dbus_message_set_auto_start(message, FALSE);

	dbus_message_append_args(message, DBUS_TYPE_OBJECT_PATH, &task->path,
							DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(connection, message,
						&call, TIMEOUT) == FALSE) {
		connman_error("Failed to remove interface");
		dbus_message_unref(message);
		return -EIO;
	}

	if (call == NULL) {
		connman_error("D-Bus connection not available");
		dbus_message_unref(message);
		return -EIO;
	}

	dbus_pending_call_set_notify(call, remove_interface_reply, task, NULL);

	dbus_message_unref(message);

	return -EINPROGRESS;
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

	dbus_message_set_auto_start(message, FALSE);

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

	if (task->netpath != NULL)
		return -EALREADY;

	message = dbus_message_new_method_call(SUPPLICANT_NAME, task->path,
				SUPPLICANT_INTF ".Interface", "addNetwork");
	if (message == NULL)
		return -ENOMEM;

	dbus_message_set_auto_start(message, FALSE);

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

	if (task->netpath == NULL || task->path == NULL)
		return -EINVAL;

	message = dbus_message_new_method_call(SUPPLICANT_NAME, task->path,
				SUPPLICANT_INTF ".Interface", "removeNetwork");
	if (message == NULL)
		return -ENOMEM;

	dbus_message_set_auto_start(message, FALSE);

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

	dbus_message_set_auto_start(message, FALSE);

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

static int disconnect_network(struct supplicant_task *task)
{
	DBusMessage *message, *reply;
	DBusError error;

	DBG("task %p", task);

	if (task->path == NULL)
		return -EINVAL;

	message = dbus_message_new_method_call(SUPPLICANT_NAME, task->path,
				SUPPLICANT_INTF ".Interface", "disconnect");
	if (message == NULL)
		return -ENOMEM;

	dbus_message_set_auto_start(message, FALSE);

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(connection,
							message, -1, &error);
	if (reply == NULL) {
		if (dbus_error_is_set(&error) == TRUE) {
			connman_error("%s", error.message);
			dbus_error_free(&error);
		} else
			connman_error("Failed to disconnect network");
		dbus_message_unref(message);
		return -EIO;
	}

	dbus_message_unref(message);

	dbus_message_unref(reply);

	return 0;
}

static int set_network_tls(struct connman_network *network,
			   DBusMessageIter *dict)
{
	const char *private_key, *client_cert, *ca_cert;
	const char *private_key_password;

	/*
	 * For TLS, we at least need a key, the client cert,
	 * and a passhprase.
	 * Server cert is optional.
	 */
	client_cert = connman_network_get_string(network,
						"WiFi.ClientCertFile");
	if (client_cert == NULL)
		return -EINVAL;

	private_key = connman_network_get_string(network,
						"WiFi.PrivateKeyFile");
	if (private_key == NULL)
		return -EINVAL;

	private_key_password = connman_network_get_string(network,
						"WiFi.PrivateKeyPassphrase");
	if (private_key_password == NULL)
		return -EINVAL;

	ca_cert = connman_network_get_string(network, "WiFi.CACertFile");
	if (ca_cert)
		connman_dbus_dict_append_basic(dict, "ca_cert",
						DBUS_TYPE_STRING, &ca_cert);

	DBG("client cert %s private key %s", client_cert, private_key);

	connman_dbus_dict_append_basic(dict, "private_key",
						DBUS_TYPE_STRING, &private_key);
	connman_dbus_dict_append_basic(dict, "private_key_passwd",
							DBUS_TYPE_STRING,
							&private_key_password);
	connman_dbus_dict_append_basic(dict, "client_cert",
						DBUS_TYPE_STRING, &client_cert);

	return 0;
}

static int set_network_peap(struct connman_network *network,
			    DBusMessageIter *dict, const char *passphrase)
{
	const char *client_cert, *ca_cert, *phase2;
	char *phase2_auth;

	/*
	 * For PEAP, we at least need the sever cert, a 2nd
	 * phase authentication and a passhprase.
	 * Client cert is optional although strongly required
	 * When setting the client cert, we then need a private
	 * key as well.
	 */
	if (passphrase == NULL) {
		connman_error("Error in PEAP/TTLS authentication: "
			      "a phase2 passphrase must be defined\n");
		return -EINVAL;
	}

	ca_cert = connman_network_get_string(network, "WiFi.CACertFile");
	if (ca_cert == NULL)
		return -EINVAL;

	phase2 = connman_network_get_string(network, "WiFi.Phase2");
	if (phase2 == NULL)
		return -EINVAL;

	DBG("CA cert %s phase2 auth %s", ca_cert, phase2);

	client_cert = connman_network_get_string(network,
							"WiFi.ClientCertFile");
	if (client_cert) {
		const char *private_key, *private_key_password;

		private_key = connman_network_get_string(network,
							"WiFi.PrivateKeyFile");
		if (private_key == NULL)
			return -EINVAL;

		private_key_password =
			connman_network_get_string(network,
						"WiFi.PrivateKeyPassphrase");
		if (private_key_password == NULL)
			return -EINVAL;

		connman_dbus_dict_append_basic(dict, "client_cert",
						DBUS_TYPE_STRING, &client_cert);

		connman_dbus_dict_append_basic(dict, "private_key",
						DBUS_TYPE_STRING, &private_key);

		connman_dbus_dict_append_basic(dict, "private_key_passwd",
							DBUS_TYPE_STRING,
							&private_key_password);

		DBG("client cert %s private key %s", client_cert, private_key);
	}

	phase2_auth = g_strdup_printf("\"auth=%s\"", phase2);

	connman_dbus_dict_append_basic(dict, "password",
						DBUS_TYPE_STRING, &passphrase);

	connman_dbus_dict_append_basic(dict, "ca_cert",
						DBUS_TYPE_STRING, &ca_cert);

	connman_dbus_dict_append_basic(dict, "phase2",
						DBUS_TYPE_STRING, &phase2_auth);

	g_free(phase2_auth);

	return 0;
}

static int set_network(struct supplicant_task *task,
				const unsigned char *network, int len,
				const char *address, const char *security,
							const char *passphrase)
{
	DBusMessage *message, *reply;
	DBusMessageIter array, dict;
	DBusError error;
	dbus_uint32_t scan_ssid = 1;

	DBG("task %p", task);

	if (task->netpath == NULL)
		return -EINVAL;

	message = dbus_message_new_method_call(SUPPLICANT_NAME, task->netpath,
					SUPPLICANT_INTF ".Network", "set");
	if (message == NULL)
		return -ENOMEM;

	dbus_message_set_auto_start(message, FALSE);

	dbus_message_iter_init_append(message, &array);

	connman_dbus_dict_open(&array, &dict);

	connman_dbus_dict_append_basic(&dict, "scan_ssid",
					 DBUS_TYPE_UINT32, &scan_ssid);

	if (network)
		connman_dbus_dict_append_fixed_array(&dict, "ssid",
						DBUS_TYPE_BYTE, &network, len);
	else if (address)
		connman_dbus_dict_append_basic(&dict, "bssid",
						DBUS_TYPE_STRING, &address);

	if (g_ascii_strcasecmp(security, "psk") == 0 ||
				g_ascii_strcasecmp(security, "wpa") == 0 ||
				g_ascii_strcasecmp(security, "rsn") == 0) {
		const char *key_mgmt = "WPA-PSK";
		connman_dbus_dict_append_basic(&dict, "key_mgmt",
						DBUS_TYPE_STRING, &key_mgmt);

		if (passphrase && strlen(passphrase) > 0)
			connman_dbus_dict_append_basic(&dict, "psk",
						DBUS_TYPE_STRING, &passphrase);
	} else if (g_ascii_strcasecmp(security, "ieee8021x") == 0) {
		struct connman_network *network = task->network;
		const char *key_mgmt = "WPA-EAP", *eap, *identity;
		char *eap_value;

		/*
		 * If our private key password is unset,
		 * we use the supplied passphrase. That is needed
		 * for PEAP where 2 passphrases (identity and client
		 * cert may have to be provided.
		 */
		if (connman_network_get_string(network,
					"WiFi.PrivateKeyPassphrase") == NULL)
			connman_network_set_string(network,
						"WiFi.PrivateKeyPassphrase",
								passphrase);

		eap = connman_network_get_string(network, "WiFi.EAP");
		if (eap == NULL)
			goto invalid;

		/* We must have an identity for both PEAP and TLS */
		identity = connman_network_get_string(network, "WiFi.Identity");
		if (identity == NULL)
			goto invalid;

		DBG("key_mgmt %s eap %s identity %s", key_mgmt, eap, identity);

		if (g_strcmp0(eap, "tls") == 0) {
			int err;

			err = set_network_tls(network, &dict);
			if (err < 0) {
				dbus_message_unref(message);
				return err;
			}
		} else if (g_strcmp0(eap, "peap") == 0 ||
				   g_strcmp0(eap, "ttls") == 0) {
			int err;

			err = set_network_peap(network, &dict, passphrase);
			if (err < 0) {
				dbus_message_unref(message);
				return err;
			}
		} else {
			connman_error("Unknown EAP %s", eap);
			goto invalid;
		}

		/* wpa_supplicant only accepts upper case EAPs */
		eap_value = g_ascii_strup(eap, -1);

		connman_dbus_dict_append_basic(&dict, "key_mgmt",
							DBUS_TYPE_STRING,
							&key_mgmt);
		connman_dbus_dict_append_basic(&dict, "eap",
							DBUS_TYPE_STRING,
							&eap_value);
		connman_dbus_dict_append_basic(&dict, "identity",
							DBUS_TYPE_STRING,
							&identity);

		g_free(eap_value);

	} else if (g_ascii_strcasecmp(security, "wep") == 0) {
		const char *key_mgmt = "NONE";
		const char *auth_alg = "OPEN";
		const char *key_index = "0";

		if (task->cfg80211 == TRUE)
			auth_alg = "OPEN SHARED";

		connman_dbus_dict_append_basic(&dict, "auth_alg",
						DBUS_TYPE_STRING, &auth_alg);

		connman_dbus_dict_append_basic(&dict, "key_mgmt",
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
				connman_dbus_dict_append_fixed_array(&dict,
						"wep_key0", DBUS_TYPE_BYTE,
							&key, size / 2);
				free(key);
			} else if (size == 5 || size == 13) {
				unsigned char *key = malloc(13);
				int i;
				if (key == NULL)
					size = 0;
				for (i = 0; i < size; i++)
					key[i] = (unsigned char) passphrase[i];
				connman_dbus_dict_append_fixed_array(&dict,
						"wep_key0", DBUS_TYPE_BYTE,
								&key, size);
				free(key);
			} else
				connman_dbus_dict_append_basic(&dict,
						"wep_key0", DBUS_TYPE_STRING,
								&passphrase);

			connman_dbus_dict_append_basic(&dict, "wep_tx_keyidx",
						DBUS_TYPE_STRING, &key_index);
		}
	} else {
		const char *key_mgmt = "NONE";
		connman_dbus_dict_append_basic(&dict, "key_mgmt",
						DBUS_TYPE_STRING, &key_mgmt);
	}

	connman_dbus_dict_close(&array, &dict);

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

invalid:
	dbus_message_unref(message);
	return -EINVAL;
}

static void scan_reply(DBusPendingCall *call, void *user_data)
{
	struct supplicant_task *task = user_data;
	DBusMessage *reply;

	DBG("task %p", task);

	task->scan_call = NULL;

	reply = dbus_pending_call_steal_reply(call);

	if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR) {
		connman_device_set_scanning(task->device, FALSE);
		goto done;
	}

	if (task->scanning == TRUE)
		connman_device_set_scanning(task->device, TRUE);

done:
	dbus_message_unref(reply);

	dbus_pending_call_unref(call);
}


static int initiate_scan(struct supplicant_task *task)
{
	DBusMessage *message;

	DBG("task %p", task);

	if (task->path == NULL)
		return -EINVAL;

	if (task->scan_call != NULL)
		return -EALREADY;

	message = dbus_message_new_method_call(SUPPLICANT_NAME, task->path,
					SUPPLICANT_INTF ".Interface", "scan");
	if (message == NULL)
		return -ENOMEM;

	dbus_message_set_auto_start(message, FALSE);

	if (dbus_connection_send_with_reply(connection, message,
					&task->scan_call, TIMEOUT) == FALSE) {
		connman_error("Failed to initiate scan");
		dbus_message_unref(message);
		return -EIO;
	}

	if (task->scan_call == NULL) {
		connman_error("D-Bus connection not available");
		dbus_message_unref(message);
		return -EIO;
	}

	dbus_pending_call_set_notify(task->scan_call, scan_reply, task, NULL);

	dbus_message_unref(message);

	return -EINPROGRESS;
}

static struct {
	char *name;
	char *value;
} special_ssid[] = {
	{ "<hidden>", "hidden"  },
	{ "default",  "linksys" },
	{ "wireless"  },
	{ "linksys"   },
	{ "netgear"   },
	{ "dlink"     },
	{ "2wire"     },
	{ "compaq"    },
	{ "tsunami"   },
	{ "comcomcom", "3com"     },
	{ "3Com",      "3com"     },
	{ "Symbol",    "symbol"   },
	{ "Motorola",  "motorola" },
	{ "Wireless" , "wireless" },
	{ "WLAN",      "wlan"     },
	{ }
};

static char *build_group(const char *addr, const char *name,
			const unsigned char *ssid, unsigned int ssid_len,
					const char *mode, const char *security)
{
	GString *str;
	unsigned int i;

	if (addr == NULL)
		return NULL;

	str = g_string_sized_new((ssid_len * 2) + 24);
	if (str == NULL)
		return NULL;

	if (ssid == NULL) {
		g_string_append_printf(str, "hidden_%s", addr);
		goto done;
	}

	for (i = 0; special_ssid[i].name; i++) {
		if (g_strcmp0(special_ssid[i].name, name) == 0) {
			if (special_ssid[i].value == NULL)
				g_string_append_printf(str, "%s_%s",
								name, addr);
			else
				g_string_append_printf(str, "%s_%s",
						special_ssid[i].value, addr);
			goto done;
		}
	}

	if (ssid_len > 0 && ssid[0] != '\0') {
		for (i = 0; i < ssid_len; i++)
			g_string_append_printf(str, "%02x", ssid[i]);
	} else
		g_string_append_printf(str, "hidden_%s", addr);

done:
	g_string_append_printf(str, "_%s_%s", mode, security);

	return g_string_free(str, FALSE);
}

static void extract_addr(DBusMessageIter *value,
					struct supplicant_result *result)
{
	DBusMessageIter array;
	struct ether_addr eth;
	unsigned char *addr;
	int addr_len;

	dbus_message_iter_recurse(value, &array);
	dbus_message_iter_get_fixed_array(&array, &addr, &addr_len);

	if (addr_len != 6)
		return;

	result->addr = g_try_malloc(addr_len);
	if (result->addr == NULL)
		return;

	memcpy(result->addr, addr, addr_len);
	result->addr_len = addr_len;

	result->path = g_try_malloc0(13);
	if (result->path == NULL)
		return;

	memcpy(&eth, addr, sizeof(eth));
	snprintf(result->path, 13, "%02x%02x%02x%02x%02x%02x",
						eth.ether_addr_octet[0],
						eth.ether_addr_octet[1],
						eth.ether_addr_octet[2],
						eth.ether_addr_octet[3],
						eth.ether_addr_octet[4],
						eth.ether_addr_octet[5]);
}

static void extract_ssid(DBusMessageIter *value,
					struct supplicant_result *result)
{
	DBusMessageIter array;
	unsigned char *ssid;
	int ssid_len, i;

	dbus_message_iter_recurse(value, &array);
	dbus_message_iter_get_fixed_array(&array, &ssid, &ssid_len);

	if (ssid_len < 1)
		return;

	if (ssid[0] == '\0')
		return;

	result->ssid = g_try_malloc(ssid_len);
	if (result->ssid == NULL)
		return;

	memcpy(result->ssid, ssid, ssid_len);
	result->ssid_len = ssid_len;

	result->name = g_try_malloc0(ssid_len + 1);
	if (result->name == NULL)
		return;

	for (i = 0; i < ssid_len; i++) {
		if (g_ascii_isprint(ssid[i]))
			result->name[i] = ssid[i];
		else
			result->name[i] = ' ';
	}
}

static unsigned char wifi_oui[3]      = { 0x00, 0x50, 0xf2 };
static unsigned char ieee80211_oui[3] = { 0x00, 0x0f, 0xac };

static void extract_rsn(struct supplicant_result *result,
					const unsigned char *buf, int len)
{
	uint16_t count;
	int i;

	/* Version */
	if (len < 2)
		return;

	buf += 2;
	len -= 2;

	/* Group cipher */
	if (len < 4)
		return;

	buf += 4;
	len -= 4;

	/* Pairwise cipher */
	if (len < 2)
		return;

	count = buf[0] | (buf[1] << 8);
	if (2 + (count * 4) > len)
		return;

	buf += 2 + (count * 4);
	len -= 2 + (count * 4);

	/* Authentication */
	if (len < 2)
		return;

	count = buf[0] | (buf[1] << 8);
	if (2 + (count * 4) > len)
		return;

	for (i = 0; i < count; i++) {
		const unsigned char *ptr = buf + 2 + (i * 4);

		if (memcmp(ptr, wifi_oui, 3) == 0) {
			switch (ptr[3]) {
			case 1:
				result->has_8021x = TRUE;
				break;
			case 2:
				result->has_psk = TRUE;
				break;
			}
		} else if (memcmp(ptr, ieee80211_oui, 3) == 0) {
			switch (ptr[3]) {
			case 1:
				result->has_8021x = TRUE;
				break;
			case 2:
				result->has_psk = TRUE;
				break;
			}
		}
	}

	buf += 2 + (count * 4);
	len -= 2 + (count * 4);
}

static void extract_wpaie(DBusMessageIter *value,
					struct supplicant_result *result)
{
	DBusMessageIter array;
	unsigned char *ie;
	int ie_len;

	dbus_message_iter_recurse(value, &array);
	dbus_message_iter_get_fixed_array(&array, &ie, &ie_len);

	if (ie_len > 6) {
		result->has_wpa = TRUE;
		extract_rsn(result, ie + 6, ie_len - 6);
	}
}

static void extract_rsnie(DBusMessageIter *value,
					struct supplicant_result *result)
{
	DBusMessageIter array;
	unsigned char *ie;
	int ie_len;

	dbus_message_iter_recurse(value, &array);
	dbus_message_iter_get_fixed_array(&array, &ie, &ie_len);

	if (ie_len > 2) {
		result->has_rsn = TRUE;
		extract_rsn(result, ie + 2, ie_len - 2);
	}
}

static void extract_wpsie(DBusMessageIter *value,
					struct supplicant_result *result)
{
	DBusMessageIter array;
	unsigned char *ie;
	int ie_len;

	dbus_message_iter_recurse(value, &array);
	dbus_message_iter_get_fixed_array(&array, &ie, &ie_len);

	if (ie_len > 0)
		result->has_wps = TRUE;
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

static unsigned char calculate_strength(struct supplicant_task *task,
					struct supplicant_result *result)
{
	if (result->quality == -1 || task->range->max_qual.qual == 0) {
		unsigned char strength;

		if (result->level > 0)
			strength = 100 - result->level;
		else
			strength = 120 + result->level;

		if (strength > 100)
			strength = 100;

		return strength;
	}

	return (result->quality * 100) / task->range->max_qual.qual;
}

static unsigned short calculate_channel(struct supplicant_result *result)
{
	if (result->frequency < 0)
		return 0;

	return (result->frequency - 2407) / 5;
}

static void get_properties(struct supplicant_task *task);

static void properties_reply(DBusPendingCall *call, void *user_data)
{
	struct supplicant_task *task = user_data;
	struct supplicant_result result;
	struct supplicant_block *block;
	struct connman_network *network;
	DBusMessage *reply;
	DBusMessageIter array, dict;
	unsigned char strength;
	unsigned short channel, frequency;
	const char *mode, *security;
	char *group = NULL;

	DBG("task %p", task);

	reply = dbus_pending_call_steal_reply(call);

	if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR)
		goto unref;

	memset(&result, 0, sizeof(result));
	result.frequency = -1;
	result.quality = -1;
	result.level = 0;
	result.noise = 0;

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
		 * wpsie        : a (97)
		 * frequency    : i (105)
		 * capabilities : q (113)
		 * quality      : i (105)
		 * noise        : i (105)
		 * level        : i (105)
		 * maxrate      : i (105)
		 */

		if (g_str_equal(key, "bssid") == TRUE)
			extract_addr(&value, &result);
		else if (g_str_equal(key, "ssid") == TRUE)
			extract_ssid(&value, &result);
		else if (g_str_equal(key, "wpaie") == TRUE)
			extract_wpaie(&value, &result);
		else if (g_str_equal(key, "rsnie") == TRUE)
			extract_rsnie(&value, &result);
		else if (g_str_equal(key, "wpsie") == TRUE)
			extract_wpsie(&value, &result);
		else if (g_str_equal(key, "capabilities") == TRUE)
			extract_capabilites(&value, &result);
		else if (g_str_equal(key, "frequency") == TRUE)
			dbus_message_iter_get_basic(&value, &result.frequency);
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

	DBG("capabilties %u frequency %d "
			"quality %d noise %d level %d maxrate %d",
					result.capabilities, result.frequency,
						result.quality, result.noise,
						result.level, result.maxrate);

	if (result.path == NULL)
		goto done;

	if (result.path[0] == '\0')
		goto done;

	if (result.name) {
		block = g_hash_table_lookup(task->hidden_blocks, result.name);
		if (block) {
			enable_network(task, block->netpath, FALSE);
			g_hash_table_remove(task->hidden_blocks, block->ssid);
		}
	}

	if (result.ssid == NULL)
		task->hidden_found = TRUE;

	if (result.frequency > 0 && result.frequency < 14)
		result.frequency = 2407 + (5 * result.frequency);
	else if (result.frequency == 14)
		result.frequency = 2484;

	strength = calculate_strength(task, &result);
	channel  = calculate_channel(&result);

	frequency = (result.frequency < 0) ? 0 : result.frequency;

	if (result.has_8021x == TRUE)
		security = "ieee8021x";
	else if (result.has_psk == TRUE)
		security = "psk";
	else if (result.has_wep == TRUE)
		security = "wep";
	else
		security = "none";

	mode = (result.adhoc == TRUE) ? "adhoc" : "managed";

	group = build_group(result.path, result.name,
					result.ssid, result.ssid_len,
							mode, security);

	if (result.has_psk == TRUE) {
		if (result.has_rsn == TRUE)
			security = "rsn";
		else if (result.has_wpa == TRUE)
			security = "wpa";
	}

	network = connman_device_get_network(task->device, result.path);
	if (network == NULL) {
		int index;

		network = connman_network_create(result.path,
						CONNMAN_NETWORK_TYPE_WIFI);
		if (network == NULL)
			goto done;

		index = connman_device_get_index(task->device);
		connman_network_set_index(network, index);

		connman_network_set_protocol(network,
						CONNMAN_NETWORK_PROTOCOL_IP);

		connman_network_set_address(network, result.addr,
							result.addr_len);

		if (connman_device_add_network(task->device, network) < 0) {
			connman_network_unref(network);
			goto done;
		}
	}

	if (result.name != NULL && result.name[0] != '\0')
		connman_network_set_name(network, result.name);

	if (result.ssid_len != 0)
		connman_network_set_blob(network, "WiFi.SSID",
						result.ssid, result.ssid_len);

	connman_network_set_string(network, "WiFi.Mode", mode);

	DBG("%s (%s %s) strength %d (%s)",
				result.name, mode, security, strength,
				(result.has_wps == TRUE) ? "WPS" : "no WPS");

	connman_network_set_available(network, TRUE);
	connman_network_set_strength(network, strength);

	connman_network_set_uint16(network, "Frequency", frequency);
	connman_network_set_uint16(network, "WiFi.Channel", channel);
	connman_network_set_string(network, "WiFi.Security", security);

	if (result.ssid != NULL)
		connman_network_set_group(network, group);

done:
	g_free(group);

	g_free(result.path);
	g_free(result.addr);
	g_free(result.name);
	g_free(result.ssid);

unref:
	dbus_message_unref(reply);

	dbus_pending_call_unref(call);

	get_properties(task);
}

static void get_properties(struct supplicant_task *task)
{
	DBusMessage *message;
	char *path;

	path = g_slist_nth_data(task->scan_results, 0);
	if (path == NULL) {
		if (task->hidden_found == TRUE) {
			/*
			 * We're done with regular scanning, let's enable
			 * the missing network blocks if there are hidden
			 * SSIDs around.
			 */
			hidden_block_enable(task);
		}
		goto noscan;
	}

	message = dbus_message_new_method_call(SUPPLICANT_NAME, path,
						SUPPLICANT_INTF ".BSSID",
								"properties");

	task->scan_results = g_slist_remove(task->scan_results, path);
	g_free(path);

	if (message == NULL)
		goto noscan;

	dbus_message_set_auto_start(message, FALSE);

	if (dbus_connection_send_with_reply(connection, message,
				&task->result_call, TIMEOUT) == FALSE) {
		connman_error("Failed to get network properties");
		dbus_message_unref(message);
		goto noscan;
	}

	if (task->result_call == NULL) {
		connman_error("D-Bus connection not available");
		dbus_message_unref(message);
		goto noscan;
	}

	dbus_pending_call_set_notify(task->result_call,
					properties_reply, task, NULL);

	dbus_message_unref(message);

	return;

noscan:
	task->result_call = NULL;

	if (task->scanning == TRUE) {
		connman_device_set_scanning(task->device, FALSE);
		task->scanning = FALSE;
	}
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

	task->hidden_found = FALSE;

	g_strfreev(results);

	dbus_message_unref(reply);

	dbus_pending_call_unref(call);

	get_properties(task);

	return;

done:
	dbus_message_unref(reply);

	dbus_pending_call_unref(call);

	task->result_call = NULL;

	if (task->scanning == TRUE) {
		connman_device_set_scanning(task->device, FALSE);
		task->scanning = FALSE;
	}
}

static void scan_results_available(struct supplicant_task *task)
{
	DBusMessage *message;

	DBG("task %p", task);

	if (task->result_call != NULL)
		return;

	message = dbus_message_new_method_call(SUPPLICANT_NAME, task->path,
						SUPPLICANT_INTF ".Interface",
							"scanResults");
	if (message == NULL)
		return;

	dbus_message_set_auto_start(message, FALSE);

	if (dbus_connection_send_with_reply(connection, message,
				&task->result_call, TIMEOUT) == FALSE) {
		connman_error("Failed to request scan result");
		goto done;
	}

	if (task->result_call == NULL) {
		connman_error("D-Bus connection not available");
		goto done;
	}

	if (task->scanning == TRUE)
		connman_device_set_scanning(task->device, TRUE);

	dbus_pending_call_set_notify(task->result_call,
					scan_results_reply, task, NULL);

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

static int task_connect(struct supplicant_task *task)
{
	const char *address, *security, *passphrase;
	const void *ssid;
	unsigned int ssid_len;
	int err;

	g_hash_table_foreach(task->hidden_blocks, block_reset, task);

	connman_inet_ifup(task->ifindex);

	address = connman_network_get_string(task->network, "Address");
	security = connman_network_get_string(task->network, "WiFi.Security");
	passphrase = connman_network_get_string(task->network, "WiFi.Passphrase");

	ssid = connman_network_get_blob(task->network, "WiFi.SSID", &ssid_len);

	DBG("address %s security %s", address, security);

	if (security == NULL)
		return -EINVAL;

	if (passphrase == NULL && g_str_equal(security, "none") == FALSE &&
				g_str_equal(security, "ieee8021x") == FALSE)
		return -EINVAL;

	remove_network(task);

	set_ap_scan(task);

	add_network(task);

	err = set_network(task, ssid, ssid_len, address, security, passphrase);
	if (err < 0)
		return err;

	err = select_network(task);
	if (err < 0)
		return err;

	return -EINPROGRESS;
}

static void scanning(struct supplicant_task *task, DBusMessage *msg)
{
	DBusError error;
	dbus_bool_t scanning;

	dbus_error_init(&error);

	if (dbus_message_get_args(msg, &error, DBUS_TYPE_BOOLEAN, &scanning,
						DBUS_TYPE_INVALID) == FALSE) {
		if (dbus_error_is_set(&error) == TRUE) {
			connman_error("%s", error.message);
			dbus_error_free(&error);
		} else
			connman_error("Wrong arguments for scanning");
		return;
	}

	connman_info("%s scanning %s", task->ifname,
				scanning == TRUE ? "started" : "finished");
}

static void state_change(struct supplicant_task *task, DBusMessage *msg)
{
	DBusError error;
	const char *newstate, *oldstate;
	unsigned char bssid[ETH_ALEN];
	unsigned int bssid_len;
	enum supplicant_state state, prevstate;

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

	connman_info("%s %s%s", task->ifname, newstate,
				task->scanning == TRUE ? " (scanning)" : "");

	state = string2state(newstate);
	if (state == WPA_INVALID)
		return;

	prevstate = task->state;
	task->state = state;

	if (task->network == NULL)
		return;

	switch (task->state) {
	case WPA_COMPLETED:
		switch (prevstate) {
		case WPA_ASSOCIATED:
		case WPA_GROUP_HANDSHAKE:
			break;
		default:
			goto badstate;
		}

		/* reset scan trigger and schedule background scan */
		connman_device_schedule_scan(task->device);

		if (get_bssid(task->device, bssid, &bssid_len) == 0)
			connman_network_set_address(task->network,
							bssid, bssid_len);

		/* carrier on */
		connman_network_set_connected(task->network, TRUE);
		break;

	case WPA_ASSOCIATING:
		switch (prevstate) {
		case WPA_COMPLETED:
			break;
		case WPA_SCANNING:
			connman_network_set_associating(task->network, TRUE);
			break;
		default:
			goto badstate;
		}
		break;

	case WPA_INACTIVE:
		switch (prevstate) {
		case WPA_SCANNING:
		case WPA_DISCONNECTED:
			break;
		default:
			goto badstate;
		}
		/* fall through */

	case WPA_DISCONNECTED:
		/* carrier off */
		connman_network_set_connected(task->network, FALSE);

		if (task->disconnecting == TRUE) {
			connman_network_unref(task->network);
			task->disconnecting = FALSE;

			if (task->pending_network != NULL) {
				task->network = task->pending_network;
				task->pending_network = NULL;
				task_connect(task);
			} else
				task->network = NULL;
		} else
			remove_network(task);

		break;

	default:
		connman_network_set_associating(task->network, FALSE);
		break;
	}

	return;

badstate:
	connman_error("%s invalid state change %s -> %s", task->ifname,
							oldstate, newstate);
}

static gboolean supplicant_filter(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct supplicant_task *task;
	const char *member, *path;

	member = dbus_message_get_member(msg);
	if (member == NULL)
		return TRUE;

	path = dbus_message_get_path(msg);
	if (path == NULL)
		return TRUE;

	task = find_task_by_path(path);
	if (task == NULL)
		return TRUE;

	DBG("task %p member %s", task, member);

	if (g_str_equal(member, "ScanResultsAvailable") == TRUE)
		scan_results_available(task);
	else if (g_str_equal(member, "Scanning") == TRUE)
		scanning(task, msg);
	else if (g_str_equal(member, "StateChange") == TRUE)
		state_change(task, msg);

	return TRUE;
}

int supplicant_start(struct connman_device *device)
{
	struct supplicant_task *task;
	int err;

	DBG("device %p", device);

	task = g_try_new0(struct supplicant_task, 1);
	if (task == NULL)
		return -ENOMEM;

	task->ifindex = connman_device_get_index(device);
	task->ifname = connman_inet_ifname(task->ifindex);

	if (task->ifname == NULL) {
		err = -ENOMEM;
		goto failed;
	}

	task->cfg80211 = connman_inet_is_cfg80211(task->ifindex);
	if (task->cfg80211 == FALSE)
		connman_warn("Enabling quirks for unsupported driver");

	task->range = g_try_malloc0(sizeof(struct iw_range));
	if (task->range == NULL) {
		err = -ENOMEM;
		goto failed;
	}

	err = get_range(task);
	if (err < 0)
		goto failed;

	task->device = connman_device_ref(device);

	task->created = FALSE;
	task->scanning = FALSE;
	task->state = WPA_INVALID;
	task->disconnecting = FALSE;
	task->pending_network = NULL;
	task->hidden_blocks = g_hash_table_new_full(g_str_hash, g_str_equal,
							NULL, remove_block);
	task_list = g_slist_append(task_list, task);

	return create_interface(task);

failed:
	g_free(task->range);
	g_free(task->ifname);
	g_free(task);

	return err;
}

int supplicant_stop(struct connman_device *device)
{
	int index = connman_device_get_index(device);
	struct supplicant_task *task;

	DBG("device %p", device);

	task = find_task_by_index(index);
	if (task == NULL)
		return -ENODEV;

	g_free(task->range);

	task_list = g_slist_remove(task_list, task);
	g_hash_table_destroy(task->hidden_blocks);

	if (task->scan_call != NULL) {
		dbus_pending_call_cancel(task->scan_call);
		task->scan_call = NULL;
	}

	if (task->result_call != NULL) {
		dbus_pending_call_cancel(task->result_call);
		task->result_call = NULL;
	}

	if (task->scanning == TRUE)
		connman_device_set_scanning(task->device, FALSE);

	remove_network(task);

	disconnect_network(task);

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

	task->scanning = TRUE;

	err = initiate_scan(task);
	if (err < 0) {
		if (err == -EINPROGRESS)
			return 0;

		task->scanning = FALSE;
		return err;
	}

	connman_device_set_scanning(task->device, TRUE);

	return 0;
}

int supplicant_connect(struct connman_network *network)
{
	struct supplicant_task *task;
	int index;

	DBG("network %p", network);

	index = connman_network_get_index(network);

	task = find_task_by_index(index);
	if (task == NULL)
		return -ENODEV;

	if (task->disconnecting == TRUE)
		task->pending_network = connman_network_ref(network);
	else {
		task->network = connman_network_ref(network);
		return task_connect(task);
	}

	return -EINPROGRESS;
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

	if (task->disconnecting == TRUE)
		return -EALREADY;

	remove_network(task);

	disconnect_network(task);

	task->disconnecting = TRUE;

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

static guint watch;
static guint iface_watch;

static int supplicant_create(void)
{
	if (g_slist_length(driver_list) > 0)
		return 0;

	connection = connman_dbus_get_connection();
	if (connection == NULL)
		return -EIO;

	DBG("connection %p", connection);

	watch = g_dbus_add_service_watch(connection, SUPPLICANT_NAME,
			supplicant_probe, supplicant_remove, NULL, NULL);

	iface_watch = g_dbus_add_signal_watch(connection, NULL, NULL,
						SUPPLICANT_INTF ".Interface",
						NULL, supplicant_filter,
						NULL, NULL);

	if (watch == 0 || iface_watch == 0) {
		g_dbus_remove_watch(connection, watch);
		g_dbus_remove_watch(connection, iface_watch);
		return -EIO;
	}

	return 0;
}

static void supplicant_destroy(void)
{
	if (g_slist_length(driver_list) > 0)
		return;

	DBG("connection %p", connection);

	g_dbus_remove_watch(connection, watch);
	g_dbus_remove_watch(connection, iface_watch);

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
