/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2012  Intel Corporation. All rights reserved.
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

#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_arp.h>
#include <linux/wireless.h>
#include <net/ethernet.h>

#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP	0x10000
#endif

#include <dbus/dbus.h>
#include <glib.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/inet.h>
#include <connman/device.h>
#include <connman/rtnl.h>
#include <connman/technology.h>
#include <connman/log.h>
#include <connman/option.h>
#include <connman/storage.h>
#include <include/setting.h>

#include <gsupplicant/gsupplicant.h>

#define CLEANUP_TIMEOUT   8	/* in seconds */
#define INACTIVE_TIMEOUT  12	/* in seconds */
#define MAXIMUM_RETRIES   4

#define BGSCAN_DEFAULT "simple:30:-45:300"
#define AUTOSCAN_DEFAULT "exponential:3:300"

static struct connman_technology *wifi_technology = NULL;

struct hidden_params {
	char ssid[32];
	unsigned int ssid_len;
	char *identity;
	char *passphrase;
	gpointer user_data;
};

/**
 * Used for autoscan "emulation".
 * Should be removed when wpa_s autoscan support will be by default.
 */
struct autoscan_params {
	int base;
	int limit;
	int interval;
	unsigned int timeout;
};

struct wifi_data {
	char *identifier;
	struct connman_device *device;
	struct connman_network *network;
	struct connman_network *pending_network;
	GSList *networks;
	GSupplicantInterface *interface;
	GSupplicantState state;
	connman_bool_t connected;
	connman_bool_t disconnecting;
	connman_bool_t tethering;
	connman_bool_t bridged;
	const char *bridge;
	int index;
	unsigned flags;
	unsigned int watch;
	int retries;
	struct hidden_params *hidden;
	/**
	 * autoscan "emulation".
	 */
	struct autoscan_params *autoscan;
};

static GList *iface_list = NULL;

static void start_autoscan(struct connman_device *device);

static void handle_tethering(struct wifi_data *wifi)
{
	if (wifi->tethering == FALSE)
		return;

	if (wifi->bridge == NULL)
		return;

	if (wifi->bridged == TRUE)
		return;

	DBG("index %d bridge %s", wifi->index, wifi->bridge);

	if (connman_inet_add_to_bridge(wifi->index, wifi->bridge) < 0)
		return;

	wifi->bridged = TRUE;
}

static void wifi_newlink(unsigned flags, unsigned change, void *user_data)
{
	struct connman_device *device = user_data;
	struct wifi_data *wifi = connman_device_get_data(device);

	if (wifi == NULL)
		return;

	DBG("index %d flags %d change %d", wifi->index, flags, change);

	if (!change)
		return;

	if ((wifi->flags & IFF_UP) != (flags & IFF_UP)) {
		if (flags & IFF_UP)
			DBG("interface up");
		else
			DBG("interface down");
	}

	if ((wifi->flags & IFF_LOWER_UP) != (flags & IFF_LOWER_UP)) {
		if (flags & IFF_LOWER_UP) {
			DBG("carrier on");

			handle_tethering(wifi);
		} else
			DBG("carrier off");
	}

	wifi->flags = flags;
}

static int wifi_probe(struct connman_device *device)
{
	struct wifi_data *wifi;

	DBG("device %p", device);

	wifi = g_try_new0(struct wifi_data, 1);
	if (wifi == NULL)
		return -ENOMEM;

	wifi->connected = FALSE;
	wifi->disconnecting = FALSE;
	wifi->tethering = FALSE;
	wifi->bridged = FALSE;
	wifi->bridge = NULL;
	wifi->state = G_SUPPLICANT_STATE_INACTIVE;

	connman_device_set_data(device, wifi);
	wifi->device = connman_device_ref(device);

	wifi->index = connman_device_get_index(device);
	wifi->flags = 0;

	wifi->watch = connman_rtnl_add_newlink_watch(wifi->index,
							wifi_newlink, device);

	iface_list = g_list_append(iface_list, wifi);

	return 0;
}

static void remove_networks(struct connman_device *device,
				struct wifi_data *wifi)
{
	GSList *list;

	for (list = wifi->networks; list != NULL; list = list->next) {
		struct connman_network *network = list->data;

		connman_device_remove_network(device, network);
		connman_network_unref(network);
	}

	g_slist_free(wifi->networks);
	wifi->networks = NULL;
}

static void reset_autoscan(struct connman_device *device)
{
	struct wifi_data *wifi = connman_device_get_data(device);
	struct autoscan_params *autoscan;

	DBG("");

	if (wifi == NULL || wifi->autoscan == NULL)
		return;

	autoscan = wifi->autoscan;

	if (autoscan->timeout == 0 && autoscan->interval == 0)
		return;

	g_source_remove(autoscan->timeout);

	autoscan->timeout = 0;
	autoscan->interval = 0;

	connman_device_unref(device);
}

static void stop_autoscan(struct connman_device *device)
{
	reset_autoscan(device);

	connman_device_set_scanning(device, FALSE);
}

static void wifi_remove(struct connman_device *device)
{
	struct wifi_data *wifi = connman_device_get_data(device);

	DBG("device %p wifi %p", device, wifi);

	if (wifi == NULL)
		return;

	iface_list = g_list_remove(iface_list, wifi);

	remove_networks(device, wifi);

	connman_device_set_powered(device, FALSE);
	connman_device_set_data(device, NULL);
	connman_device_unref(wifi->device);
	connman_rtnl_remove_watch(wifi->watch);

	g_supplicant_interface_set_data(wifi->interface, NULL);

	g_free(wifi->autoscan);
	g_free(wifi->identifier);
	g_free(wifi);
}

static int add_scan_param(gchar *hex_ssid, int freq,
			GSupplicantScanParams *scan_data,
			int driver_max_scan_ssids)
{
	unsigned int i;
	struct scan_ssid *scan_ssid;

	if (driver_max_scan_ssids > scan_data->num_ssids && hex_ssid != NULL) {
		gchar *ssid;
		unsigned int j = 0, hex;
		size_t hex_ssid_len = strlen(hex_ssid);

		ssid = g_try_malloc0(hex_ssid_len / 2);
		if (ssid == NULL)
			return -ENOMEM;

		for (i = 0; i < hex_ssid_len; i += 2) {
			sscanf(hex_ssid + i, "%02x", &hex);
			ssid[j++] = hex;
		}

		scan_ssid = g_try_new(struct scan_ssid, 1);
		if (scan_ssid == NULL) {
			g_free(ssid);
			return -ENOMEM;
		}

		memcpy(scan_ssid->ssid, ssid, j);
		scan_ssid->ssid_len = j;
		scan_data->ssids = g_slist_prepend(scan_data->ssids,
								scan_ssid);

		scan_data->num_ssids++;

		g_free(ssid);
	} else
		return -EINVAL;

	scan_data->ssids = g_slist_reverse(scan_data->ssids);

	if (scan_data->freqs == NULL) {
		scan_data->freqs = g_try_malloc0(sizeof(uint16_t) *
						scan_data->num_ssids);
		if (scan_data->freqs == NULL) {
			g_slist_free_full(scan_data->ssids, g_free);
			return -ENOMEM;
		}
	} else {
		scan_data->freqs = g_try_realloc(scan_data->freqs,
				sizeof(uint16_t) * scan_data->num_ssids);
		if (scan_data->freqs == NULL) {
			g_slist_free_full(scan_data->ssids, g_free);
			return -ENOMEM;
		}
		scan_data->freqs[scan_data->num_ssids - 1] = 0;
	}

	/* Don't add duplicate entries */
	for (i = 0; i < scan_data->num_ssids; i++) {
		if (scan_data->freqs[i] == 0) {
			scan_data->freqs[i] = freq;
			break;
		} else if (scan_data->freqs[i] == freq)
			break;
	}

	return 0;
}

static int get_hidden_connections(int max_ssids,
				GSupplicantScanParams *scan_data)
{
	GKeyFile *keyfile;
	gchar **services;
	char *ssid;
	gchar *str;
	int i, freq;
	gboolean value;
	int num_ssids = 0, add_param_failed = 0;

	services = connman_storage_get_services();
	for (i = 0; services && services[i]; i++) {
		if (strncmp(services[i], "wifi_", 5) != 0)
			continue;

		keyfile = connman_storage_load_service(services[i]);

		value = g_key_file_get_boolean(keyfile,
					services[i], "Hidden", NULL);
		if (value == FALSE) {
			g_key_file_free(keyfile);
			continue;
		}

		value = g_key_file_get_boolean(keyfile,
					services[i], "Favorite", NULL);
		if (value == FALSE) {
			g_key_file_free(keyfile);
			continue;
		}

		value = g_key_file_get_boolean(keyfile,
					services[i], "AutoConnect", NULL);
		if (value == FALSE) {
			g_key_file_free(keyfile);
			continue;
		}

		ssid = g_key_file_get_string(keyfile,
					services[i], "SSID", NULL);

		freq = g_key_file_get_integer(keyfile, services[i],
					"Frequency", NULL);

		if (add_scan_param(ssid, freq, scan_data, max_ssids) < 0) {
			str = g_key_file_get_string(keyfile,
					services[i], "Name", NULL);
			DBG("Cannot scan %s (%s)", ssid, str);
			g_free(str);
			add_param_failed++;
		}

		num_ssids++;

		g_key_file_free(keyfile);
	}

	if (add_param_failed > 0)
		connman_warn("Unable to scan %d out of %d SSIDs (max is %d)",
			add_param_failed, num_ssids, max_ssids);

	g_strfreev(services);

	return num_ssids > max_ssids ? max_ssids : num_ssids;
}

static int throw_wifi_scan(struct connman_device *device,
			GSupplicantInterfaceCallback callback)
{
	struct wifi_data *wifi = connman_device_get_data(device);
	int ret;

	if (wifi == NULL)
		return -ENODEV;

	DBG("device %p %p", device, wifi->interface);

	if (wifi->tethering == TRUE)
		return 0;

	if (connman_device_get_scanning(device) == TRUE)
		return -EALREADY;

	connman_device_ref(device);

	ret = g_supplicant_interface_scan(wifi->interface, NULL,
						callback, device);
	if (ret == 0)
		connman_device_set_scanning(device, TRUE);
	else
		connman_device_unref(device);

	return ret;
}

static void hidden_free(struct hidden_params *hidden)
{
	if (hidden == NULL)
		return;

	g_free(hidden->identity);
	g_free(hidden->passphrase);
	g_free(hidden);
}

static void scan_callback(int result, GSupplicantInterface *interface,
						void *user_data)
{
	struct connman_device *device = user_data;
	struct wifi_data *wifi = connman_device_get_data(device);

	DBG("result %d wifi %p", result, wifi);

	if (wifi != NULL && wifi->hidden != NULL) {
		connman_network_clear_hidden(wifi->hidden->user_data);
		hidden_free(wifi->hidden);
		wifi->hidden = NULL;
	}

	if (result < 0)
		connman_device_reset_scanning(device);

	connman_device_set_scanning(device, FALSE);
	start_autoscan(device);
	connman_device_unref(device);
}

static void scan_callback_hidden(int result,
			GSupplicantInterface *interface, void *user_data)
{
	struct connman_device *device = user_data;
	struct wifi_data *wifi = connman_device_get_data(device);
	int driver_max_ssids;

	DBG("result %d wifi %p", result, wifi);

	if (wifi == NULL)
		goto out;

	/*
	 * Scan hidden networks so that we can autoconnect to them.
	 */
	driver_max_ssids = g_supplicant_interface_get_max_scan_ssids(
							wifi->interface);
	DBG("max ssids %d", driver_max_ssids);

	if (driver_max_ssids > 0) {
		GSupplicantScanParams *scan_params;
		int ret;

		scan_params = g_try_malloc0(sizeof(GSupplicantScanParams));
		if (scan_params == NULL)
			goto out;

		if (get_hidden_connections(driver_max_ssids,
						scan_params) > 0) {
			ret = g_supplicant_interface_scan(wifi->interface,
							scan_params,
							scan_callback,
							device);
			if (ret == 0)
				return;
		}

		g_supplicant_free_scan_params(scan_params);
	}

out:
	scan_callback(result, interface, user_data);
}

static gboolean autoscan_timeout(gpointer data)
{
	struct connman_device *device = data;
	struct wifi_data *wifi = connman_device_get_data(device);
	struct autoscan_params *autoscan;
	int interval;

	if (wifi == NULL)
		return FALSE;

	autoscan = wifi->autoscan;

	if (autoscan->interval <= 0) {
		interval = autoscan->base;
		goto set_interval;
	} else
		interval = autoscan->interval * autoscan->base;

	if (autoscan->interval >= autoscan->limit)
		interval = autoscan->limit;

	throw_wifi_scan(wifi->device, scan_callback_hidden);

set_interval:
	DBG("interval %d", interval);

	autoscan->interval = interval;

	autoscan->timeout = g_timeout_add_seconds(interval,
						autoscan_timeout, device);

	return FALSE;
}

static void start_autoscan(struct connman_device *device)
{
	struct wifi_data *wifi = connman_device_get_data(device);
	struct autoscan_params *autoscan;

	DBG("");

	if (wifi == NULL)
		return;

	autoscan = wifi->autoscan;
	if (autoscan == NULL)
		return;

	if (autoscan->timeout > 0 || autoscan->interval > 0)
		return;

	connman_device_ref(device);

	autoscan_timeout(device);
}

static struct autoscan_params *parse_autoscan_params(const char *params)
{
	struct autoscan_params *autoscan;
	char **list_params;
	int limit;
	int base;

	DBG("Emulating autoscan");

	list_params = g_strsplit(params, ":", 0);
	if (list_params == 0)
		return NULL;

	if (g_strv_length(list_params) < 3) {
		g_strfreev(list_params);
		return NULL;
	}

	base = atoi(list_params[1]);
	limit = atoi(list_params[2]);

	g_strfreev(list_params);

	autoscan = g_try_malloc0(sizeof(struct autoscan_params));
	if (autoscan == NULL) {
		DBG("Could not allocate memory for autoscan");
		return NULL;
	}

	DBG("base %d - limit %d", base, limit);
	autoscan->base = base;
	autoscan->limit = limit;

	return autoscan;
}

static void setup_autoscan(struct wifi_data *wifi)
{
	if (wifi->autoscan == NULL)
		wifi->autoscan = parse_autoscan_params(AUTOSCAN_DEFAULT);

	start_autoscan(wifi->device);
}

static void interface_create_callback(int result,
					GSupplicantInterface *interface,
							void *user_data)
{
	struct wifi_data *wifi = user_data;

	DBG("result %d ifname %s, wifi %p", result,
				g_supplicant_interface_get_ifname(interface),
				wifi);

	if (result < 0 || wifi == NULL)
		return;

	wifi->interface = interface;
	g_supplicant_interface_set_data(interface, wifi);

	if (g_supplicant_interface_get_ready(interface) == FALSE)
		return;

	DBG("interface is ready wifi %p tethering %d", wifi, wifi->tethering);

	if (wifi->device == NULL) {
		connman_error("WiFi device not set");
		return;
	}

	connman_device_set_powered(wifi->device, TRUE);

	if (connman_setting_get_bool("BackgroundScanning") == FALSE)
		return;

	/* Setting up automatic scanning */
	setup_autoscan(wifi);
}

static int wifi_enable(struct connman_device *device)
{
	struct wifi_data *wifi = connman_device_get_data(device);
	const char *interface = connman_device_get_string(device, "Interface");
	const char *driver = connman_option_get_string("wifi");
	int ret;

	DBG("device %p %p", device, wifi);

	if (wifi == NULL)
		return -ENODEV;

	ret = g_supplicant_interface_create(interface, driver, NULL,
						interface_create_callback,
							wifi);
	if (ret < 0)
		return ret;

	return -EINPROGRESS;
}

static int wifi_disable(struct connman_device *device)
{
	struct wifi_data *wifi = connman_device_get_data(device);
	int ret;

	DBG("device %p wifi %p", device, wifi);

	if (wifi == NULL)
		return -ENODEV;

	wifi->connected = FALSE;
	wifi->disconnecting = FALSE;

	if (wifi->pending_network != NULL)
		wifi->pending_network = NULL;

	stop_autoscan(device);

	/* In case of a user scan, device is still referenced */
	if (connman_device_get_scanning(device) == TRUE) {
		connman_device_set_scanning(device, FALSE);
		connman_device_unref(wifi->device);
	}

	remove_networks(device, wifi);

	ret = g_supplicant_interface_remove(wifi->interface, NULL, NULL);
	if (ret < 0)
		return ret;

	return -EINPROGRESS;
}

struct last_connected {
	GTimeVal modified;
	gchar *ssid;
	int freq;
};

static gint sort_entry(gconstpointer a, gconstpointer b, gpointer user_data)
{
	GTimeVal *aval = (GTimeVal *)a;
	GTimeVal *bval = (GTimeVal *)b;

	/* Note that the sort order is descending */
	if (aval->tv_sec < bval->tv_sec)
		return 1;

	if (aval->tv_sec > bval->tv_sec)
		return -1;

	return 0;
}

static void free_entry(gpointer data)
{
	struct last_connected *entry = data;

	g_free(entry->ssid);
	g_free(entry);
}

static int get_latest_connections(int max_ssids,
				GSupplicantScanParams *scan_data)
{
	GSequenceIter *iter;
	GSequence *latest_list;
	struct last_connected *entry;
	GKeyFile *keyfile;
	GTimeVal modified;
	gchar **services;
	gchar *str;
	char *ssid;
	int i, freq;
	int num_ssids = 0;

	latest_list = g_sequence_new(free_entry);
	if (latest_list == NULL)
		return -ENOMEM;

	services = connman_storage_get_services();
	for (i = 0; services && services[i]; i++) {
		if (strncmp(services[i], "wifi_", 5) != 0)
			continue;

		keyfile = connman_storage_load_service(services[i]);

		str = g_key_file_get_string(keyfile,
					services[i], "Favorite", NULL);
		if (str == NULL || g_strcmp0(str, "true")) {
			if (str)
				g_free(str);
			g_key_file_free(keyfile);
			continue;
		}
		g_free(str);

		str = g_key_file_get_string(keyfile,
					services[i], "AutoConnect", NULL);
		if (str == NULL || g_strcmp0(str, "true")) {
			if (str)
				g_free(str);
			g_key_file_free(keyfile);
			continue;
		}
		g_free(str);

		str = g_key_file_get_string(keyfile,
					services[i], "Modified", NULL);
		if (str != NULL) {
			g_time_val_from_iso8601(str, &modified);
			g_free(str);
		}

		ssid = g_key_file_get_string(keyfile,
					services[i], "SSID", NULL);

		freq = g_key_file_get_integer(keyfile, services[i],
					"Frequency", NULL);
		if (freq) {
			entry = g_try_new(struct last_connected, 1);
			if (entry == NULL) {
				g_sequence_free(latest_list);
				g_key_file_free(keyfile);
				g_free(ssid);
				return -ENOMEM;
			}

			entry->ssid = ssid;
			entry->modified = modified;
			entry->freq = freq;

			g_sequence_insert_sorted(latest_list, entry,
						sort_entry, NULL);
			num_ssids++;
		} else
			g_free(ssid);

		g_key_file_free(keyfile);
	}

	g_strfreev(services);

	num_ssids = num_ssids > max_ssids ? max_ssids : num_ssids;

	iter = g_sequence_get_begin_iter(latest_list);

	for (i = 0; i < num_ssids; i++) {
		entry = g_sequence_get(iter);

		DBG("ssid %s freq %d modified %lu", entry->ssid, entry->freq,
						entry->modified.tv_sec);

		add_scan_param(entry->ssid, entry->freq, scan_data, max_ssids);

		iter = g_sequence_iter_next(iter);
	}

	g_sequence_free(latest_list);
	return num_ssids;
}

static int wifi_scan(struct connman_device *device)
{
	reset_autoscan(device);

	return throw_wifi_scan(device, scan_callback_hidden);
}

static int wifi_scan_fast(struct connman_device *device)
{
	struct wifi_data *wifi = connman_device_get_data(device);
	GSupplicantScanParams *scan_params = NULL;
	int ret;
	int driver_max_ssids = 0;

	if (wifi == NULL)
		return -ENODEV;

	DBG("device %p %p", device, wifi->interface);

	if (wifi->tethering == TRUE)
		return 0;

	if (connman_device_get_scanning(device) == TRUE)
		return -EALREADY;

	driver_max_ssids = g_supplicant_interface_get_max_scan_ssids(
							wifi->interface);
	DBG("max ssids %d", driver_max_ssids);
	if (driver_max_ssids == 0)
		return wifi_scan(device);

	scan_params = g_try_malloc0(sizeof(GSupplicantScanParams));
	if (scan_params == NULL)
		return -ENOMEM;

	ret = get_latest_connections(driver_max_ssids, scan_params);
	if (ret <= 0) {
		g_supplicant_free_scan_params(scan_params);
		return wifi_scan(device);
	}

	connman_device_ref(device);
	reset_autoscan(device);

	ret = g_supplicant_interface_scan(wifi->interface, scan_params,
						scan_callback, device);
	if (ret == 0)
		connman_device_set_scanning(device, TRUE);
	else {
		g_supplicant_free_scan_params(scan_params);
		connman_device_unref(device);
	}

	return ret;
}

/*
 * This func is only used when connecting to this specific AP first time.
 * It is not used when system autoconnects to hidden AP.
 */
static int wifi_scan_hidden(struct connman_device *device,
		const char *ssid, unsigned int ssid_len,
		const char *identity, const char* passphrase,
		gpointer user_data)
{
	struct wifi_data *wifi = connman_device_get_data(device);
	GSupplicantScanParams *scan_params = NULL;
	struct scan_ssid *scan_ssid;
	struct hidden_params *hidden;
	int ret;

	if (wifi == NULL)
		return -ENODEV;

	DBG("hidden SSID %s", ssid);

	if (wifi->tethering == TRUE || wifi->hidden != NULL)
		return -EBUSY;

	if (ssid == NULL || ssid_len == 0 || ssid_len > 32)
		return -EINVAL;

	if (connman_device_get_scanning(device) == TRUE)
		return -EALREADY;

	scan_params = g_try_malloc0(sizeof(GSupplicantScanParams));
	if (scan_params == NULL)
		return -ENOMEM;

	scan_ssid = g_try_new(struct scan_ssid, 1);
	if (scan_ssid == NULL) {
		g_free(scan_params);
		return -ENOMEM;
	}

	memcpy(scan_ssid->ssid, ssid, ssid_len);
	scan_ssid->ssid_len = ssid_len;
	scan_params->ssids = g_slist_prepend(scan_params->ssids, scan_ssid);

	scan_params->num_ssids = 1;

	hidden = g_try_new0(struct hidden_params, 1);
	if (hidden == NULL) {
		g_free(scan_params);
		return -ENOMEM;
	}
	memcpy(hidden->ssid, ssid, ssid_len);
	hidden->ssid_len = ssid_len;
	hidden->identity = g_strdup(identity);
	hidden->passphrase = g_strdup(passphrase);
	hidden->user_data = user_data;
	wifi->hidden = hidden;

	connman_device_ref(device);

	reset_autoscan(device);

	ret = g_supplicant_interface_scan(wifi->interface, scan_params,
			scan_callback, device);
	if (ret == 0)
		connman_device_set_scanning(device, TRUE);
	else {
		connman_device_unref(device);
		g_supplicant_free_scan_params(scan_params);
		hidden_free(wifi->hidden);
		wifi->hidden = NULL;
	}

	return ret;
}

static struct connman_device_driver wifi_ng_driver = {
	.name		= "wifi",
	.type		= CONNMAN_DEVICE_TYPE_WIFI,
	.priority	= CONNMAN_DEVICE_PRIORITY_LOW,
	.probe		= wifi_probe,
	.remove		= wifi_remove,
	.enable		= wifi_enable,
	.disable	= wifi_disable,
	.scan		= wifi_scan,
	.scan_fast	= wifi_scan_fast,
	.scan_hidden    = wifi_scan_hidden,
};

static void system_ready(void)
{
	DBG("");

	if (connman_device_driver_register(&wifi_ng_driver) < 0)
		connman_error("Failed to register WiFi driver");
}

static void system_killed(void)
{
	DBG("");

	connman_device_driver_unregister(&wifi_ng_driver);
}

static int network_probe(struct connman_network *network)
{
	DBG("network %p", network);

	return 0;
}

static void network_remove(struct connman_network *network)
{
	struct connman_device *device = connman_network_get_device(network);
	struct wifi_data *wifi;

	DBG("network %p", network);

	wifi = connman_device_get_data(device);
	if (wifi == NULL)
		return;

	if (wifi->network != network)
		return;

	wifi->network = NULL;
}

static void connect_callback(int result, GSupplicantInterface *interface,
							void *user_data)
{
	struct connman_network *network = user_data;

	DBG("network %p result %d", network, result);

	if (result == -ENOKEY) {
		connman_network_set_error(network,
					CONNMAN_NETWORK_ERROR_INVALID_KEY);
	} else if (result < 0) {
		connman_network_set_error(network,
					CONNMAN_NETWORK_ERROR_CONFIGURE_FAIL);
	}
}

static GSupplicantSecurity network_security(const char *security)
{
	if (g_str_equal(security, "none") == TRUE)
		return G_SUPPLICANT_SECURITY_NONE;
	else if (g_str_equal(security, "wep") == TRUE)
		return G_SUPPLICANT_SECURITY_WEP;
	else if (g_str_equal(security, "psk") == TRUE)
		return G_SUPPLICANT_SECURITY_PSK;
	else if (g_str_equal(security, "wpa") == TRUE)
		return G_SUPPLICANT_SECURITY_PSK;
	else if (g_str_equal(security, "rsn") == TRUE)
		return G_SUPPLICANT_SECURITY_PSK;
	else if (g_str_equal(security, "ieee8021x") == TRUE)
		return G_SUPPLICANT_SECURITY_IEEE8021X;

	return G_SUPPLICANT_SECURITY_UNKNOWN;
}

static void ssid_init(GSupplicantSSID *ssid, struct connman_network *network)
{
	const char *security, *passphrase, *agent_passphrase;

	memset(ssid, 0, sizeof(*ssid));
	ssid->mode = G_SUPPLICANT_MODE_INFRA;
	ssid->ssid = connman_network_get_blob(network, "WiFi.SSID",
						&ssid->ssid_len);
	ssid->scan_ssid = 1;
	security = connman_network_get_string(network, "WiFi.Security");
	ssid->security = network_security(security);
	passphrase = connman_network_get_string(network,
						"WiFi.Passphrase");
	if (passphrase == NULL || strlen(passphrase) == 0) {

		/* Use agent provided passphrase as a fallback */
		agent_passphrase = connman_network_get_string(network,
						"WiFi.AgentPassphrase");

		if (agent_passphrase == NULL || strlen(agent_passphrase) == 0)
			ssid->passphrase = NULL;
		else
			ssid->passphrase = agent_passphrase;
	} else
		ssid->passphrase = passphrase;

	ssid->eap = connman_network_get_string(network, "WiFi.EAP");

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
						ssid->passphrase);
	/* We must have an identity for both PEAP and TLS */
	ssid->identity = connman_network_get_string(network, "WiFi.Identity");

	/* Use agent provided identity as a fallback */
	if (ssid->identity == NULL || strlen(ssid->identity) == 0)
		ssid->identity = connman_network_get_string(network,
							"WiFi.AgentIdentity");

	ssid->ca_cert_path = connman_network_get_string(network,
							"WiFi.CACertFile");
	ssid->client_cert_path = connman_network_get_string(network,
							"WiFi.ClientCertFile");
	ssid->private_key_path = connman_network_get_string(network,
							"WiFi.PrivateKeyFile");
	ssid->private_key_passphrase = connman_network_get_string(network,
						"WiFi.PrivateKeyPassphrase");
	ssid->phase2_auth = connman_network_get_string(network, "WiFi.Phase2");

	ssid->use_wps = connman_network_get_bool(network, "WiFi.UseWPS");
	ssid->pin_wps = connman_network_get_string(network, "WiFi.PinWPS");

	if (connman_setting_get_bool("BackgroundScanning") == TRUE)
		ssid->bgscan = BGSCAN_DEFAULT;
}

static int network_connect(struct connman_network *network)
{
	struct connman_device *device = connman_network_get_device(network);
	struct wifi_data *wifi;
	GSupplicantInterface *interface;
	GSupplicantSSID *ssid;

	DBG("network %p", network);

	if (device == NULL)
		return -ENODEV;

	wifi = connman_device_get_data(device);
	if (wifi == NULL)
		return -ENODEV;

	ssid = g_try_malloc0(sizeof(GSupplicantSSID));
	if (ssid == NULL)
		return -ENOMEM;

	interface = wifi->interface;

	ssid_init(ssid, network);

	if (wifi->disconnecting == TRUE)
		wifi->pending_network = network;
	else {
		wifi->network = network;
		wifi->retries = 0;

		return g_supplicant_interface_connect(interface, ssid,
						connect_callback, network);
	}

	return -EINPROGRESS;
}

static void disconnect_callback(int result, GSupplicantInterface *interface,
								void *user_data)
{
	struct wifi_data *wifi = user_data;

	if (wifi->network != NULL) {
		/*
		 * if result < 0 supplican return an error because
		 * the network is not current.
		 * we wont receive G_SUPPLICANT_STATE_DISCONNECTED since it
		 * failed, call connman_network_set_connected to report
		 * disconnect is completed.
		 */
		if (result < 0)
			connman_network_set_connected(wifi->network, FALSE);
	}

	wifi->network = NULL;

	wifi->disconnecting = FALSE;

	if (wifi->pending_network != NULL) {
		network_connect(wifi->pending_network);
		wifi->pending_network = NULL;
	}

	start_autoscan(wifi->device);
}

static int network_disconnect(struct connman_network *network)
{
	struct connman_device *device = connman_network_get_device(network);
	struct wifi_data *wifi;
	int err;

	DBG("network %p", network);

	wifi = connman_device_get_data(device);
	if (wifi == NULL || wifi->interface == NULL)
		return -ENODEV;

	connman_network_set_associating(network, FALSE);

	if (wifi->disconnecting == TRUE)
		return -EALREADY;

	wifi->disconnecting = TRUE;

	err = g_supplicant_interface_disconnect(wifi->interface,
						disconnect_callback, wifi);
	if (err < 0)
		wifi->disconnecting = FALSE;

	return err;
}

static struct connman_network_driver network_driver = {
	.name		= "wifi",
	.type		= CONNMAN_NETWORK_TYPE_WIFI,
	.priority	= CONNMAN_NETWORK_PRIORITY_LOW,
	.probe		= network_probe,
	.remove		= network_remove,
	.connect	= network_connect,
	.disconnect	= network_disconnect,
};

static void interface_added(GSupplicantInterface *interface)
{
	const char *ifname = g_supplicant_interface_get_ifname(interface);
	const char *driver = g_supplicant_interface_get_driver(interface);
	struct wifi_data *wifi;

	wifi = g_supplicant_interface_get_data(interface);

	/*
	 * We can get here with a NULL wifi pointer when
	 * the interface added signal is sent before the
	 * interface creation callback is called.
	 */
	if (wifi == NULL)
		return;

	DBG("ifname %s driver %s wifi %p tethering %d",
			ifname, driver, wifi, wifi->tethering);

	if (wifi->device == NULL) {
		connman_error("WiFi device not set");
		return;
	}

	connman_device_set_powered(wifi->device, TRUE);

	if (wifi->tethering == TRUE)
		return;
}

static connman_bool_t is_idle(struct wifi_data *wifi)
{
	DBG("state %d", wifi->state);

	switch (wifi->state) {
	case G_SUPPLICANT_STATE_UNKNOWN:
	case G_SUPPLICANT_STATE_DISCONNECTED:
	case G_SUPPLICANT_STATE_INACTIVE:
	case G_SUPPLICANT_STATE_SCANNING:
		return TRUE;

	case G_SUPPLICANT_STATE_AUTHENTICATING:
	case G_SUPPLICANT_STATE_ASSOCIATING:
	case G_SUPPLICANT_STATE_ASSOCIATED:
	case G_SUPPLICANT_STATE_4WAY_HANDSHAKE:
	case G_SUPPLICANT_STATE_GROUP_HANDSHAKE:
	case G_SUPPLICANT_STATE_COMPLETED:
		return FALSE;
	}

	return FALSE;
}

static connman_bool_t is_idle_wps(GSupplicantInterface *interface,
						struct wifi_data *wifi)
{
	/* First, let's check if WPS processing did not went wrong */
	if (g_supplicant_interface_get_wps_state(interface) ==
		G_SUPPLICANT_WPS_STATE_FAIL)
		return FALSE;

	/* Unlike normal connection, being associated while processing wps
	 * actually means that we are idling. */
	switch (wifi->state) {
	case G_SUPPLICANT_STATE_UNKNOWN:
	case G_SUPPLICANT_STATE_DISCONNECTED:
	case G_SUPPLICANT_STATE_INACTIVE:
	case G_SUPPLICANT_STATE_SCANNING:
	case G_SUPPLICANT_STATE_ASSOCIATED:
		return TRUE;
	case G_SUPPLICANT_STATE_AUTHENTICATING:
	case G_SUPPLICANT_STATE_ASSOCIATING:
	case G_SUPPLICANT_STATE_4WAY_HANDSHAKE:
	case G_SUPPLICANT_STATE_GROUP_HANDSHAKE:
	case G_SUPPLICANT_STATE_COMPLETED:
		return FALSE;
	}

	return FALSE;
}

static connman_bool_t handle_wps_completion(GSupplicantInterface *interface,
					struct connman_network *network,
					struct connman_device *device,
					struct wifi_data *wifi)
{
	connman_bool_t wps;

	wps = connman_network_get_bool(network, "WiFi.UseWPS");
	if (wps == TRUE) {
		const unsigned char *ssid, *wps_ssid;
		unsigned int ssid_len, wps_ssid_len;
		const char *wps_key;

		/* Checking if we got associated with requested
		 * network */
		ssid = connman_network_get_blob(network, "WiFi.SSID",
						&ssid_len);

		wps_ssid = g_supplicant_interface_get_wps_ssid(
			interface, &wps_ssid_len);

		if (wps_ssid == NULL || wps_ssid_len != ssid_len ||
				memcmp(ssid, wps_ssid, ssid_len) != 0) {
			connman_network_set_associating(network, FALSE);
			g_supplicant_interface_disconnect(wifi->interface,
						disconnect_callback, wifi);
			return FALSE;
		}

		wps_key = g_supplicant_interface_get_wps_key(interface);
		connman_network_set_string(network, "WiFi.Passphrase",
					wps_key);

		connman_network_set_string(network, "WiFi.PinWPS", NULL);
	}

	return TRUE;
}

static connman_bool_t handle_4way_handshake_failure(GSupplicantInterface *interface,
					struct connman_network *network,
					struct wifi_data *wifi)
{
	if (wifi->state != G_SUPPLICANT_STATE_4WAY_HANDSHAKE)
		return FALSE;

	wifi->retries++;

	if (wifi->retries < MAXIMUM_RETRIES)
		return TRUE;

	connman_network_set_error(network, CONNMAN_NETWORK_ERROR_INVALID_KEY);

	return FALSE;
}

static void interface_state(GSupplicantInterface *interface)
{
	struct connman_network *network;
	struct connman_device *device;
	struct wifi_data *wifi;
	GSupplicantState state = g_supplicant_interface_get_state(interface);
	connman_bool_t wps;

	wifi = g_supplicant_interface_get_data(interface);

	DBG("wifi %p interface state %d", wifi, state);

	if (wifi == NULL)
		return;

	network = wifi->network;
	device = wifi->device;

	if (device == NULL || network == NULL)
		return;

	switch (state) {
	case G_SUPPLICANT_STATE_SCANNING:
		break;

	case G_SUPPLICANT_STATE_AUTHENTICATING:
	case G_SUPPLICANT_STATE_ASSOCIATING:
		stop_autoscan(device);

		if (wifi->connected == FALSE)
			connman_network_set_associating(network, TRUE);

		break;

	case G_SUPPLICANT_STATE_COMPLETED:
		/* though it should be already stopped: */
		stop_autoscan(device);

		if (handle_wps_completion(interface, network, device, wifi) ==
									FALSE)
			break;

		connman_network_set_connected(network, TRUE);
		break;

	case G_SUPPLICANT_STATE_DISCONNECTED:
		/*
		 * If we're in one of the idle modes, we have
		 * not started association yet and thus setting
		 * those ones to FALSE could cancel an association
		 * in progress.
		 */
		wps = connman_network_get_bool(network, "WiFi.UseWPS");
		if (wps == TRUE)
			if (is_idle_wps(interface, wifi) == TRUE)
				break;

		if (is_idle(wifi))
			break;

		/* If previous state was 4way-handshake, then
		 * it's either: psk was incorrect and thus we retry
		 * or if we reach the maximum retries we declare the
		 * psk as wrong */
		if (handle_4way_handshake_failure(interface,
						network, wifi) == TRUE)
			break;

		/* We disable the selected network, if not then
		 * wpa_supplicant will loop retrying */
		if (g_supplicant_interface_enable_selected_network(interface,
						FALSE) != 0)
			DBG("Could not disables selected network");

		connman_network_set_connected(network, FALSE);
		connman_network_set_associating(network, FALSE);
		wifi->disconnecting = FALSE;

		start_autoscan(device);

		break;

	case G_SUPPLICANT_STATE_INACTIVE:
		connman_network_set_associating(network, FALSE);
		start_autoscan(device);

		break;

	case G_SUPPLICANT_STATE_UNKNOWN:
	case G_SUPPLICANT_STATE_ASSOCIATED:
	case G_SUPPLICANT_STATE_4WAY_HANDSHAKE:
	case G_SUPPLICANT_STATE_GROUP_HANDSHAKE:
		break;
	}

	wifi->state = state;

	/* Saving wpa_s state policy:
	 * If connected and if the state changes are roaming related:
	 * --> We stay connected
	 * If completed
	 * --> We are connected
	 * All other case:
	 * --> We are not connected
	 * */
	switch (state) {
	case G_SUPPLICANT_STATE_AUTHENTICATING:
	case G_SUPPLICANT_STATE_ASSOCIATING:
	case G_SUPPLICANT_STATE_ASSOCIATED:
	case G_SUPPLICANT_STATE_4WAY_HANDSHAKE:
	case G_SUPPLICANT_STATE_GROUP_HANDSHAKE:
		if (wifi->connected == TRUE)
			connman_warn("Probably roaming right now!"
						" Staying connected...");
		else
			wifi->connected = FALSE;
		break;
	case G_SUPPLICANT_STATE_COMPLETED:
		wifi->connected = TRUE;
		break;
	default:
		wifi->connected = FALSE;
		break;
	}

	DBG("DONE");
}

static void interface_removed(GSupplicantInterface *interface)
{
	const char *ifname = g_supplicant_interface_get_ifname(interface);
	struct wifi_data *wifi;

	DBG("ifname %s", ifname);

	wifi = g_supplicant_interface_get_data(interface);

	if (wifi != NULL && wifi->tethering == TRUE)
		return;

	if (wifi == NULL || wifi->device == NULL) {
		DBG("wifi interface already removed");
		return;
	}

	wifi->interface = NULL;
	connman_device_set_powered(wifi->device, FALSE);
}

static void scan_started(GSupplicantInterface *interface)
{
	DBG("");
}

static void scan_finished(GSupplicantInterface *interface)
{
	DBG("");
}

static unsigned char calculate_strength(GSupplicantNetwork *supplicant_network)
{
	unsigned char strength;

	strength = 120 + g_supplicant_network_get_signal(supplicant_network);
	if (strength > 100)
		strength = 100;

	return strength;
}

static void network_added(GSupplicantNetwork *supplicant_network)
{
	struct connman_network *network;
	GSupplicantInterface *interface;
	struct wifi_data *wifi;
	const char *name, *identifier, *security, *group, *mode;
	const unsigned char *ssid;
	unsigned int ssid_len;
	connman_bool_t wps;
	connman_bool_t wps_pbc;
	connman_bool_t wps_ready;
	connman_bool_t wps_advertizing;

	DBG("");

	interface = g_supplicant_network_get_interface(supplicant_network);
	wifi = g_supplicant_interface_get_data(interface);
	name = g_supplicant_network_get_name(supplicant_network);
	identifier = g_supplicant_network_get_identifier(supplicant_network);
	security = g_supplicant_network_get_security(supplicant_network);
	group = g_supplicant_network_get_identifier(supplicant_network);
	wps = g_supplicant_network_get_wps(supplicant_network);
	wps_pbc = g_supplicant_network_is_wps_pbc(supplicant_network);
	wps_ready = g_supplicant_network_is_wps_active(supplicant_network);
	wps_advertizing = g_supplicant_network_is_wps_advertizing(
							supplicant_network);
	mode = g_supplicant_network_get_mode(supplicant_network);

	if (wifi == NULL)
		return;

	ssid = g_supplicant_network_get_ssid(supplicant_network, &ssid_len);

	network = connman_device_get_network(wifi->device, identifier);

	if (network == NULL) {
		network = connman_network_create(identifier,
						CONNMAN_NETWORK_TYPE_WIFI);
		if (network == NULL)
			return;

		connman_network_set_index(network, wifi->index);

		if (connman_device_add_network(wifi->device, network) < 0) {
			connman_network_unref(network);
			return;
		}

		wifi->networks = g_slist_append(wifi->networks, network);
	}

	if (name != NULL && name[0] != '\0')
		connman_network_set_name(network, name);

	connman_network_set_blob(network, "WiFi.SSID",
						ssid, ssid_len);
	connman_network_set_string(network, "WiFi.Security", security);
	connman_network_set_strength(network,
				calculate_strength(supplicant_network));
	connman_network_set_bool(network, "WiFi.WPS", wps);

	if (wps == TRUE) {
		/* Is AP advertizing for WPS association?
		 * If so, we decide to use WPS by default */
		if (wps_ready == TRUE && wps_pbc == TRUE &&
						wps_advertizing == TRUE)
			connman_network_set_bool(network, "WiFi.UseWPS", TRUE);
	}

	connman_network_set_frequency(network,
			g_supplicant_network_get_frequency(supplicant_network));

	connman_network_set_available(network, TRUE);
	connman_network_set_string(network, "WiFi.Mode", mode);

	if (ssid != NULL)
		connman_network_set_group(network, group);

	if (wifi->hidden != NULL && ssid != NULL) {
		if (wifi->hidden->ssid_len == ssid_len &&
				memcmp(wifi->hidden->ssid, ssid,
						ssid_len) == 0) {
			connman_network_connect_hidden(network,
					wifi->hidden->identity,
					wifi->hidden->passphrase,
					wifi->hidden->user_data);
			wifi->hidden->user_data = NULL;
			hidden_free(wifi->hidden);
			wifi->hidden = NULL;
		}
	}
}

static void network_removed(GSupplicantNetwork *network)
{
	GSupplicantInterface *interface;
	struct wifi_data *wifi;
	const char *name, *identifier;
	struct connman_network *connman_network;

	interface = g_supplicant_network_get_interface(network);
	wifi = g_supplicant_interface_get_data(interface);
	identifier = g_supplicant_network_get_identifier(network);
	name = g_supplicant_network_get_name(network);

	DBG("name %s", name);

	if (wifi == NULL)
		return;

	connman_network = connman_device_get_network(wifi->device, identifier);
	if (connman_network == NULL)
		return;

	wifi->networks = g_slist_remove(wifi->networks, connman_network);

	connman_device_remove_network(wifi->device, connman_network);
	connman_network_unref(connman_network);
}

static void network_changed(GSupplicantNetwork *network, const char *property)
{
	GSupplicantInterface *interface;
	struct wifi_data *wifi;
	const char *name, *identifier;
	struct connman_network *connman_network;

	interface = g_supplicant_network_get_interface(network);
	wifi = g_supplicant_interface_get_data(interface);
	identifier = g_supplicant_network_get_identifier(network);
	name = g_supplicant_network_get_name(network);

	DBG("name %s", name);

	if (wifi == NULL)
		return;

	connman_network = connman_device_get_network(wifi->device, identifier);
	if (connman_network == NULL)
		return;

	if (g_str_equal(property, "Signal") == TRUE) {
	       connman_network_set_strength(connman_network,
					calculate_strength(network));
	       connman_network_update(connman_network);
	}
}

static void debug(const char *str)
{
	if (getenv("CONNMAN_SUPPLICANT_DEBUG"))
		connman_debug("%s", str);
}

static const GSupplicantCallbacks callbacks = {
	.system_ready		= system_ready,
	.system_killed		= system_killed,
	.interface_added	= interface_added,
	.interface_state	= interface_state,
	.interface_removed	= interface_removed,
	.scan_started		= scan_started,
	.scan_finished		= scan_finished,
	.network_added		= network_added,
	.network_removed	= network_removed,
	.network_changed	= network_changed,
	.debug			= debug,
};


static int tech_probe(struct connman_technology *technology)
{
	wifi_technology = technology;

	return 0;
}

static void tech_remove(struct connman_technology *technology)
{
	wifi_technology = NULL;
}

struct wifi_tethering_info {
	struct wifi_data *wifi;
	struct connman_technology *technology;
	char *ifname;
	GSupplicantSSID *ssid;
};

static GSupplicantSSID *ssid_ap_init(const char *ssid, const char *passphrase)
{
	GSupplicantSSID *ap;

	ap = g_try_malloc0(sizeof(GSupplicantSSID));
	if (ap == NULL)
		return NULL;

	ap->mode = G_SUPPLICANT_MODE_MASTER;
	ap->ssid = ssid;
	ap->ssid_len = strlen(ssid);
	ap->scan_ssid = 0;
	ap->freq = 2412;

	if (passphrase == NULL || strlen(passphrase) == 0) {
		ap->security = G_SUPPLICANT_SECURITY_NONE;
		ap->passphrase = NULL;
	} else {
	       ap->security = G_SUPPLICANT_SECURITY_PSK;
	       ap->protocol = G_SUPPLICANT_PROTO_RSN;
	       ap->pairwise_cipher = G_SUPPLICANT_PAIRWISE_CCMP;
	       ap->group_cipher = G_SUPPLICANT_GROUP_CCMP;
	       ap->passphrase = passphrase;
	}

	return ap;
}

static void ap_start_callback(int result, GSupplicantInterface *interface,
							void *user_data)
{
	struct wifi_tethering_info *info = user_data;

	DBG("result %d index %d bridge %s",
		result, info->wifi->index, info->wifi->bridge);

	if (result < 0) {
		connman_inet_remove_from_bridge(info->wifi->index,
							info->wifi->bridge);
		connman_technology_tethering_notify(info->technology, FALSE);
	}

	g_free(info->ifname);
	g_free(info);
}

static void ap_create_callback(int result,
				GSupplicantInterface *interface,
					void *user_data)
{
	struct wifi_tethering_info *info = user_data;

	DBG("result %d ifname %s", result,
				g_supplicant_interface_get_ifname(interface));

	if (result < 0) {
		connman_inet_remove_from_bridge(info->wifi->index,
							info->wifi->bridge);
		connman_technology_tethering_notify(info->technology, FALSE);

		g_free(info->ifname);
		g_free(info);
		return;
	}

	info->wifi->interface = interface;
	g_supplicant_interface_set_data(interface, info->wifi);

	if (g_supplicant_interface_set_apscan(interface, 2) < 0)
		connman_error("Failed to set interface ap_scan property");

	g_supplicant_interface_connect(interface, info->ssid,
						ap_start_callback, info);
}

static void sta_remove_callback(int result,
				GSupplicantInterface *interface,
					void *user_data)
{
	struct wifi_tethering_info *info = user_data;
	const char *driver = connman_option_get_string("wifi");

	DBG("ifname %s result %d ", info->ifname, result);

	if (result < 0) {
		info->wifi->tethering = TRUE;

		g_free(info->ifname);
		g_free(info);
		return;
	}

	info->wifi->interface = NULL;

	connman_technology_tethering_notify(info->technology, TRUE);

	g_supplicant_interface_create(info->ifname, driver, info->wifi->bridge,
						ap_create_callback,
							info);
}

static int tech_set_tethering(struct connman_technology *technology,
				const char *identifier, const char *passphrase,
				const char *bridge, connman_bool_t enabled)
{
	GList *list;
	GSupplicantInterface *interface;
	struct wifi_data *wifi;
	struct wifi_tethering_info *info;
	const char *ifname;
	unsigned int mode;
	int err;

	DBG("");

	if (enabled == FALSE) {
		for (list = iface_list; list; list = list->next) {
			wifi = list->data;

			if (wifi->tethering == TRUE) {
				wifi->tethering = FALSE;

				connman_inet_remove_from_bridge(wifi->index,
									bridge);
				wifi->bridged = FALSE;
			}
		}

		connman_technology_tethering_notify(technology, FALSE);

		return 0;
	}

	for (list = iface_list; list; list = list->next) {
		wifi = list->data;

		interface = wifi->interface;

		if (interface == NULL)
			continue;

		ifname = g_supplicant_interface_get_ifname(wifi->interface);

		mode = g_supplicant_interface_get_mode(interface);
		if ((mode & G_SUPPLICANT_CAPABILITY_MODE_AP) == 0) {
			DBG("%s does not support AP mode", ifname);
			continue;
		}

		info = g_try_malloc0(sizeof(struct wifi_tethering_info));
		if (info == NULL)
			return -ENOMEM;

		info->wifi = wifi;
		info->technology = technology;
		info->wifi->bridge = bridge;
		info->ssid = ssid_ap_init(identifier, passphrase);
		if (info->ssid == NULL) {
			g_free(info);
			continue;
		}
		info->ifname = g_strdup(ifname);
		if (info->ifname == NULL) {
			g_free(info);
			continue;
		}

		info->wifi->tethering = TRUE;

		err = g_supplicant_interface_remove(interface,
						sta_remove_callback,
							info);
		if (err == 0)
			return err;
	}

	return -EOPNOTSUPP;
}

static void regdom_callback(void *user_data)
{
	char *alpha2 = user_data;

	DBG("");

	if (wifi_technology == NULL)
		return;

	connman_technology_regdom_notify(wifi_technology, alpha2);
}

static int tech_set_regdom(struct connman_technology *technology, const char *alpha2)
{
	return g_supplicant_set_country(alpha2, regdom_callback, alpha2);
}

static struct connman_technology_driver tech_driver = {
	.name		= "wifi",
	.type		= CONNMAN_SERVICE_TYPE_WIFI,
	.probe		= tech_probe,
	.remove		= tech_remove,
	.set_tethering	= tech_set_tethering,
	.set_regdom	= tech_set_regdom,
};

static int wifi_init(void)
{
	int err;

	err = connman_network_driver_register(&network_driver);
	if (err < 0)
		return err;

	err = g_supplicant_register(&callbacks);
	if (err < 0) {
		connman_network_driver_unregister(&network_driver);
		return err;
	}

	err = connman_technology_driver_register(&tech_driver);
	if (err < 0) {
		g_supplicant_unregister(&callbacks);
		connman_network_driver_unregister(&network_driver);
		return err;
	}

	return 0;
}

static void wifi_exit(void)
{
	DBG();

	connman_technology_driver_unregister(&tech_driver);

	g_supplicant_unregister(&callbacks);

	connman_network_driver_unregister(&network_driver);
}

CONNMAN_PLUGIN_DEFINE(wifi, "WiFi interface plugin", VERSION,
		CONNMAN_PLUGIN_PRIORITY_DEFAULT, wifi_init, wifi_exit)
