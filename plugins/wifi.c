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

#include <unistd.h>
#include <errno.h>
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
#include <connman/log.h>

#include <gsupplicant/gsupplicant.h>

#define CLEANUP_TIMEOUT   8	/* in seconds */
#define INACTIVE_TIMEOUT  12	/* in seconds */

struct wifi_data {
	char *identifier;
	struct connman_device *device;
	struct connman_network *network;
	GSupplicantInterface *interface;
	connman_bool_t connected;
	int index;
	unsigned flags;
	unsigned int watch;
};

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

static void wifi_newlink(unsigned flags, unsigned change, void *user_data)
{
	struct connman_device *device = user_data;
	struct wifi_data *wifi = connman_device_get_data(device);

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
		if (flags & IFF_LOWER_UP)
			DBG("carrier on");
		else
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

	connman_device_set_data(device, wifi);
	wifi->device = connman_device_ref(device);

	wifi->index = connman_device_get_index(device);
	wifi->flags = 0;

	wifi->watch = connman_rtnl_add_newlink_watch(wifi->index,
							wifi_newlink, device);

	return 0;
}

static void wifi_remove(struct connman_device *device)
{
	struct wifi_data *wifi = connman_device_get_data(device);

	DBG("device %p", device);

	connman_device_set_data(device, NULL);
	connman_device_unref(wifi->device);
	connman_rtnl_remove_watch(wifi->watch);

	g_free(wifi->identifier);
	g_free(wifi);
}

static void interface_create_callback(int result,
					GSupplicantInterface *interface,
							void *user_data)
{
	struct wifi_data *wifi = user_data;

	DBG("result %d ifname %s", result,
				g_supplicant_interface_get_ifname(interface));

	if (result < 0)
		return;

	wifi->interface = interface;
	g_supplicant_interface_set_data(interface, wifi);
}

static void interface_remove_callback(int result,
					GSupplicantInterface *interface,
							void *user_data)
{
	struct wifi_data *wifi = user_data;

	DBG("result %d", result);

	if (result < 0)
		return;

	wifi->interface = NULL;
}


static int wifi_enable(struct connman_device *device)
{
	struct wifi_data *wifi = connman_device_get_data(device);
	const char *interface = connman_device_get_string(device, "Interface");

	DBG("device %p %p", device, wifi);

	return g_supplicant_interface_create(interface, "nl80211,wext",
						interface_create_callback,
							wifi);
}

static int wifi_disable(struct connman_device *device)
{
	struct wifi_data *wifi = connman_device_get_data(device);

	DBG("device %p", device);

	wifi->connected = FALSE;

	return g_supplicant_interface_remove(wifi->interface,
						interface_remove_callback,
							wifi);
}

static void scan_callback(int result, GSupplicantInterface *interface,
						void *user_data)
{
	struct connman_device *device = user_data;

	DBG("result %d", result);

	if (result < 0) {
		connman_device_set_scanning(device, FALSE);
		return;
	}

	connman_device_set_scanning(device, TRUE);
}

static int wifi_scan(struct connman_device *device)
{
	struct wifi_data *wifi = connman_device_get_data(device);

	DBG("device %p %p", device, wifi->interface);

	return g_supplicant_interface_scan(wifi->interface, scan_callback,
								device);
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

static void interface_added(GSupplicantInterface *interface)
{
	const char *ifname = g_supplicant_interface_get_ifname(interface);
	const char *driver = g_supplicant_interface_get_driver(interface);
	struct wifi_data *wifi;

	wifi = (struct wifi_data *)g_supplicant_interface_get_data(interface);

	DBG("ifname %s driver %s wifi %p", ifname, driver, wifi);

	if (wifi == NULL || wifi->device == NULL) {
		connman_error("Wrong wifi pointer");
		return;
	}

	connman_device_set_powered(wifi->device, TRUE);
	wifi_scan(wifi->device);
}

static void interface_state(GSupplicantInterface *interface)
{
	struct connman_network *network;
	struct connman_device *device;
	struct wifi_data *wifi;
	GSupplicantState state = g_supplicant_interface_get_state(interface);
	unsigned char bssid[ETH_ALEN];
	unsigned int bssid_len;

	wifi = (struct wifi_data *) g_supplicant_interface_get_data(interface);

	DBG("wifi %p interface state %d", wifi, state);

	if (wifi == NULL)
		return;

	network = wifi->network;
	device = wifi->device;

	if (device == NULL || network == NULL)
		return;

	switch (state) {
	case G_SUPPLICANT_STATE_SCANNING:
		connman_device_set_scanning(device, TRUE);
		break;

	case G_SUPPLICANT_STATE_AUTHENTICATING:
	case G_SUPPLICANT_STATE_ASSOCIATING:
		connman_network_set_associating(network, TRUE);
		break;

	case G_SUPPLICANT_STATE_COMPLETED:
		/* reset scan trigger and schedule background scan */
		connman_device_schedule_scan(device);

		if (get_bssid(device, bssid, &bssid_len) == 0)
			connman_network_set_address(network,
							bssid, bssid_len);
		connman_network_set_connected(network, TRUE);
		break;

	case G_SUPPLICANT_STATE_DISCONNECTED:
		connman_network_set_connected(network, FALSE);
		break;

	case G_SUPPLICANT_STATE_INACTIVE:
		break;

	case G_SUPPLICANT_STATE_UNKNOWN:
	case G_SUPPLICANT_STATE_ASSOCIATED:
	case G_SUPPLICANT_STATE_4WAY_HANDSHAKE:
	case G_SUPPLICANT_STATE_GROUP_HANDSHAKE:
		break;
	}

	DBG("DONE");
}

static void interface_removed(GSupplicantInterface *interface)
{
	const char *ifname = g_supplicant_interface_get_ifname(interface);
	struct wifi_data *wifi;

	DBG("ifname %s", ifname);

	wifi = (struct wifi_data *)g_supplicant_interface_get_data(interface);

	if (wifi == NULL || wifi->device == NULL) {
		connman_error("Wrong wifi pointer");
		return;
	}

	connman_device_set_powered(wifi->device, FALSE);
}

static void scan_started(GSupplicantInterface *interface)
{
	struct wifi_data *wifi;

	DBG("");

	wifi = (struct wifi_data *)g_supplicant_interface_get_data(interface);

	if (wifi == NULL)
		return;

	if (wifi->device)
		connman_device_set_scanning(wifi->device, TRUE);
}

static void scan_finished(GSupplicantInterface *interface)
{
	struct wifi_data *wifi;

	DBG("");

	wifi = (struct wifi_data *)g_supplicant_interface_get_data(interface);

	if (wifi == NULL)
		return;
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
	const char *name, *path, *identifier, *mode, *security, *group;
	unsigned char *ssid;
	unsigned int ssid_len;

	DBG("");

	interface = g_supplicant_network_get_interface(supplicant_network);
	wifi = (struct wifi_data *) g_supplicant_interface_get_data(interface);
	name = g_supplicant_network_get_name(supplicant_network);
	path = g_supplicant_network_get_path(supplicant_network);
	identifier = g_supplicant_network_get_identifier(supplicant_network);
	mode = g_supplicant_network_get_mode(supplicant_network);
	security = g_supplicant_network_get_security(supplicant_network);
	group = g_supplicant_network_get_identifier(supplicant_network);

	if (wifi == NULL)
		return;

	ssid = (unsigned char *)g_supplicant_network_get_ssid(supplicant_network, &ssid_len);

	network = connman_device_get_network(wifi->device, path);

	if (network == NULL) {
		network = connman_network_create(identifier,
						CONNMAN_NETWORK_TYPE_WIFI);
		if (network == NULL)
			return;

		connman_network_set_index(network, wifi->index);

		connman_network_set_protocol(network,
						CONNMAN_NETWORK_PROTOCOL_IP);

		if (connman_device_add_network(wifi->device, network) < 0) {
			connman_network_unref(network);
			return;
		}
	}

	if (name != NULL && name[0] != '\0')
		connman_network_set_name(network, name);

	connman_network_set_blob(network, "WiFi.SSID",
						ssid, ssid_len);
	connman_network_set_string(network, "WiFi.Mode", mode);
	connman_network_set_string(network, "WiFi.Security", security);
	connman_network_set_strength(network,
				calculate_strength(supplicant_network));

	connman_network_set_available(network, TRUE);

	if (ssid != NULL)
		connman_network_set_group(network, group);
}

static void network_removed(GSupplicantNetwork *network)
{
	const char *name = g_supplicant_network_get_name(network);

	DBG("* name %s", name);
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
};


static int network_probe(struct connman_network *network)
{
	DBG("network %p", network);

	return 0;
}

static void network_remove(struct connman_network *network)
{
	DBG("network %p", network);
}

static void connect_callback(int result, GSupplicantInterface *interface,
							void *user_data)
{
	connman_error("%s", __func__);
}

static void disconnect_callback(int result, GSupplicantInterface *interface,
							void *user_data)
{
	struct wifi_data *wifi = user_data;

	if (result < 0) {
		connman_error("%s", __func__);
		return;
	}

	connman_network_unref(wifi->network);

	wifi->network = NULL;
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
	const char *security;

	memset(ssid, 0, sizeof(*ssid));
	ssid->ssid = connman_network_get_blob(network, "WiFi.SSID",
						&ssid->ssid_len);
	security = connman_network_get_string(network, "WiFi.Security");
	ssid->security = network_security(security);
	ssid->passphrase = connman_network_get_string(network,
							"WiFi.Passphrase");
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
	ssid->ca_cert_path = connman_network_get_string(network,
							"WiFi.CACertFile");
	ssid->client_cert_path = connman_network_get_string(network,
							"WiFi.ClientCertFile");
	ssid->private_key_path = connman_network_get_string(network,
							"WiFi.PrivateKeyFile");
	ssid->private_key_passphrase = connman_network_get_string(network,
						"WiFi.PrivateKeyPassphrase");
	ssid->phase2_auth = connman_network_get_string(network, "WiFi.Phase2");

}

static int network_connect(struct connman_network *network)
{
	struct connman_device *device = connman_network_get_device(network);
	struct wifi_data *wifi;
	GSupplicantInterface *interface;
	GSupplicantSSID ssid;

	DBG("network %p", network);

	if (device == NULL)
		return -ENODEV;

	wifi = connman_device_get_data(device);
	if (wifi == NULL)
		return -ENODEV;

	interface = wifi->interface;

	ssid_init(&ssid, network);

	wifi->network = connman_network_ref(network);

	return g_supplicant_interface_connect(interface, &ssid,
						connect_callback, NULL);
}

static int network_disconnect(struct connman_network *network)
{
	struct connman_device *device = connman_network_get_device(network);
	struct wifi_data *wifi;

	DBG("network %p", network);

	wifi = connman_device_get_data(device);
	if (wifi == NULL || wifi->interface == NULL)
		return -ENODEV;

	return g_supplicant_interface_disconnect(wifi->interface,
						disconnect_callback, wifi);
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

	return 0;
}

static void wifi_exit(void)
{
	DBG();

	g_supplicant_unregister(&callbacks);

	connman_network_driver_unregister(&network_driver);
}

CONNMAN_PLUGIN_DEFINE(wifi, "WiFi interface plugin", VERSION,
		CONNMAN_PLUGIN_PRIORITY_DEFAULT, wifi_init, wifi_exit)
