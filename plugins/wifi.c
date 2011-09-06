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
#include <stdlib.h>
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
#include <connman/technology.h>
#include <connman/log.h>
#include <connman/option.h>

#include <gsupplicant/gsupplicant.h>

#define CLEANUP_TIMEOUT   8	/* in seconds */
#define INACTIVE_TIMEOUT  12	/* in seconds */

struct connman_technology *wifi_technology = NULL;

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
};

static GList *iface_list = NULL;

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

static void wifi_remove(struct connman_device *device)
{
	struct wifi_data *wifi = connman_device_get_data(device);

	DBG("device %p", device);

	if (wifi == NULL)
		return;

	iface_list = g_list_remove(iface_list, wifi);

	remove_networks(device, wifi);

	connman_device_set_data(device, NULL);
	connman_device_unref(wifi->device);
	connman_rtnl_remove_watch(wifi->watch);

	g_supplicant_interface_set_data(wifi->interface, NULL);

	g_free(wifi->identifier);
	g_free(wifi);
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
}

static void interface_remove_callback(int result,
					GSupplicantInterface *interface,
							void *user_data)
{
	struct wifi_data *wifi = user_data;

	DBG("result %d wifi %p", result, wifi);

	if (result < 0 || wifi == NULL)
		return;

	wifi->interface = NULL;
}


static int wifi_enable(struct connman_device *device)
{
	struct wifi_data *wifi = connman_device_get_data(device);
	const char *interface = connman_device_get_string(device, "Interface");
	const char *driver = connman_option_get_string("wifi");
	int ret;

	DBG("device %p %p", device, wifi);

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

	DBG("device %p", device);

	wifi->connected = FALSE;
	wifi->disconnecting = FALSE;

	if (wifi->pending_network != NULL)
		wifi->pending_network = NULL;

	remove_networks(device, wifi);

	ret = g_supplicant_interface_remove(wifi->interface,
						interface_remove_callback,
							wifi);
	if (ret < 0)
		return ret;

	return -EINPROGRESS;
}

static void scan_callback(int result, GSupplicantInterface *interface,
						void *user_data)
{
	struct connman_device *device = user_data;

	DBG("result %d", result);

	if (result < 0)
		connman_device_reset_scanning(device);
	else
		connman_device_set_scanning(device, FALSE);
	connman_device_unref(device);
}

static int wifi_scan(struct connman_device *device)
{
	struct wifi_data *wifi = connman_device_get_data(device);
	int ret;

	DBG("device %p %p", device, wifi->interface);

	if (wifi->tethering == TRUE)
		return 0;

	connman_device_ref(device);
	ret = g_supplicant_interface_scan(wifi->interface, scan_callback,
								device);
	if (ret == 0)
		connman_device_set_scanning(device, TRUE);
	else
		connman_device_unref(device);

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

	wifi_scan(wifi->device);
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
		connman_network_set_associating(network, TRUE);
		break;

	case G_SUPPLICANT_STATE_COMPLETED:
		if (handle_wps_completion(interface, network, device, wifi) ==
									FALSE)
			break;

		/* reset scan trigger and schedule background scan */
		connman_device_schedule_scan(device);

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
		connman_network_set_associating(network, FALSE);
		connman_network_set_connected(network, FALSE);
		break;

	case G_SUPPLICANT_STATE_INACTIVE:
		connman_network_set_associating(network, FALSE);
		break;

	case G_SUPPLICANT_STATE_UNKNOWN:
	case G_SUPPLICANT_STATE_ASSOCIATED:
	case G_SUPPLICANT_STATE_4WAY_HANDSHAKE:
	case G_SUPPLICANT_STATE_GROUP_HANDSHAKE:
		break;
	}

	wifi->state = state;

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
		connman_error("Wrong wifi pointer");
		return;
	}

	connman_device_set_powered(wifi->device, FALSE);
}

static void scan_started(GSupplicantInterface *interface)
{
	struct wifi_data *wifi;

	DBG("");

	wifi = g_supplicant_interface_get_data(interface);

	if (wifi == NULL)
		return;
}

static void scan_finished(GSupplicantInterface *interface)
{
	struct wifi_data *wifi;

	DBG("");

	wifi = g_supplicant_interface_get_data(interface);

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
	const char *name, *identifier, *security, *group;
	const unsigned char *ssid;
	unsigned int ssid_len;
	connman_bool_t wps;

	DBG("");

	interface = g_supplicant_network_get_interface(supplicant_network);
	wifi = g_supplicant_interface_get_data(interface);
	name = g_supplicant_network_get_name(supplicant_network);
	identifier = g_supplicant_network_get_identifier(supplicant_network);
	security = g_supplicant_network_get_security(supplicant_network);
	group = g_supplicant_network_get_identifier(supplicant_network);
	wps = g_supplicant_network_get_wps(supplicant_network);

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

	connman_network_set_available(network, TRUE);

	if (ssid != NULL)
		connman_network_set_group(network, group);
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
