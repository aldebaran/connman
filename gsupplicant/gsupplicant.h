/*
 *
 *  WPA supplicant library with GLib integration
 *
 *  Copyright (C) 2012-2013  Intel Corporation. All rights reserved.
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
#ifndef __G_SUPPLICANT_H
#define __G_SUPPLICANT_H

#ifdef __cplusplus
extern "C" {
#endif

#define G_SUPPLICANT_EAP_METHOD_MD5	(1 << 0)
#define G_SUPPLICANT_EAP_METHOD_TLS	(1 << 1)
#define G_SUPPLICANT_EAP_METHOD_MSCHAPV2	(1 << 2)
#define G_SUPPLICANT_EAP_METHOD_PEAP	(1 << 3)
#define G_SUPPLICANT_EAP_METHOD_TTLS	(1 << 4)
#define G_SUPPLICANT_EAP_METHOD_GTC	(1 << 5)
#define G_SUPPLICANT_EAP_METHOD_OTP	(1 << 6)
#define G_SUPPLICANT_EAP_METHOD_LEAP	(1 << 7)
#define G_SUPPLICANT_EAP_METHOD_WSC	(1 << 8)

#define G_SUPPLICANT_CAPABILITY_AUTHALG_OPEN	(1 << 0)
#define G_SUPPLICANT_CAPABILITY_AUTHALG_SHARED	(1 << 1)
#define G_SUPPLICANT_CAPABILITY_AUTHALG_LEAP	(1 << 2)

#define G_SUPPLICANT_CAPABILITY_PROTO_WPA		(1 << 0)
#define G_SUPPLICANT_CAPABILITY_PROTO_RSN		(1 << 1)

#define G_SUPPLICANT_CAPABILITY_SCAN_ACTIVE	(1 << 0)
#define G_SUPPLICANT_CAPABILITY_SCAN_PASSIVE	(1 << 1)
#define G_SUPPLICANT_CAPABILITY_SCAN_SSID		(1 << 2)

#define G_SUPPLICANT_CAPABILITY_MODE_INFRA	(1 << 0)
#define G_SUPPLICANT_CAPABILITY_MODE_IBSS		(1 << 1)
#define G_SUPPLICANT_CAPABILITY_MODE_AP		(1 << 2)

#define G_SUPPLICANT_KEYMGMT_NONE		(1 << 0)
#define G_SUPPLICANT_KEYMGMT_IEEE8021X	(1 << 1)
#define G_SUPPLICANT_KEYMGMT_WPA_NONE	(1 << 2)
#define G_SUPPLICANT_KEYMGMT_WPA_PSK	(1 << 3)
#define G_SUPPLICANT_KEYMGMT_WPA_PSK_256	(1 << 4)
#define G_SUPPLICANT_KEYMGMT_WPA_FT_PSK	(1 << 5)
#define G_SUPPLICANT_KEYMGMT_WPA_FT_EAP	(1 << 6)
#define G_SUPPLICANT_KEYMGMT_WPA_EAP	(1 << 7)
#define G_SUPPLICANT_KEYMGMT_WPA_EAP_256	(1 << 8)
#define G_SUPPLICANT_KEYMGMT_WPS		(1 << 9)

#define G_SUPPLICANT_PROTO_WPA		(1 << 0)
#define G_SUPPLICANT_PROTO_RSN		(1 << 1)

#define G_SUPPLICANT_GROUP_WEP40		(1 << 0)
#define G_SUPPLICANT_GROUP_WEP104		(1 << 1)
#define G_SUPPLICANT_GROUP_TKIP		(1 << 2)
#define G_SUPPLICANT_GROUP_CCMP		(1 << 3)

#define G_SUPPLICANT_PAIRWISE_NONE	(1 << 0)
#define G_SUPPLICANT_PAIRWISE_TKIP	(1 << 1)
#define G_SUPPLICANT_PAIRWISE_CCMP	(1 << 2)

#define G_SUPPLICANT_WPS_CONFIGURED     (1 << 0)
#define G_SUPPLICANT_WPS_PBC            (1 << 1)
#define G_SUPPLICANT_WPS_PIN            (1 << 2)
#define G_SUPPLICANT_WPS_REGISTRAR      (1 << 3)

typedef enum {
	G_SUPPLICANT_MODE_UNKNOWN,
	G_SUPPLICANT_MODE_INFRA,
	G_SUPPLICANT_MODE_IBSS,
	G_SUPPLICANT_MODE_MASTER,
} GSupplicantMode;

typedef enum {
	G_SUPPLICANT_SECURITY_UNKNOWN,
	G_SUPPLICANT_SECURITY_NONE,
	G_SUPPLICANT_SECURITY_WEP,
	G_SUPPLICANT_SECURITY_PSK,
	G_SUPPLICANT_SECURITY_IEEE8021X,
} GSupplicantSecurity;

typedef enum {
	G_SUPPLICANT_STATE_UNKNOWN,
	G_SUPPLICANT_STATE_DISABLED,
	G_SUPPLICANT_STATE_DISCONNECTED,
	G_SUPPLICANT_STATE_INACTIVE,
	G_SUPPLICANT_STATE_SCANNING,
	G_SUPPLICANT_STATE_AUTHENTICATING,
	G_SUPPLICANT_STATE_ASSOCIATING,
	G_SUPPLICANT_STATE_ASSOCIATED,
	G_SUPPLICANT_STATE_4WAY_HANDSHAKE,
	G_SUPPLICANT_STATE_GROUP_HANDSHAKE,
	G_SUPPLICANT_STATE_COMPLETED,
} GSupplicantState;

typedef enum {
	G_SUPPLICANT_WPS_STATE_UNKNOWN,
	G_SUPPLICANT_WPS_STATE_SUCCESS,
	G_SUPPLICANT_WPS_STATE_FAIL,
} GSupplicantWpsState;

struct _GSupplicantSSID {
	const void *ssid;
	unsigned int ssid_len;
	unsigned int scan_ssid;
	GSupplicantMode mode;
	GSupplicantSecurity security;
	unsigned int protocol;
	unsigned int pairwise_cipher;
	unsigned int group_cipher;
	unsigned int freq;
	const char *eap;
	const char *passphrase;
	const char *identity;
	const char *ca_cert_path;
	const char *client_cert_path;
	const char *private_key_path;
	const char *private_key_passphrase;
	const char *phase2_auth;
	dbus_bool_t use_wps;
	const char *pin_wps;
	const char *bgscan;
};

typedef struct _GSupplicantSSID GSupplicantSSID;

struct scan_ssid {
	unsigned char ssid[32];
	uint8_t ssid_len;
};

struct _GSupplicantScanParams {
	GSList *ssids;

	uint8_t num_ssids;

	uint8_t num_freqs;
	uint16_t *freqs;
};

typedef struct _GSupplicantScanParams GSupplicantScanParams;

/* global API */
typedef void (*GSupplicantCountryCallback) (int result,
						const char *alpha2,
							void *user_data);

int g_supplicant_set_country(const char *alpha2,
				GSupplicantCountryCallback callback,
						const void *user_data);

/* Interface API */
struct _GSupplicantInterface;

typedef struct _GSupplicantInterface GSupplicantInterface;

typedef void (*GSupplicantInterfaceCallback) (int result,
					GSupplicantInterface *interface,
							void *user_data);

int g_supplicant_interface_create(const char *ifname, const char *driver,
					const char *bridge,
					GSupplicantInterfaceCallback callback,
							void *user_data);
int g_supplicant_interface_remove(GSupplicantInterface *interface,
					GSupplicantInterfaceCallback callback,
							void *user_data);
int g_supplicant_interface_scan(GSupplicantInterface *interface,
					GSupplicantScanParams *scan_data,
					GSupplicantInterfaceCallback callback,
							void *user_data);

int g_supplicant_interface_autoscan(GSupplicantInterface *interface,
					const char *autoscan_data,
					GSupplicantInterfaceCallback callback,
							void *user_data);

int g_supplicant_interface_p2p_find(GSupplicantInterface *interface,
					GSupplicantInterfaceCallback callback,
							void *user_data);

int g_supplicant_interface_p2p_stop_find(GSupplicantInterface *interface);

int g_supplicant_interface_connect(GSupplicantInterface *interface,
					GSupplicantSSID *ssid,
					GSupplicantInterfaceCallback callback,
							void *user_data);

int g_supplicant_interface_disconnect(GSupplicantInterface *interface,
					GSupplicantInterfaceCallback callback,
							void *user_data);

int g_supplicant_interface_set_apscan(GSupplicantInterface *interface,
							unsigned int ap_scan);

void g_supplicant_interface_set_data(GSupplicantInterface *interface,
								void *data);
void *g_supplicant_interface_get_data(GSupplicantInterface *interface);
const char *g_supplicant_interface_get_ifname(GSupplicantInterface *interface);
const char *g_supplicant_interface_get_driver(GSupplicantInterface *interface);
GSupplicantState g_supplicant_interface_get_state(GSupplicantInterface *interface);
const char *g_supplicant_interface_get_wps_key(GSupplicantInterface *interface);
const void *g_supplicant_interface_get_wps_ssid(GSupplicantInterface *interface,
							unsigned int *ssid_len);
GSupplicantWpsState g_supplicant_interface_get_wps_state(GSupplicantInterface *interface);
unsigned int g_supplicant_interface_get_mode(GSupplicantInterface *interface);
dbus_bool_t g_supplicant_interface_get_ready(GSupplicantInterface *interface);
unsigned int g_supplicant_interface_get_max_scan_ssids(
					GSupplicantInterface *interface);

int g_supplicant_interface_enable_selected_network(GSupplicantInterface *interface,
							dbus_bool_t enable);
int g_supplicant_interface_set_country(GSupplicantInterface *interface,
					GSupplicantCountryCallback callback,
							const char *alpha2,
							void *user_data);
bool g_supplicant_interface_has_p2p(GSupplicantInterface *interface);

/* Network and Peer API */
struct _GSupplicantNetwork;
struct _GSupplicantPeer;

typedef struct _GSupplicantNetwork GSupplicantNetwork;
typedef struct _GSupplicantPeer GSupplicantPeer;

GSupplicantInterface *g_supplicant_network_get_interface(GSupplicantNetwork *network);
const char *g_supplicant_network_get_name(GSupplicantNetwork *network);
const char *g_supplicant_network_get_identifier(GSupplicantNetwork *network);
const char *g_supplicant_network_get_path(GSupplicantNetwork *network);
const void *g_supplicant_network_get_ssid(GSupplicantNetwork *network,
							unsigned int *ssid_len);
const char *g_supplicant_network_get_mode(GSupplicantNetwork *network);
const char *g_supplicant_network_get_security(GSupplicantNetwork *network);
dbus_int16_t g_supplicant_network_get_signal(GSupplicantNetwork *network);
dbus_uint16_t g_supplicant_network_get_frequency(GSupplicantNetwork *network);
dbus_bool_t g_supplicant_network_get_wps(GSupplicantNetwork *network);
dbus_bool_t g_supplicant_network_is_wps_active(GSupplicantNetwork *network);
dbus_bool_t g_supplicant_network_is_wps_pbc(GSupplicantNetwork *network);
dbus_bool_t g_supplicant_network_is_wps_advertizing(GSupplicantNetwork *network);

GSupplicantInterface *g_supplicant_peer_get_interface(GSupplicantPeer *peer);
const char *g_supplicant_peer_get_identifier(GSupplicantPeer *peer);
const void *g_supplicant_peer_get_device_address(GSupplicantPeer *peer);
const char *g_supplicant_peer_get_name(GSupplicantPeer *peer);

struct _GSupplicantCallbacks {
	void (*system_ready) (void);
	void (*system_killed) (void);
	void (*interface_added) (GSupplicantInterface *interface);
	void (*interface_state) (GSupplicantInterface *interface);
	void (*interface_removed) (GSupplicantInterface *interface);
	void (*p2p_support) (GSupplicantInterface *interface);
	void (*scan_started) (GSupplicantInterface *interface);
	void (*scan_finished) (GSupplicantInterface *interface);
	void (*network_added) (GSupplicantNetwork *network);
	void (*network_removed) (GSupplicantNetwork *network);
	void (*network_changed) (GSupplicantNetwork *network,
					const char *property);
	void (*peer_found) (GSupplicantPeer *peer);
	void (*peer_lost) (GSupplicantPeer *peer);
	void (*debug) (const char *str);
};

typedef struct _GSupplicantCallbacks GSupplicantCallbacks;

int g_supplicant_register(const GSupplicantCallbacks *callbacks);
void g_supplicant_unregister(const GSupplicantCallbacks *callbacks);

static inline
void g_supplicant_free_scan_params(GSupplicantScanParams *scan_params)
{
	g_slist_free_full(scan_params->ssids, g_free);
	g_free(scan_params->freqs);
	g_free(scan_params);
}

#ifdef __cplusplus
}
#endif

#endif /* __G_SUPPLICANT_H */
