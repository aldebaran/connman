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

#include <connman/element.h>

#define SUPPLICANT_NAME  "fi.epitest.hostap.WPASupplicant"
#define SUPPLICANT_INTF  "fi.epitest.hostap.WPASupplicant"
#define SUPPLICANT_PATH  "/fi/epitest/hostap/WPASupplicant"

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

struct supplicant_network {
	gchar *identifier;
	guint8 *ssid;
	guint ssid_len;
	guint16 capabilities;
	gboolean has_wep;
	gboolean has_wpa;
	gboolean has_rsn;
	gint32 quality;
	gint32 noise;
	gint32 level;
	gint32 maxrate;
};

struct supplicant_callback {
	void (*state_change) (struct connman_element *element,
						enum supplicant_state state);
	void (*scan_result) (struct connman_element *element,
					struct supplicant_network *network);
};

int __supplicant_init(DBusConnection *conn);
void __supplicant_exit(void);

int __supplicant_start(struct connman_element *element,
					struct supplicant_callback *callback);
int __supplicant_stop(struct connman_element *element);

int __supplicant_scan(struct connman_element *element);

int __supplicant_connect(struct connman_element *element,
				const unsigned char *ssid, int ssid_len,
							const char *passphrase);
int __supplicant_disconnect(struct connman_element *element);
