/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2010  BMW Car IT GmbH. All rights reserved.
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

#define VPN_FLAG_NO_TUN	1

enum vpn_state {
	VPN_STATE_UNKNOWN       = 0,
	VPN_STATE_IDLE          = 1,
	VPN_STATE_CONNECT       = 2,
	VPN_STATE_READY         = 3,
	VPN_STATE_DISCONNECT    = 4,
	VPN_STATE_FAILURE       = 5,
	VPN_STATE_AUTH_FAILURE  = 6,
};

struct vpn_driver {
	int flags;
	int (*notify) (DBusMessage *msg, struct connman_provider *provider);
	int (*connect) (struct connman_provider *provider,
			struct connman_task *task, const char *if_name);
	void (*disconnect) (void);
	int (*error_code) (int exit_code);
	int (*save) (struct connman_provider *provider, GKeyFile *keyfile);
};

int vpn_register(const char *name, struct vpn_driver *driver,
			const char *program);
void vpn_unregister(const char *provider_name);
void vpn_died(struct connman_task *task, int exit_code, void *user_data);
int vpn_set_ifname(struct connman_provider *provider, const char *ifname);
