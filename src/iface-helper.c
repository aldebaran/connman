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

#include <string.h>

#include "connman.h"

const char *__connman_iface_type2string(enum connman_iface_type type)
{
	switch (type) {
	case CONNMAN_IFACE_TYPE_UNKNOWN:
		return "unknown";
	case CONNMAN_IFACE_TYPE_80203:
		return "80203";
	case CONNMAN_IFACE_TYPE_80211:
		return "80211";
	case CONNMAN_IFACE_TYPE_WIMAX:
		return "wimax";
	case CONNMAN_IFACE_TYPE_MODEM:
		return "modem";
	case CONNMAN_IFACE_TYPE_BLUETOOTH:
		return "bluetooth";
	}

	return "unknown";
}

const char *__connman_iface_state2string(enum connman_iface_state state)
{
	switch (state) {
	case CONNMAN_IFACE_STATE_UNKNOWN:
		return "unknown";
	case CONNMAN_IFACE_STATE_OFF:
		return "off";
	case CONNMAN_IFACE_STATE_ENABLED:
		return "enabled";
	case CONNMAN_IFACE_STATE_SCANNING:
		return "scanning";
	case CONNMAN_IFACE_STATE_CONNECT:
		return "connect";
	case CONNMAN_IFACE_STATE_CONNECTED:
		return "connected";
	case CONNMAN_IFACE_STATE_CARRIER:
		return "carrier";
	case CONNMAN_IFACE_STATE_CONFIGURE:
		return "configure";
	case CONNMAN_IFACE_STATE_READY:
		return "ready";
	case CONNMAN_IFACE_STATE_SHUTDOWN:
		return "shutdown";
	}

	return "unknown";
}

const char *__connman_iface_policy2string(enum connman_iface_policy policy)
{
	switch (policy) {
	case CONNMAN_IFACE_POLICY_UNKNOWN:
		return "unknown";
	case CONNMAN_IFACE_POLICY_OFF:
		return "off";
	case CONNMAN_IFACE_POLICY_IGNORE:
		return "ignore";
	case CONNMAN_IFACE_POLICY_AUTO:
		return "auto";
	case CONNMAN_IFACE_POLICY_ASK:
		return "ask";
	}

	return "unknown";
}

enum connman_iface_policy __connman_iface_string2policy(const char *policy)
{
	if (strcasecmp(policy, "off") == 0)
		return CONNMAN_IFACE_POLICY_OFF;
	else if (strcasecmp(policy, "ignore") == 0)
		return CONNMAN_IFACE_POLICY_IGNORE;
	else if (strcasecmp(policy, "auto") == 0)
		return CONNMAN_IFACE_POLICY_AUTO;
	else if (strcasecmp(policy, "ask") == 0)
		return CONNMAN_IFACE_POLICY_ASK;
	else
		return CONNMAN_IFACE_POLICY_UNKNOWN;
}

const char *__connman_ipv4_method2string(enum connman_ipv4_method method)
{
	switch (method) {
	case CONNMAN_IPV4_METHOD_UNKNOWN:
		return "unknown";
	case CONNMAN_IPV4_METHOD_OFF:
		return "off";
	case CONNMAN_IPV4_METHOD_STATIC:
		return "static";
	case CONNMAN_IPV4_METHOD_DHCP:
		return "dhcp";
	}

	return "unknown";
}

enum connman_ipv4_method __connman_ipv4_string2method(const char *method)
{
	if (strcasecmp(method, "off") == 0)
		return CONNMAN_IPV4_METHOD_OFF;
	else if (strcasecmp(method, "static") == 0)
		return CONNMAN_IPV4_METHOD_STATIC;
	else if (strcasecmp(method, "dhcp") == 0)
		return CONNMAN_IPV4_METHOD_DHCP;
	else
		return CONNMAN_IPV4_METHOD_UNKNOWN;
}
