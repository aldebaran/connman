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
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/route.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <glib.h>
#include <gdbus.h>

#include <hal/libhal.h>

#include "connman.h"

static DBusConnection *connection = NULL;

static gchar *ifname_filter = NULL;

static GSList *drivers = NULL;

int connman_iface_register(struct connman_iface_driver *driver)
{
	DBG("driver %p", driver);

	drivers = g_slist_append(drivers, driver);

	return 0;
}

void connman_iface_unregister(struct connman_iface_driver *driver)
{
	DBG("driver %p", driver);

	drivers = g_slist_remove(drivers, driver);
}

static GSList *interfaces = NULL;

struct connman_iface *__connman_iface_find(int index)
{
	GSList *list;

	for (list = interfaces; list; list = list->next) {
		struct connman_iface *iface = list->data;

		if (iface->index == index)
			return iface;
	}

	return NULL;
}

void __connman_iface_list(DBusMessageIter *iter)
{
	GSList *list;

	DBG("");

	for (list = interfaces; list; list = list->next) {
		struct connman_iface *iface = list->data;

		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_OBJECT_PATH, &iface->path);
	}
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

static gboolean scan_timeout(gpointer user_data)
{
	struct connman_iface *iface = user_data;

	switch (iface->state) {
	case CONNMAN_IFACE_STATE_SCANNING:
		if (iface->driver->scan)
			iface->driver->scan(iface);
		return TRUE;
	default:
		break;
	}

	return FALSE;
}

static void state_changed(struct connman_iface *iface)
{
	const char *str = __connman_iface_state2string(iface->state);
	enum connman_iface_state state = iface->state;

	DBG("iface %p state %s", iface, str);

	g_dbus_emit_signal(connection, iface->path,
				CONNMAN_IFACE_INTERFACE, "StateChanged",
				DBUS_TYPE_STRING, &str, DBUS_TYPE_INVALID);

	switch (iface->state) {
	case CONNMAN_IFACE_STATE_OFF:
		__connman_iface_stop(iface);
		break;

	case CONNMAN_IFACE_STATE_ENABLED:
		__connman_iface_start(iface);
		if (iface->flags & CONNMAN_IFACE_FLAG_SCANNING)
			state = CONNMAN_IFACE_STATE_SCANNING;
		break;

	case CONNMAN_IFACE_STATE_SCANNING:
		if (iface->driver->scan)
			iface->driver->scan(iface);
		g_timeout_add(8000, scan_timeout, iface);
		break;

	case CONNMAN_IFACE_STATE_CARRIER:
		if (iface->policy == CONNMAN_IFACE_POLICY_AUTO)
			state = CONNMAN_IFACE_STATE_CONFIGURE;
		break;

	case CONNMAN_IFACE_STATE_CONFIGURE:
		__connman_dhcp_request(iface);
		break;

	case CONNMAN_IFACE_STATE_SHUTDOWN:
		__connman_iface_stop(iface);
		if (iface->policy != CONNMAN_IFACE_POLICY_AUTO)
			state = CONNMAN_IFACE_STATE_OFF;
		break;

	case CONNMAN_IFACE_STATE_READY:
		break;

	default:
		break;
	}

	if (iface->state != state) {
		iface->state = state;
		state_changed(iface);
	}
}

static void switch_policy(struct connman_iface *iface)
{
	DBG("iface %p policy %d", iface, iface->policy);

	switch (iface->policy) {
	case CONNMAN_IFACE_POLICY_OFF:
		__connman_iface_stop(iface);
		break;

	case CONNMAN_IFACE_POLICY_IGNORE:
		break;

	case CONNMAN_IFACE_POLICY_AUTO:
	case CONNMAN_IFACE_POLICY_ASK:
		__connman_iface_start(iface);
		break;

	default:
		break;
	}
}

void connman_iface_indicate_ifup(struct connman_iface *iface)
{
	DBG("iface %p state %d", iface, iface->state);

	switch (iface->state) {
	case CONNMAN_IFACE_STATE_OFF:
		iface->state = CONNMAN_IFACE_STATE_ENABLED;
		state_changed(iface);
		break;
	default:
		break;
	}
}

void connman_iface_indicate_ifdown(struct connman_iface *iface)
{
	DBG("iface %p state %d", iface, iface->state);

	if (iface->policy == CONNMAN_IFACE_POLICY_AUTO)
		iface->state = CONNMAN_IFACE_STATE_ENABLED;
	else
		iface->state = CONNMAN_IFACE_STATE_SHUTDOWN;

	state_changed(iface);
}

void connman_iface_indicate_connected(struct connman_iface *iface)
{
	DBG("iface %p state %d", iface, iface->state);

	switch (iface->state) {
	case CONNMAN_IFACE_STATE_CONNECT:
		iface->state = CONNMAN_IFACE_STATE_CONNECTED;
		state_changed(iface);
		break;
	default:
		break;
	}
}

void connman_iface_indicate_carrier_on(struct connman_iface *iface)
{
	DBG("iface %p state %d", iface, iface->state);

	switch (iface->state) {
	case CONNMAN_IFACE_STATE_ENABLED:
	case CONNMAN_IFACE_STATE_CONNECT:
	case CONNMAN_IFACE_STATE_CONNECTED:
		iface->state = CONNMAN_IFACE_STATE_CARRIER;
		state_changed(iface);
		break;
	default:
		break;
	}
}

void connman_iface_indicate_carrier_off(struct connman_iface *iface)
{
	DBG("iface %p state %d", iface, iface->state);

	switch (iface->state) {
	case CONNMAN_IFACE_STATE_CARRIER:
	case CONNMAN_IFACE_STATE_CONFIGURE:
	case CONNMAN_IFACE_STATE_READY:
		__connman_iface_disconnect(iface);
		if (iface->flags & CONNMAN_IFACE_FLAG_SCANNING)
			iface->state = CONNMAN_IFACE_STATE_SCANNING;
		else
			iface->state = CONNMAN_IFACE_STATE_ENABLED;
		state_changed(iface);
		break;
	default:
		break;
	}
}

void connman_iface_indicate_configured(struct connman_iface *iface)
{
	DBG("iface %p state %d", iface, iface->state);

	switch (iface->state) {
	case CONNMAN_IFACE_STATE_CONFIGURE:
		iface->state = CONNMAN_IFACE_STATE_READY;
		state_changed(iface);
		break;
	default:
		break;
	}
}

static void append_station(DBusMessage *reply, const char *name,
						int signal, int security)
{
	DBusMessageIter array, dict;
	const char *wpa = "WPA";

	dbus_message_iter_init_append(reply, &array);

	dbus_message_iter_open_container(&array, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	append_entry(&dict, "ESSID", DBUS_TYPE_STRING, &name);
	append_entry(&dict, "Signal", DBUS_TYPE_UINT16, &signal);

	if (security > 0)
		append_entry(&dict, "Security", DBUS_TYPE_STRING, &wpa);

	dbus_message_iter_close_container(&array, &dict);
}

void connman_iface_indicate_station(struct connman_iface *iface,
				const char *name, int strength, int security)
{
	DBusMessage *signal;
	char *ssid, *passphrase;
	int len;

	DBG("iface %p security %d name %s", iface, security, name);

	if (name == NULL || strlen(name) == 0)
		return;

	signal = dbus_message_new_signal(iface->path,
				CONNMAN_IFACE_INTERFACE, "NetworkFound");
	if (signal == NULL)
		return;

	append_station(signal, name, strength, security);

	dbus_connection_send(connection, signal, NULL);
	dbus_message_unref(signal);

	switch (iface->state) {
	case CONNMAN_IFACE_STATE_CONNECT:
	case CONNMAN_IFACE_STATE_CONNECTED:
	case CONNMAN_IFACE_STATE_CARRIER:
	case CONNMAN_IFACE_STATE_CONFIGURE:
	case CONNMAN_IFACE_STATE_READY:
		return;
	default:
		break;
	}

	len = strlen(name);
	ssid = strdup(name);
	if (ssid == NULL)
		return;

	/* The D-Link access points return a 0x05 at the end of the SSID */
	if (ssid[len - 1] == '\05')
		ssid[len - 1] = '\0';

	passphrase = __connman_iface_find_passphrase(iface, ssid);
	if (passphrase != NULL) {
		DBG("network %s passphrase %s", ssid, passphrase);

		g_free(iface->network.identifier);
		iface->network.identifier = g_strdup(ssid);
		g_free(iface->network.passphrase);
		iface->network.passphrase = passphrase;

		__connman_iface_connect(iface, &iface->network);

		iface->state = CONNMAN_IFACE_STATE_CONNECT;
		state_changed(iface);
	}

	free(ssid);
}

int connman_iface_get_ipv4(struct connman_iface *iface,
						struct connman_ipv4 *ipv4)
{
#if 0
	struct {
		struct nlmsghdr hdr;
		struct rtgenmsg msg;
	} req;

	if ((iface->flags & CONNMAN_IFACE_FLAG_RTNL) == 0)
		return -1;

	DBG("iface %p ipv4 %p", iface, ipv4);

	memset(&req, 0, sizeof(req));
	req.hdr.nlmsg_len = sizeof(req.hdr) + sizeof(req.msg);
	req.hdr.nlmsg_type = RTM_GETADDR;
	req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.hdr.nlmsg_pid = 0;
	req.hdr.nlmsg_seq = 4711;
	req.msg.rtgen_family = AF_INET;

	__connman_rtnl_send(&req, sizeof(req));
#endif

	return 0;
}

int connman_iface_set_ipv4(struct connman_iface *iface,
						struct connman_ipv4 *ipv4)
{
	struct ifreq ifr;
	struct rtentry rt;
	struct sockaddr_in *addr;
	int sk, err;

	if ((iface->flags & CONNMAN_IFACE_FLAG_RTNL) == 0)
		return -1;

	DBG("iface %p ipv4 %p", iface, ipv4);

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = iface->index;

	if (ioctl(sk, SIOCGIFNAME, &ifr) < 0) {
		close(sk);
		return -1;
	}

	DBG("ifname %s", ifr.ifr_name);

	addr = (struct sockaddr_in *) &ifr.ifr_addr;
	addr->sin_family = AF_INET;
	addr->sin_addr = ipv4->address;

	err = ioctl(sk, SIOCSIFADDR, &ifr);

	if (err < 0)
		DBG("address setting failed (%s)", strerror(errno));

	addr = (struct sockaddr_in *) &ifr.ifr_netmask;
	addr->sin_family = AF_INET;
	addr->sin_addr = ipv4->netmask;

	err = ioctl(sk, SIOCSIFNETMASK, &ifr);

	if (err < 0)
		DBG("netmask setting failed (%s)", strerror(errno));

	addr = (struct sockaddr_in *) &ifr.ifr_broadaddr;
	addr->sin_family = AF_INET;
	addr->sin_addr = ipv4->broadcast;

	err = ioctl(sk, SIOCSIFBRDADDR, &ifr);

	if (err < 0)
		DBG("broadcast setting failed (%s)", strerror(errno));

	memset(&rt, 0, sizeof(rt));
	rt.rt_flags = RTF_UP | RTF_GATEWAY;

	addr = (struct sockaddr_in *) &rt.rt_dst;
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = INADDR_ANY;

	addr = (struct sockaddr_in *) &rt.rt_gateway;
	addr->sin_family = AF_INET;
	addr->sin_addr = ipv4->gateway;

	addr = (struct sockaddr_in *) &rt.rt_genmask;
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = INADDR_ANY;

	err = ioctl(sk, SIOCADDRT, &rt);

	close(sk);

	if (err < 0) {
		DBG("default route failed (%s)", strerror(errno));
		return -1;
	}

	__connman_resolver_append(iface, inet_ntoa(ipv4->nameserver));

	return 0;
}

int connman_iface_clear_ipv4(struct connman_iface *iface)
{
	struct ifreq ifr;
	struct sockaddr_in *addr;
	int sk, err;

	if ((iface->flags & CONNMAN_IFACE_FLAG_RTNL) == 0)
		return -1;

	DBG("iface %p", iface);

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = iface->index;

	if (ioctl(sk, SIOCGIFNAME, &ifr) < 0) {
		close(sk);
		return -1;
	}

	DBG("ifname %s", ifr.ifr_name);

	addr = (struct sockaddr_in *) &ifr.ifr_addr;
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = INADDR_ANY;

	//err = ioctl(sk, SIOCDIFADDR, &ifr);
	err = ioctl(sk, SIOCSIFADDR, &ifr);

	close(sk);

	if (err < 0 && errno != EADDRNOTAVAIL) {
		DBG("address removal failed (%s)", strerror(errno));
		return -1;
	}

	__connman_resolver_remove(iface);

	return 0;
}

static DBusMessage *scan_iface(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_iface *iface = data;
	struct connman_iface_driver *driver = iface->driver;
	DBusMessage *reply;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_INVALID);

	switch (iface->state) {
	case CONNMAN_IFACE_STATE_CONNECT:
	case CONNMAN_IFACE_STATE_CONFIGURE:
			return reply;
	default:
		break;
	}

	if (driver->scan)
		driver->scan(iface);

	return reply;
}

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_iface *iface = data;
	DBusMessage *reply;
	DBusMessageIter array, dict;
	const char *str;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &array);

	dbus_message_iter_open_container(&array, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	str = __connman_iface_type2string(iface->type);
	append_entry(&dict, "Type", DBUS_TYPE_STRING, &str);

	str = __connman_iface_state2string(iface->state);
	append_entry(&dict, "State", DBUS_TYPE_STRING, &str);

	if (iface->type == CONNMAN_IFACE_TYPE_80211) {
		dbus_uint16_t signal = 75;
		append_entry(&dict, "Signal", DBUS_TYPE_UINT16, &signal);
	}

	str = __connman_iface_policy2string(iface->policy);
	append_entry(&dict, "Policy", DBUS_TYPE_STRING, &str);

	if (iface->device.driver != NULL)
		append_entry(&dict, "Driver",
				DBUS_TYPE_STRING, &iface->device.driver);

	if (iface->device.vendor != NULL)
		append_entry(&dict, "Vendor",
				DBUS_TYPE_STRING, &iface->device.vendor);

	if (iface->device.product != NULL)
		append_entry(&dict, "Product",
				DBUS_TYPE_STRING, &iface->device.product);

	dbus_message_iter_close_container(&array, &dict);

	return reply;
}

static DBusMessage *get_state(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_iface *iface = data;
	DBusMessage *reply;
	const char *state;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	state = __connman_iface_state2string(iface->state);

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &state,
							DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *get_signal(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_iface *iface = data;
	DBusMessage *reply;
	dbus_uint16_t signal;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	if (iface->type == CONNMAN_IFACE_TYPE_80211)
		signal = 75;
	else
		signal = 0;

	dbus_message_append_args(reply, DBUS_TYPE_UINT16, &signal,
							DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *get_policy(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_iface *iface = data;
	DBusMessage *reply;
	const char *policy;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	policy = __connman_iface_policy2string(iface->policy);

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &policy,
							DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *set_policy(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_iface *iface = data;
	DBusMessage *reply;
	enum connman_iface_policy new_policy;
	const char *policy;

	DBG("conn %p", conn);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &policy,
							DBUS_TYPE_INVALID);

	new_policy = __connman_iface_string2policy(policy);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_INVALID);

	if (iface->policy != new_policy) {
		iface->policy = new_policy;
		__connman_iface_store(iface);

		switch_policy(iface);
		policy = __connman_iface_policy2string(new_policy);

		g_dbus_emit_signal(conn, iface->path, CONNMAN_IFACE_INTERFACE,
				"PolicyChanged", DBUS_TYPE_STRING, &policy,
							DBUS_TYPE_INVALID);
	}

	return reply;
}

static void append_network(DBusMessage *reply,
				struct connman_iface *iface, gboolean secrets)
{
	DBusMessageIter array, dict;

	dbus_message_iter_init_append(reply, &array);

	dbus_message_iter_open_container(&array, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	switch (iface->type) {
	case CONNMAN_IFACE_TYPE_80211:
		if (iface->network.identifier != NULL)
			append_entry(&dict, "ESSID",
				DBUS_TYPE_STRING, &iface->network.identifier);
		if (secrets == TRUE && iface->network.passphrase != NULL)
			append_entry(&dict, "PSK",
				DBUS_TYPE_STRING, &iface->network.passphrase);
		break;
	default:
		break;
	}

	dbus_message_iter_close_container(&array, &dict);
}

static DBusMessage *get_network(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_iface *iface = data;
	DBusMessage *reply;

	DBG("conn %p", conn);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	append_network(reply, iface, TRUE);

	return reply;
}

static DBusMessage *set_network(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_iface *iface = data;
	DBusMessage *reply, *signal;
	DBusMessageIter array, dict;
	gboolean changed = FALSE;

	DBG("conn %p", conn);

	dbus_message_iter_init(msg, &array);

	dbus_message_iter_recurse(&array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key, *val;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);

		dbus_message_iter_recurse(&entry, &value);

		//type = dbus_message_iter_get_arg_type(&value);
		dbus_message_iter_get_basic(&value, &val);

		if (g_strcasecmp(key, "ESSID") == 0) {
			g_free(iface->network.identifier);
			iface->network.identifier = g_strdup(val);
			changed = TRUE;
		}

		if (g_strcasecmp(key, "PSK") == 0) {
			g_free(iface->network.passphrase);
			iface->network.passphrase = g_strdup(val);
			changed = TRUE;
		}

		dbus_message_iter_next(&dict);
	}

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_INVALID);

	if (changed == TRUE) {
		__connman_iface_store(iface);

		signal = dbus_message_new_signal(iface->path,
				CONNMAN_IFACE_INTERFACE, "NetworkChanged");
		if (signal != NULL) {
			append_network(signal, iface, FALSE);
			dbus_connection_send(conn, signal, NULL);
			dbus_message_unref(signal);
		}

		__connman_iface_connect(iface, &iface->network);
	}

	return reply;
}

static DBusMessage *select_network(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_iface *iface = data;
	DBusMessage *reply;
	const char *network;

	DBG("conn %p", conn);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &network,
							DBUS_TYPE_INVALID);

	g_free(iface->network.identifier);
	iface->network.identifier = g_strdup(network);

	__connman_iface_connect(iface, &iface->network);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_INVALID);

	return reply;
}

static void append_ipv4(DBusMessage *reply, struct connman_iface *iface)
{
	DBusMessageIter array, dict;
	const char *str;

	dbus_message_iter_init_append(reply, &array);

	dbus_message_iter_open_container(&array, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	str = __connman_ipv4_method2string(CONNMAN_IPV4_METHOD_DHCP);
	append_entry(&dict, "Method", DBUS_TYPE_STRING, &str);

	if (iface->ipv4.address.s_addr != INADDR_ANY) {
		str = inet_ntoa(iface->ipv4.address);
		append_entry(&dict, "Address", DBUS_TYPE_STRING, &str);
	}

	if (iface->ipv4.netmask.s_addr != INADDR_ANY) {
		str = inet_ntoa(iface->ipv4.netmask);
		append_entry(&dict, "Netmask", DBUS_TYPE_STRING, &str);
	}

	if (iface->ipv4.gateway.s_addr != INADDR_ANY) {
		str = inet_ntoa(iface->ipv4.gateway);
		append_entry(&dict, "Gateway", DBUS_TYPE_STRING, &str);
	}

	dbus_message_iter_close_container(&array, &dict);
}

static DBusMessage *get_ipv4(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_iface *iface = data;
	DBusMessage *reply;

	DBG("conn %p", conn);

	switch (iface->policy) {
	case CONNMAN_IFACE_POLICY_OFF:
	case CONNMAN_IFACE_POLICY_IGNORE:
		return dbus_message_new_error(msg, CONNMAN_ERROR_INTERFACE
						".NotAvailable", "");
	default:
		break;
	}

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	append_ipv4(reply, iface);

	return reply;
}

static DBusMessage *set_ipv4(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_iface *iface = data;
	DBusMessage *reply, *signal;
	DBusMessageIter array, dict;
	gboolean changed = FALSE;

	DBG("conn %p", conn);

	return dbus_message_new_error(msg, CONNMAN_ERROR_INTERFACE
						".NotImplemented", "");

	dbus_message_iter_init(msg, &array);

	dbus_message_iter_recurse(&array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key, *val;
		enum connman_ipv4_method method;
		in_addr_t addr;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);

		dbus_message_iter_recurse(&entry, &value);

		//type = dbus_message_iter_get_arg_type(&value);
		dbus_message_iter_get_basic(&value, &val);

		if (g_strcasecmp(key, "Method") == 0) {
			method = __connman_ipv4_string2method(val);
			if (iface->ipv4.method != method) {
				iface->ipv4.method = method;
				changed = TRUE;
			}
		}

		if (g_strcasecmp(key, "Address") == 0) {
			addr = inet_addr(val);
			if (iface->ipv4.address.s_addr != addr) {
				iface->ipv4.address.s_addr = addr;
				changed = TRUE;
			}
		}

		if (g_strcasecmp(key, "Netmask") == 0) {
			addr = inet_addr(val);
			if (iface->ipv4.netmask.s_addr != addr) {
				iface->ipv4.netmask.s_addr = addr;
				changed = TRUE;
			}
		}

		if (g_strcasecmp(key, "Gateway") == 0) {
			addr = inet_addr(val);
			if (iface->ipv4.gateway.s_addr != addr) {
				iface->ipv4.gateway.s_addr = addr;
				changed = TRUE;
			}
		}

		dbus_message_iter_next(&dict);
	}

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_INVALID);

	if (changed == TRUE) {
		__connman_iface_store(iface);

		signal = dbus_message_new_signal(iface->path,
				CONNMAN_IFACE_INTERFACE, "IPv4Changed");
		if (signal != NULL) {
			append_ipv4(signal, iface);
			dbus_connection_send(conn, signal, NULL);
			dbus_message_unref(signal);
		}
	}

	return reply;
}

static GDBusMethodTable iface_methods[] = {
	{ "Scan",          "",      "",      scan_iface     },
	{ "GetProperties", "",      "a{sv}", get_properties },
	{ "GetState",      "",      "s",     get_state      },
	{ "GetSignal",     "",      "q",     get_signal     },
	{ "GetPolicy",     "",      "s",     get_policy     },
	{ "SetPolicy",     "s",     "",      set_policy     },
	{ "GetNetwork",    "",      "a{sv}", get_network    },
	{ "SetNetwork",    "a{sv}", "",      set_network    },
	{ "SelectNetwork", "s",     "",      select_network },
	{ "GetIPv4",       "",      "a{sv}", get_ipv4       },
	{ "SetIPv4",       "a{sv}", "",      set_ipv4       },
	{ },
};

static GDBusSignalTable iface_signals[] = {
	{ "StateChanged",   "s"     },
	{ "SignalChanged",  "q"     },
	{ "PolicyChanged",  "s"     },
	{ "NetworkFound",   "a{sv}" },
	{ "NetworkChanged", "a{sv}" },
	{ "IPv4Changed",    "a{sv}" },
	{ },
};

static void device_free(void *data)
{
	struct connman_iface *iface = data;

	DBG("iface %p", iface);

	connman_iface_clear_ipv4(iface);

	if (iface->driver && iface->driver->remove)
		iface->driver->remove(iface);

	g_free(iface->path);
	g_free(iface->udi);
	g_free(iface->sysfs);
	g_free(iface->identifier);
	g_free(iface->network.identifier);
	g_free(iface->network.passphrase);
	g_free(iface->device.driver);
	g_free(iface->device.vendor);
	g_free(iface->device.product);
	g_free(iface);
}

static void detect_device_info(LibHalContext *ctx, struct connman_iface *iface)
{
	char *parent, *subsys, *value;

	parent = libhal_device_get_property_string(ctx, iface->udi,
						"info.parent", NULL);

	subsys = libhal_device_get_property_string(ctx, iface->udi,
						"linux.subsystem", NULL);

	value = libhal_device_get_property_string(ctx, iface->udi,
						"info.linux.driver", NULL);
	if (value == NULL) {
		value = libhal_device_get_property_string(ctx, parent,
						"info.linux.driver", NULL);
		if (value != NULL)
			iface->device.driver = g_strdup(value);
	}

	if (strcmp(subsys, "net") == 0) {
		value = libhal_device_get_property_string(ctx, parent,
							"info.vendor", NULL);
		if (value != NULL)
			iface->device.vendor = g_strdup(value);

		value = libhal_device_get_property_string(ctx, parent,
							"info.product", NULL);
		if (value != NULL)
			iface->device.product = g_strdup(value);
	}
}

static int probe_device(LibHalContext *ctx,
			struct connman_iface_driver *driver, const char *udi)
{
	DBusConnection *conn;
	struct connman_iface *iface;
	char *temp, *sysfs, *ifname;
	int err;

	DBG("ctx %p driver %p udi %s", ctx, driver, udi);

	if (!driver->probe)
		return -1;

	iface = g_try_new0(struct connman_iface, 1);
	if (iface == NULL)
		return -1;

	temp = g_path_get_basename(udi);
	iface->path = g_strdup_printf("%s/%s", CONNMAN_IFACE_BASEPATH, temp);
	g_free(temp);

	iface->udi = g_strdup(udi);

	DBG("iface %p path %s", iface, iface->path);

	sysfs = libhal_device_get_property_string(ctx, udi,
						"linux.sysfs_path", NULL);
	if (sysfs != NULL)
		iface->sysfs = g_strdup(sysfs);

	detect_device_info(ctx, iface);

	iface->index = -1;

	if (g_str_has_prefix(driver->capability, "net") == TRUE) {
		iface->index = libhal_device_get_property_int(ctx, udi,
						"net.linux.ifindex", NULL);

		ifname = libhal_device_get_property_string(ctx, udi,
						"net.interface", NULL);
		if (ifname != NULL && ifname_filter != NULL &&
						*ifname_filter != '\0' &&
				g_str_equal(ifname, ifname_filter) == FALSE) {
			device_free(iface);
			return -1;
		}
	}

	iface->type = CONNMAN_IFACE_TYPE_UNKNOWN;
	iface->flags = 0;
	iface->state = CONNMAN_IFACE_STATE_UNKNOWN;
	iface->policy = CONNMAN_IFACE_POLICY_UNKNOWN;

	err = driver->probe(iface);
	if (err < 0) {
		device_free(iface);
		return -1;
	}

	__connman_iface_create_identifier(iface);

	__connman_iface_init_via_inet(iface);

	iface->driver = driver;

	iface->policy = CONNMAN_IFACE_POLICY_AUTO;

	__connman_iface_load(iface);

	DBG("iface %p network %s secret %s", iface,
					iface->network.identifier,
					iface->network.passphrase);

	conn = libhal_ctx_get_dbus_connection(ctx);

	g_dbus_register_object(conn, iface->path, iface, device_free);

	interfaces = g_slist_append(interfaces, iface);

	if (iface->flags & CONNMAN_IFACE_FLAG_IPV4) {
		connman_iface_get_ipv4(iface, &iface->ipv4);

		DBG("address %s", inet_ntoa(iface->ipv4.address));
	}

	g_dbus_register_interface(conn, iface->path,
					CONNMAN_IFACE_INTERFACE,
					iface_methods, iface_signals, NULL);

	DBG("iface %p identifier %s", iface, iface->identifier);

	g_dbus_emit_signal(conn, CONNMAN_MANAGER_PATH,
					CONNMAN_MANAGER_INTERFACE,
					"InterfaceAdded",
					DBUS_TYPE_OBJECT_PATH, &iface->path,
					DBUS_TYPE_INVALID);

	switch_policy(iface);

	state_changed(iface);

	return 0;
}

static void device_added(LibHalContext *ctx, const char *udi)
{
	GSList *list;

	DBG("ctx %p udi %s", ctx, udi);

	for (list = drivers; list; list = list->next) {
		struct connman_iface_driver *driver = list->data;

		if (driver->capability == NULL)
			continue;

		if (libhal_device_query_capability(ctx, udi,
					driver->capability, NULL) == TRUE) {
			if (probe_device(ctx, driver, udi) == 0)
				break;
		}
	}
}

static void device_removed(LibHalContext *ctx, const char *udi)
{
	DBusConnection *conn;
	GSList *list;

	DBG("ctx %p udi %s", ctx, udi);

	conn = libhal_ctx_get_dbus_connection(ctx);

	for (list = interfaces; list; list = list->next) {
		struct connman_iface *iface = list->data;

		if (strcmp(udi, iface->udi) == 0) {
			g_dbus_emit_signal(conn, CONNMAN_MANAGER_PATH,
					CONNMAN_MANAGER_INTERFACE,
					"InterfaceRemoved",
					DBUS_TYPE_OBJECT_PATH, &iface->path,
					DBUS_TYPE_INVALID);
			interfaces = g_slist_remove(interfaces, iface);
			g_dbus_unregister_interface(conn, iface->path,
						CONNMAN_IFACE_INTERFACE);
			g_dbus_unregister_object(conn, iface->path);
			break;
		}
	}
}

static void probe_driver(LibHalContext *ctx,
				struct connman_iface_driver *driver)
{
	char **list;
	int num;

	DBG("ctx %p driver %p", ctx, driver);

	list = libhal_find_device_by_capability(ctx,
					driver->capability, &num, NULL);
	if (list) {
		char **tmp = list;

		while (*tmp) {
			probe_device(ctx, driver, *tmp);
			tmp++;
		}

		libhal_free_string_array(list);
	}
}

static void find_devices(LibHalContext *ctx)
{
	GSList *list;

	DBG("ctx %p", ctx);

	for (list = drivers; list; list = list->next) {
		struct connman_iface_driver *driver = list->data;

		DBG("driver %p", driver);

		if (driver->capability == NULL)
			continue;

		probe_driver(ctx, driver);
	}
}

static LibHalContext *hal_ctx = NULL;

static void hal_init(void *data)
{
	DBusConnection *conn = data;

	DBG("conn %p", conn);

	if (hal_ctx != NULL)
		return;

	hal_ctx = libhal_ctx_new();
	if (hal_ctx == NULL)
		return;

	if (libhal_ctx_set_dbus_connection(hal_ctx, conn) == FALSE) {
		libhal_ctx_free(hal_ctx);
		return;
	}

	if (libhal_ctx_init(hal_ctx, NULL) == FALSE) {
		libhal_ctx_free(hal_ctx);
		return ;
	}

	libhal_ctx_set_device_added(hal_ctx, device_added);
	libhal_ctx_set_device_removed(hal_ctx, device_removed);

	//libhal_ctx_set_device_new_capability(hal_ctx, new_capability);
	//libhal_ctx_set_device_lost_capability(hal_ctx, lost_capability);

	find_devices(hal_ctx);
}

static void hal_cleanup(void *data)
{
	DBusConnection *conn = data;
	GSList *list;

	DBG("conn %p", conn);

	if (hal_ctx == NULL)
		return;

	for (list = interfaces; list; list = list->next) {
		struct connman_iface *iface = list->data;

		DBG("path %s", iface->path);

		g_dbus_emit_signal(conn, CONNMAN_MANAGER_PATH,
					CONNMAN_MANAGER_INTERFACE,
					"InterfaceRemoved",
					DBUS_TYPE_OBJECT_PATH, &iface->path,
					DBUS_TYPE_INVALID);

		g_dbus_unregister_interface(conn, iface->path,
						CONNMAN_IFACE_INTERFACE);

		g_dbus_unregister_object(conn, iface->path);
	}

	g_slist_free(interfaces);

	interfaces = NULL;

	libhal_ctx_shutdown(hal_ctx, NULL);

	libhal_ctx_free(hal_ctx);

	hal_ctx = NULL;
}

static guint hal_watch = 0;

int __connman_iface_init(DBusConnection *conn, const char *interface)
{
	DBG("conn %p", conn);

	connection = dbus_connection_ref(conn);
	if (connection == NULL)
		return -1;

	if (interface != NULL)
		ifname_filter = g_strdup(interface);

	hal_init(connection);

	hal_watch = g_dbus_add_watch(connection, "org.freedesktop.Hal",
				hal_init, hal_cleanup, connection, NULL);

	return 0;
}

void __connman_iface_cleanup(void)
{
	DBG("conn %p", connection);

	g_dbus_remove_watch(connection, hal_watch);

	hal_cleanup(connection);

	g_free(ifname_filter);

	dbus_connection_unref(connection);
}
