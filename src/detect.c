/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2009  Intel Corporation. All rights reserved.
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
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <linux/if_arp.h>
#include <linux/wireless.h>

#include <glib.h>

#include "connman.h"

static GSList *device_list = NULL;

static struct connman_device *find_device(int index)
{
	GSList *list;

	for (list = device_list; list; list = list->next) {
		struct connman_device *device = list->data;

		if (connman_device_get_index(device) == index)
			return device;
	}

	return NULL;
}

static char *index2name(int index)
{
	struct ifreq ifr;
	int sk, err;

	if (index < 0)
		return NULL;

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0)
		return NULL;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = index;

	err = ioctl(sk, SIOCGIFNAME, &ifr);

	close(sk);

	if (err < 0)
		return NULL;

	return strdup(ifr.ifr_name);
}

static char *index2addr(int index)
{
	struct ifreq ifr;
	struct ether_addr *eth;
	char *str;
	int sk, err;

	if (index < 0)
		return NULL;

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0)
		return NULL;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = index;

	err = ioctl(sk, SIOCGIFNAME, &ifr);

	if (err == 0)
		err = ioctl(sk, SIOCGIFHWADDR, &ifr);

	close(sk);

	if (err < 0)
		return NULL;

	str = malloc(18);
	if (!str)
		return NULL;

	eth = (void *) &ifr.ifr_hwaddr.sa_data;
	snprintf(str, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
						eth->ether_addr_octet[0],
						eth->ether_addr_octet[1],
						eth->ether_addr_octet[2],
						eth->ether_addr_octet[3],
						eth->ether_addr_octet[4],
						eth->ether_addr_octet[5]);

	return str;
}

static char *index2ident(int index, const char *prefix)
{
	struct ifreq ifr;
	struct ether_addr *eth;
	char *str;
	int sk, err, len;

	if (index < 0)
		return NULL;

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0)
		return NULL;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = index;

	err = ioctl(sk, SIOCGIFNAME, &ifr);

	if (err == 0)
		err = ioctl(sk, SIOCGIFHWADDR, &ifr);

	close(sk);

	if (err < 0)
		return NULL;

	len = prefix ? strlen(prefix) + 18 : 18;

	str = malloc(len);
	if (!str)
		return NULL;

	eth = (void *) &ifr.ifr_hwaddr.sa_data;
	snprintf(str, len, "%s%02X_%02X_%02X_%02X_%02X_%02X",
						prefix ? prefix : "",
						eth->ether_addr_octet[0],
						eth->ether_addr_octet[1],
						eth->ether_addr_octet[2],
						eth->ether_addr_octet[3],
						eth->ether_addr_octet[4],
						eth->ether_addr_octet[5]);

	return str;
}

static void detect_newlink(unsigned short type, int index,
					unsigned flags, unsigned change)
{
	enum connman_device_type devtype = CONNMAN_DEVICE_TYPE_UNKNOWN;
	enum connman_device_mode mode = CONNMAN_DEVICE_MODE_UNKNOWN;
	struct connman_device *device;
	gchar *addr, *name, *devname;

	DBG("type %d index %d", type, index);

	device = find_device(index);
	if (device != NULL)
		return;

	devname = index2name(index);
	if (devname == NULL)
		return;

	if (type == ARPHRD_ETHER) {
		char bridge_path[PATH_MAX], wimax_path[PATH_MAX];
		struct stat st;
		struct iwreq iwr;
		int sk;

		snprintf(bridge_path, PATH_MAX,
					"/sys/class/net/%s/bridge", devname);
		snprintf(wimax_path, PATH_MAX,
					"/sys/class/net/%s/wimax", devname);

		memset(&iwr, 0, sizeof(iwr));
		strncpy(iwr.ifr_ifrn.ifrn_name, devname, IFNAMSIZ);

		sk = socket(PF_INET, SOCK_DGRAM, 0);

		if (g_str_has_prefix(devname, "bnep") == TRUE)
			devtype = CONNMAN_DEVICE_TYPE_UNKNOWN;
		else if (g_str_has_prefix(devname, "wmx") == TRUE)
			devtype = CONNMAN_DEVICE_TYPE_UNKNOWN;
		else if (g_str_has_prefix(devname, "vmnet") == TRUE)
			devtype = CONNMAN_DEVICE_TYPE_UNKNOWN;
		else if (g_str_has_prefix(devname, "vboxnet") == TRUE)
			devtype = CONNMAN_DEVICE_TYPE_UNKNOWN;
		else if (stat(bridge_path, &st) == 0 && (st.st_mode & S_IFDIR))
			devtype = CONNMAN_DEVICE_TYPE_UNKNOWN;
		else if (stat(wimax_path, &st) == 0 && (st.st_mode & S_IFDIR))
			devtype = CONNMAN_DEVICE_TYPE_UNKNOWN;
		else if (ioctl(sk, SIOCGIWNAME, &iwr) == 0)
			devtype = CONNMAN_DEVICE_TYPE_WIFI;
		else
			devtype = CONNMAN_DEVICE_TYPE_ETHERNET;

		close(sk);
	} else if (type == ARPHRD_NONE) {
		if (g_str_has_prefix(devname, "hso") == TRUE)
			devtype = CONNMAN_DEVICE_TYPE_HSO;
	}

	switch (devtype) {
	case CONNMAN_DEVICE_TYPE_UNKNOWN:
		g_free(devname);
		return;
	case CONNMAN_DEVICE_TYPE_ETHERNET:
	case CONNMAN_DEVICE_TYPE_WIFI:
	case CONNMAN_DEVICE_TYPE_WIMAX:
		name = index2ident(index, "dev_");
		addr = index2addr(index);
		break;
	case CONNMAN_DEVICE_TYPE_BLUETOOTH:
	case CONNMAN_DEVICE_TYPE_GPS:
	case CONNMAN_DEVICE_TYPE_HSO:
	case CONNMAN_DEVICE_TYPE_NOZOMI:
	case CONNMAN_DEVICE_TYPE_HUAWEI:
	case CONNMAN_DEVICE_TYPE_NOVATEL:
	case CONNMAN_DEVICE_TYPE_VENDOR:
		name = strdup(devname);
		addr = NULL;
		break;
	}

	device = connman_device_create(name, devtype);
	if (device == NULL) {
		g_free(devname);
		g_free(name);
		g_free(addr);
		return;
	}

	switch (devtype) {
	case CONNMAN_DEVICE_TYPE_UNKNOWN:
	case CONNMAN_DEVICE_TYPE_VENDOR:
	case CONNMAN_DEVICE_TYPE_NOZOMI:
	case CONNMAN_DEVICE_TYPE_HUAWEI:
	case CONNMAN_DEVICE_TYPE_NOVATEL:
	case CONNMAN_DEVICE_TYPE_GPS:
		mode = CONNMAN_DEVICE_MODE_UNKNOWN;
		break;
	case CONNMAN_DEVICE_TYPE_ETHERNET:
		mode = CONNMAN_DEVICE_MODE_TRANSPORT_IP;
		break;
	case CONNMAN_DEVICE_TYPE_WIFI:
	case CONNMAN_DEVICE_TYPE_WIMAX:
		mode = CONNMAN_DEVICE_MODE_NETWORK_SINGLE;
		break;
	case CONNMAN_DEVICE_TYPE_BLUETOOTH:
		mode = CONNMAN_DEVICE_MODE_NETWORK_MULTIPLE;
		break;
	case CONNMAN_DEVICE_TYPE_HSO:
		mode = CONNMAN_DEVICE_MODE_NETWORK_SINGLE;
		connman_device_set_policy(device, CONNMAN_DEVICE_POLICY_MANUAL);
		break;
	}

	connman_device_set_mode(device, mode);

	connman_device_set_index(device, index);
	connman_device_set_interface(device, devname);

	connman_device_set_string(device, "Address", addr);

	g_free(devname);
	g_free(name);
	g_free(addr);

	if (connman_device_register(device) < 0) {
		connman_device_unref(device);
		return;
	}

	device_list = g_slist_append(device_list, device);
}

static void detect_dellink(unsigned short type, int index,
					unsigned flags, unsigned change)
{
	struct connman_device *device;

	DBG("type %d index %d", type, index);

	device = find_device(index);
	if (device == NULL)
		return;

	device_list = g_slist_remove(device_list, device);

	connman_device_unregister(device);
	connman_device_unref(device);
}

static struct connman_rtnl detect_rtnl = {
	.name		= "detect",
	.priority	= CONNMAN_RTNL_PRIORITY_LOW,
	.newlink	= detect_newlink,
	.dellink	= detect_dellink,
};

int __connman_detect_init(void)
{
	int err;

	err = connman_rtnl_register(&detect_rtnl);
	if (err < 0)
		return err;

	connman_rtnl_send_getlink();

	return 0;
}

void __connman_detect_cleanup(void)
{
	GSList *list;

	connman_rtnl_unregister(&detect_rtnl);

	for (list = device_list; list; list = list->next) {
		struct connman_device *device = list->data;

		connman_device_unregister(device);
		connman_device_unref(device);
	}

	g_slist_free(device_list);
	device_list = NULL;
}
