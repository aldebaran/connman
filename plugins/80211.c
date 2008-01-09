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
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/wireless.h>

#include <glib.h>

#include <connman/plugin.h>
#include <connman/iface.h>

#include "supplicant.h"

struct station_data {
	char *address;
	char *name;
	int mode;
	int qual;
	int noise;
	int level;

	unsigned char wpa_ie[40];
	int wpa_ie_len;
	unsigned char rsn_ie[40];
	int rsn_ie_len;
};

struct iface_data {
	char ifname[IFNAMSIZ];
	GSList *stations;

	gchar *network;
	gchar *passphrase;
};

static struct station_data *create_station(struct iface_data *iface,
							const char *address)
{
	struct station_data *station;
	GSList *list;

	for (list = iface->stations; list; list = list->next) {
		station = list->data;

		if (g_ascii_strcasecmp(station->address, address) == 0)
			return station;
	}

	station = g_try_new0(struct station_data, 1);
	if (station == NULL)
		return NULL;

	station->address = g_strdup(address);
	if (station->address == NULL) {
		g_free(station);
		return NULL;
	}

	iface->stations = g_slist_append(iface->stations, station);

	return station;
}

static void load_stations(struct iface_data *iface)
{
	GKeyFile *keyfile;
	gchar **groups, **group;
	gsize length;

	keyfile = g_key_file_new();

	if (g_key_file_load_from_file(keyfile, "/tmp/stations.list",
				G_KEY_FILE_KEEP_COMMENTS, NULL) == FALSE)
		goto done;

	groups = g_key_file_get_groups(keyfile, &length);

	for (group = groups; *group; group++) {
		struct station_data *station;

		station = create_station(iface, *group);
		if (station == NULL)
			continue;

		station->name = g_key_file_get_string(keyfile,
						*group, "Name", NULL);
	
		station->mode = g_key_file_get_integer(keyfile,
						*group, "Mode", NULL);
	}

	g_strfreev(groups);

done:
	g_key_file_free(keyfile);

	printf("[802.11] loaded %d stations\n",
				g_slist_length(iface->stations));
}

static void print_stations(struct iface_data *iface)
{
	GKeyFile *keyfile;
	gchar *data;
	gsize length;
	GSList *list;

	keyfile = g_key_file_new();

	for (list = iface->stations; list; list = list->next) {
		struct station_data *station = list->data;

		//printf("Address:%s Mode:%d ESSID:\"%s\" Quality:%d/100\n",
		//			station->address, station->mode,
		//				station->name, station->qual);

		g_key_file_set_string(keyfile, station->address,
						"Name", station->name);

		g_key_file_set_integer(keyfile, station->address,
						"Mode", station->mode);
	}

	data = g_key_file_to_data(keyfile, &length, NULL);

	g_file_set_contents("/tmp/stations.list", data, length, NULL);

	g_key_file_free(keyfile);
}

static int iface_probe(struct connman_iface *iface)
{
	struct iface_data *data;
	struct ifreq ifr;
	int sk, err;

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0)
		return -EIO;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = iface->index;

	err = ioctl(sk, SIOCGIFNAME, &ifr);

	close(sk);

	if (err < 0)
		return -EIO;

	printf("[802.11] probe %s\n", ifr.ifr_name);

	data = malloc(sizeof(*data));
	if (data == NULL)
		return -ENOMEM;

	memset(data, 0, sizeof(*data));

	memcpy(data->ifname, ifr.ifr_name, IFNAMSIZ);

	iface->type = CONNMAN_IFACE_TYPE_80211;

	iface->flags = CONNMAN_IFACE_FLAG_RTNL |
				CONNMAN_IFACE_FLAG_IPV4;

	connman_iface_set_data(iface, data);

	load_stations(data);

	return 0;
}

static void iface_remove(struct connman_iface *iface)
{
	struct iface_data *data = connman_iface_get_data(iface);

	printf("[802.11] remove %s\n", data->ifname);

	__supplicant_stop(iface);

	connman_iface_set_data(iface, NULL);

	g_free(data->network);
	g_free(data->passphrase);

	free(data);
}

static int iface_activate(struct connman_iface *iface)
{
	struct iface_data *data = connman_iface_get_data(iface);

	printf("[802.11] activate %s\n", data->ifname);

	connman_iface_update(iface, CONNMAN_IFACE_STATE_ENABLED);

	return 0;
}

static int iface_shutdown(struct connman_iface *iface)
{
	struct iface_data *data = connman_iface_get_data(iface);

	printf("[802.11] shutdown %s\n", data->ifname);

	__supplicant_stop(iface);

	connman_iface_update(iface, CONNMAN_IFACE_STATE_OFF);

	return 0;
}

static int iface_scan(struct connman_iface *iface)
{
	struct iface_data *data = connman_iface_get_data(iface);
	struct iwreq iwr;
	struct iw_scan_req iws;
	int sk, err;

	printf("[802.11] scanning %s\n", data->ifname);

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0)
		return -EIO;

	memset(&iws, 0, sizeof(iws));
	iws.scan_type = IW_SCAN_TYPE_PASSIVE;
	//iws.scan_type = IW_SCAN_TYPE_ACTIVE;

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, data->ifname, IFNAMSIZ);

	iwr.u.data.pointer = (caddr_t ) &iws;
	iwr.u.data.length = sizeof(iws);
	iwr.u.data.flags = IW_SCAN_DEFAULT;

	err = ioctl(sk, SIOCSIWSCAN, &iwr);

	close(sk);

	if (err < 0)
		printf("[802.11] scan initiate error %d\n", errno);

	return err;
}

static int iface_connect(struct connman_iface *iface,
					struct connman_network *network)
{
	struct iface_data *data = connman_iface_get_data(iface);

	printf("[802.11] connect %s\n", data->ifname);

	__supplicant_start(iface);

	__supplicant_connect(iface, data->network, data->passphrase);

	return 0;
}

static void iface_set_network(struct connman_iface *iface,
						const char *network)
{
	struct iface_data *data = connman_iface_get_data(iface);

	printf("[802.11] set network %s\n", data->ifname);

	g_free(data->network);

	data->network = g_strdup(network);
}

static void iface_set_passphrase(struct connman_iface *iface,
						const char *passphrase)
{
	struct iface_data *data = connman_iface_get_data(iface);

	printf("[802.11] set passphrase %s\n", data->ifname);

	g_free(data->passphrase);

	data->passphrase = g_strdup(passphrase);
}

static void iface_carrier(struct connman_iface *iface, int carrier)
{
	printf("[802.11] carrier %s\n", carrier ? "on" : "off");

	connman_iface_indicate_carrier(iface, carrier);
}

static void parse_genie(struct station_data *station,
					unsigned char *data, int len)
{
	int offset = 0;

	while (offset <= len - 2) {
		//int i;

		switch (data[offset]) {
		case 0xdd:	/* WPA1 (and other) */
			break;
		case 0x30:	/* WPA2 (RSN) */
			break;
		default:
			break;
		}

		//for (i = 0; i < len; i++)
		//	printf(" %02x", data[i]);
		//printf("\n");

		offset += data[offset + 1] + 2;
	}
}

static void parse_scan_results(struct connman_iface *iface,
					unsigned char *data, int len)
{
	unsigned char *ptr = data;
	struct station_data *station = NULL;
	struct ether_addr *eth;
	char addr[18];
	int num = 0;

	while (len > IW_EV_LCP_PK_LEN) {
		struct iw_event *event = (void *) ptr;

		switch (event->cmd) {
		case SIOCGIWAP:
			eth = (void *) &event->u.ap_addr.sa_data;
			sprintf(addr, "%02X:%02X:%02X:%02X:%02X:%02X",
						eth->ether_addr_octet[0],
						eth->ether_addr_octet[1],
						eth->ether_addr_octet[2],
						eth->ether_addr_octet[3],
						eth->ether_addr_octet[4],
						eth->ether_addr_octet[5]);
			station = create_station(connman_iface_get_data(iface),
									addr);
			num++;
			break;
		case SIOCGIWESSID:
			if (station != NULL) {
				station->name = malloc(event->len - 7);
				if (station->name != NULL) {
					memset(station->name, 0, event->len - 7);
					memcpy(station->name, ptr + 8,
								event->len - 8);
				}
			}
			break;
		case SIOCGIWNAME:
			break;
		case SIOCGIWMODE:
			if (station != NULL)
				station->mode = event->u.mode;
			break;
		case SIOCGIWFREQ:
			break;
		case SIOCGIWENCODE:
			if (station != NULL) {
				if (!(event->u.data.flags & IW_ENCODE_DISABLED)) {
					/* privacy */
				}
			}
			break;
		case SIOCGIWRATE:
			break;
		case IWEVQUAL:
			if (station != NULL) {
				station->qual = event->u.qual.qual;
				station->noise = event->u.qual.noise;
				station->level = event->u.qual.level;
			}
			break;
		case IWEVGENIE:
			if (station != NULL)
				parse_genie(station, ptr + 8, event->len - 8);
			break;
		case IWEVCUSTOM:
			break;
		default:
			printf("[802.11] scan element 0x%04x (len %d)\n",
						event->cmd, event->len);
			break;
		}

		ptr += event->len;
		len -= event->len;
	}

	printf("[802.11] found %d networks\n", num);
}

static void iface_scan_results(struct connman_iface *iface)
{
	struct iface_data *data = connman_iface_get_data(iface);
	struct iwreq iwr;
	unsigned char *buf;
	int sk, err, size = 1024;

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0)
		return;

retrieve:
	buf = malloc(size);
	if (buf == NULL) {
		close(sk);
		return;
	}

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, data->ifname, IFNAMSIZ);
	iwr.u.data.pointer = buf;
	iwr.u.data.length = size;
	iwr.u.data.flags = 0;

	err = ioctl(sk, SIOCGIWSCAN, &iwr);
	if (err < 0) {
		if (errno == E2BIG) {
			free(buf);
			size *= 2;
			goto retrieve;
		}
	} else
		parse_scan_results(iface, iwr.u.data.pointer,
						iwr.u.data.length);

	close(sk);

	free(buf);

	print_stations(data);
}

static void iface_wireless(struct connman_iface *iface,
					void *data, unsigned short len)
{
	struct iw_event *event = data;
	struct iw_point point;
	struct ether_addr *eth;
	char addr[18];

	switch (event->cmd) {
	case SIOCSIWFREQ:
		printf("[802.11] Set Frequency (flags %d)\n",
							event->u.freq.flags);
		break;
	case SIOCSIWMODE:
		printf("[802.11] Set Mode (mode %d)\n", event->u.mode);
		break;
	case SIOCSIWESSID:
		memcpy(&point, data + IW_EV_LCP_LEN -
					IW_EV_POINT_OFF, sizeof(point));
		point.pointer = data + IW_EV_LCP_LEN +
					sizeof(point) - IW_EV_POINT_OFF;
		printf("[802.11] Set ESSID (length %d flags %d) \"%s\"\n",
					point.length, point.flags,
						(char *) point.pointer);
		break;
	case SIOCSIWENCODE:
		printf("[802.11] Set Encryption key (flags %d)\n",
							event->u.data.flags);
		break;

	case SIOCGIWAP:
		eth = (void *) &event->u.ap_addr.sa_data;
		sprintf(addr, "%02X:%02X:%02X:%02X:%02X:%02X",
						eth->ether_addr_octet[0],
						eth->ether_addr_octet[1],
						eth->ether_addr_octet[2],
						eth->ether_addr_octet[3],
						eth->ether_addr_octet[4],
						eth->ether_addr_octet[5]);
		printf("[802.11] New Access Point %s\n", addr);
		break;
	case SIOCGIWSCAN:
		iface_scan_results(iface);
		break;
	default:
		printf("[802.11] Wireless event (cmd 0x%04x len %d)\n",
						event->cmd, event->len);
		break;
	}
}

static struct connman_iface_driver iface_driver = {
	.name		= "80211",
	.capability	= "net.80211",
	.probe		= iface_probe,
	.remove		= iface_remove,
	.activate	= iface_activate,
	.shutdown	= iface_shutdown,
	.scan		= iface_scan,
	.connect	= iface_connect,
	.set_network	= iface_set_network,
	.set_passphrase	= iface_set_passphrase,
	.rtnl_carrier	= iface_carrier,
	.rtnl_wireless	= iface_wireless,
};

static int plugin_init(void)
{
	connman_iface_register(&iface_driver);

	return 0;
}

static void plugin_exit(void)
{
	connman_iface_unregister(&iface_driver);
}

CONNMAN_PLUGIN_DEFINE("80211", "IEEE 802.11 interface plugin", VERSION,
						plugin_init, plugin_exit)
