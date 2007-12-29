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
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <glib.h>

#include "connman.h"

static inline void print_char(struct rtattr *attr, const char *name)
{
	printf("  attr %s (len %d) %s\n", name, RTA_PAYLOAD(attr),
						(char *) RTA_DATA(attr));
}

static inline void print_attr(struct rtattr *attr, const char *name)
{
	if (name)
		printf("  attr %s (len %d)\n", name, RTA_PAYLOAD(attr));
	else
		printf("  attr %d (len %d)\n",
					attr->rta_type, RTA_PAYLOAD(attr));
}

static void rtnl_link(struct nlmsghdr *hdr)
{
	struct connman_iface *iface;
	struct ifinfomsg *msg;
	struct rtattr *attr;
	int bytes;

	msg = (struct ifinfomsg *) NLMSG_DATA(hdr);
	bytes = IFLA_PAYLOAD(hdr);

	DBG("ifi_index %d ifi_flags 0x%04x", msg->ifi_index, msg->ifi_flags);

	iface = __connman_iface_find(msg->ifi_index);
	if (iface == NULL)
		return;

	if ((iface->flags & CONNMAN_IFACE_FLAG_RTNL) == 0)
		return;

	if (iface->carrier != (msg->ifi_flags & IFF_RUNNING)) {
		iface->carrier = (msg->ifi_flags & IFF_RUNNING);
		DBG("carrier %s", iface->carrier ? "on" : "off");
	}

	for (attr = IFLA_RTA(msg); RTA_OK(attr, bytes);
					attr = RTA_NEXT(attr, bytes)) {
		switch (attr->rta_type) {
		case IFLA_ADDRESS:
			print_attr(attr, "address");
			break;
		case IFLA_BROADCAST:
			print_attr(attr, "broadcast");
			break;
		case IFLA_IFNAME:
			print_char(attr, "ifname");
			break;
		case IFLA_MTU:
			print_attr(attr, "mtu");
			break;
		case IFLA_LINK:
			print_attr(attr, "link");
			break;
		case IFLA_QDISC:
			print_attr(attr, "qdisc");
			break;
		case IFLA_STATS:
			print_attr(attr, "stats");
			break;
		case IFLA_COST:
			print_attr(attr, "cost");
			break;
		case IFLA_PRIORITY:
			print_attr(attr, "priority");
			break;
		case IFLA_MASTER:
			print_attr(attr, "master");
			break;
		case IFLA_WIRELESS:
			if (iface->driver->rtnl_wireless)
				iface->driver->rtnl_wireless(iface,
					RTA_DATA(attr), RTA_PAYLOAD(attr));
			break;
		case IFLA_PROTINFO:
			print_attr(attr, "protinfo");
			break;
		case IFLA_TXQLEN:
			print_attr(attr, "txqlen");
			break;
		case IFLA_MAP:
			print_attr(attr, "map");
			break;
		case IFLA_WEIGHT:
			print_attr(attr, "weight");
			break;
		case IFLA_OPERSTATE:
			print_attr(attr, "operstate");
			break;
		case IFLA_LINKMODE:
			print_attr(attr, "linkmode");
			break;
		default:
			print_attr(attr, NULL);
			break;
		}
	}
}

static void rtnl_addr(struct nlmsghdr *hdr)
{
	struct connman_iface *iface;
	struct ifaddrmsg *msg;
	struct rtattr *attr;
	int bytes;

	msg = (struct ifaddrmsg *) NLMSG_DATA(hdr);
	bytes = IFA_PAYLOAD(hdr);

	DBG("ifa_family %d ifa_index %d", msg->ifa_family, msg->ifa_index);

	iface = __connman_iface_find(msg->ifa_index);
	if (iface == NULL)
		return;

	if ((iface->flags & CONNMAN_IFACE_FLAG_RTNL) == 0)
		return;

	for (attr = IFA_RTA(msg); RTA_OK(attr, bytes);
					attr = RTA_NEXT(attr, bytes)) {
		switch (attr->rta_type) {
		case IFA_ADDRESS:
			print_attr(attr, "address");
			if (msg->ifa_family == AF_INET) {
				struct in_addr addr;
				addr = *((struct in_addr *) RTA_DATA(attr));
				DBG("    address %s", inet_ntoa(addr));
			}
			break;
		case IFA_LOCAL:
			print_attr(attr, "local");
			if (msg->ifa_family == AF_INET) {
				struct in_addr addr;
				addr = *((struct in_addr *) RTA_DATA(attr));
				DBG("    address %s", inet_ntoa(addr));
			}
			break;
		case IFA_LABEL:
			print_char(attr, "label");
			break;
		case IFA_BROADCAST:
			print_attr(attr, "broadcast");
			if (msg->ifa_family == AF_INET) {
				struct in_addr addr;
				addr = *((struct in_addr *) RTA_DATA(attr));
				DBG("    address %s", inet_ntoa(addr));
			}
			break;
		case IFA_ANYCAST:
			print_attr(attr, "anycast");
			break;
		case IFA_CACHEINFO:
			print_attr(attr, "cacheinfo");
			break;
		case IFA_MULTICAST:
			print_attr(attr, "multicast");
			break;
		default:
			print_attr(attr, NULL);
			break;
		}
	}
}

static void rtnl_route(struct nlmsghdr *hdr)
{
	struct rtmsg *msg;
	struct rtattr *attr;
	int bytes;

	msg = (struct rtmsg *) NLMSG_DATA(hdr);
	bytes = RTM_PAYLOAD(hdr);

	DBG("rtm_family %d rtm_flags 0x%04x", msg->rtm_family, msg->rtm_flags);

	for (attr = RTM_RTA(msg); RTA_OK(attr, bytes);
					attr = RTA_NEXT(attr, bytes)) {
		switch (attr->rta_type) {
		case RTA_DST:
			print_attr(attr, "dst");
			if (msg->rtm_family == AF_INET) {
				struct in_addr addr;
				addr = *((struct in_addr *) RTA_DATA(attr));
				DBG("    address %s", inet_ntoa(addr));
			}
			break;
		case RTA_SRC:
			print_attr(attr, "src");
			if (msg->rtm_family == AF_INET) {
				struct in_addr addr;
				addr = *((struct in_addr *) RTA_DATA(attr));
				DBG("    address %s", inet_ntoa(addr));
			}
			break;
		case RTA_IIF:
			print_char(attr, "iif");
			break;
		case RTA_OIF:
			print_attr(attr, "oif");
			break;
		case RTA_GATEWAY:
			print_attr(attr, "gateway");
			if (msg->rtm_family == AF_INET) {
				struct in_addr addr;
				addr = *((struct in_addr *) RTA_DATA(attr));
				DBG("    address %s", inet_ntoa(addr));
			}
			break;
		case RTA_PRIORITY:
			print_attr(attr, "priority");
			break;
		case RTA_PREFSRC:
			print_attr(attr, "prefsrc");
			if (msg->rtm_family == AF_INET) {
				struct in_addr addr;
				addr = *((struct in_addr *) RTA_DATA(attr));
				DBG("    address %s", inet_ntoa(addr));
			}
			break;
		case RTA_METRICS:
			print_attr(attr, "metrics");
			break;
		case RTA_TABLE:
			print_attr(attr, "table");
			break;
		default:
			print_attr(attr, NULL);
			break;
		}
	}
}

static void rtnl_message(unsigned char *buf, size_t size)
{
	struct nlmsghdr *hdr = (void *) buf;

	if (!NLMSG_OK(hdr, size))
		return;

	switch (hdr->nlmsg_type) {
	case NLMSG_DONE:
		DBG("done");
		return;
	case NLMSG_NOOP:
		DBG("noop");
		return;
	case NLMSG_OVERRUN:
		DBG("overrun");
		return;
	case NLMSG_ERROR:
		DBG("error");
		return;
	case RTM_NEWLINK:
		rtnl_link(hdr);
		break;
	case RTM_DELLINK:
		rtnl_link(hdr);
		break;
	case RTM_NEWADDR:
		rtnl_addr(hdr);
		break;
	case RTM_DELADDR:
		rtnl_addr(hdr);
		break;
	case RTM_NEWROUTE:
		rtnl_route(hdr);
		break;
	case RTM_DELROUTE:
		rtnl_route(hdr);
		break;
	default:
		DBG("type %d", hdr->nlmsg_type);
		break;
	}
}

static gboolean netlink_event(GIOChannel *chan,
				GIOCondition cond, gpointer data)
{
	unsigned char buf[256];
	gsize len;
	GIOError err;

	if (cond & (G_IO_NVAL | G_IO_HUP | G_IO_ERR)) {
		g_io_channel_unref(chan);
		return FALSE;
	}

	memset(buf, 0, sizeof(buf));

	err = g_io_channel_read(chan, (gchar *) buf, sizeof(buf), &len);
	if (err) {
		if (err == G_IO_ERROR_AGAIN)
			return TRUE;
		g_io_channel_unref(chan);
		return FALSE;
	}

	rtnl_message(buf, len);

	return TRUE;
}

static GIOChannel *channel = NULL;

int __connman_rtnl_init(void)
{
	struct sockaddr_nl addr;
	int sk;

	DBG("");

	sk = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (sk < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = RTMGRP_LINK;
	//addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE;
	addr.nl_pid = getpid();

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(sk);
		return -1;
	}

	channel = g_io_channel_unix_new(sk);
	g_io_channel_set_close_on_unref(channel, TRUE);

	g_io_add_watch(channel,
			G_IO_IN | G_IO_NVAL | G_IO_HUP | G_IO_ERR,
						netlink_event, NULL);

	g_io_channel_unref(channel);

	return 0;
}

void __connman_rtnl_cleanup(void)
{
	DBG("");

	g_io_channel_unref(channel);

	channel = NULL;
}
