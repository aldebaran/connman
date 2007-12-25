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

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <glib.h>

#include "connman.h"

static void parse_link(struct nlmsghdr *hdr)
{
	struct ifinfomsg *msg;
	struct rtattr *attr;
	int bytes;

	msg = (struct ifinfomsg *) NLMSG_DATA(hdr);
	bytes = IFLA_PAYLOAD(hdr);

	DBG("ifi_index %d ifi_flags %d", msg->ifi_index, msg->ifi_flags);

	for (attr = IFLA_RTA(msg); RTA_OK(attr, bytes);
					attr = RTA_NEXT(attr, bytes)) {
		int len = RTA_PAYLOAD(attr);

		switch (attr->rta_type) {
		case IFLA_ADDRESS:
			DBG("  rta_type address len %d", len);
			break;
		case IFLA_BROADCAST:
			DBG("  rta_type broadcast len %d", len);
			break;
		case IFLA_IFNAME:
			DBG("  rta_type ifname %s", (char *) RTA_DATA(attr));
			break;
		case IFLA_MTU:
			DBG("  rta_type mtu len %d", len);
			break;
		case IFLA_LINK:
			DBG("  rta_type link len %d", len);
			break;
		case IFLA_QDISC:
			DBG("  rta_type qdisc len %d", len);
			break;
		case IFLA_STATS:
			DBG("  rta_type stats len %d", len);
			break;
		case IFLA_COST:
			DBG("  rta_type cost len %d", len);
			break;
		case IFLA_PRIORITY:
			DBG("  rta_type priority len %d", len);
			break;
		case IFLA_MASTER:
			DBG("  rta_type master len %d", len);
			break;
		case IFLA_WIRELESS:
			DBG("  rta_type wireless len %d", len);
			{
				unsigned char *data = RTA_DATA(attr);
				int i;
				for (i = 0; i < len; i++)
					printf(" %02x", data[i]);
				printf("\n");
			}
			break;
		case IFLA_PROTINFO:
			DBG("  rta_type protinfo len %d", len);
			break;
		case IFLA_TXQLEN:
			DBG("  rta_type txqlen len %d", len);
			break;
		case IFLA_MAP:
			DBG("  rta_type map len %d", len);
			break;
		case IFLA_WEIGHT:
			DBG("  rta_type widght len %d", len);
			break;
		case IFLA_OPERSTATE:
			DBG("  rta_type operstate len %d", len);
			break;
		case IFLA_LINKMODE:
			DBG("  rta_type linkmode len %d", len);
			break;
		default:
			DBG("  rta_type %d len %d", attr->rta_type, len);
			break;
		}
	}
}

static void parse_addr(struct nlmsghdr *hdr)
{
	struct ifaddrmsg *msg;
	struct rtattr *attr;
	int bytes;

	msg = (struct ifaddrmsg *) NLMSG_DATA(hdr);
	bytes = IFA_PAYLOAD(hdr);

	DBG("ifa_family %d ifa_index %d", msg->ifa_family, msg->ifa_index);

	for (attr = IFA_RTA(msg); RTA_OK(attr, bytes);
					attr = RTA_NEXT(attr, bytes)) {
		int len = RTA_PAYLOAD(attr);

		switch (attr->rta_type) {
		case IFA_ADDRESS:
			DBG("  rta_type address len %d", len);
			if (msg->ifa_family == AF_INET) {
				struct in_addr addr;
				addr = *((struct in_addr *) RTA_DATA(attr));
				DBG("    address %s", inet_ntoa(addr));
			}
			break;
		case IFA_LOCAL:
			DBG("  rta_type local len %d", len);
			if (msg->ifa_family == AF_INET) {
				struct in_addr addr;
				addr = *((struct in_addr *) RTA_DATA(attr));
				DBG("    address %s", inet_ntoa(addr));
			}
			break;
		case IFA_LABEL:
			DBG("  rta_type label %s", (char *) RTA_DATA(attr));
			break;
		case IFA_BROADCAST:
			DBG("  rta_type broadcast len %d", len);
			if (msg->ifa_family == AF_INET) {
				struct in_addr addr;
				addr = *((struct in_addr *) RTA_DATA(attr));
				DBG("    address %s", inet_ntoa(addr));
			}
			break;
		case IFA_ANYCAST:
			DBG("  rta_type anycast len %d", len);
			break;
		case IFA_CACHEINFO:
			DBG("  rta_type cacheinfo len %d", len);
			break;
		case IFA_MULTICAST:
			DBG("  rta_type multicast len %d", len);
			break;
		default:
			DBG("  rta_type %d len %d", attr->rta_type, len);
			break;
		}
	}
}

static void parse_route(struct nlmsghdr *hdr)
{
	struct rtmsg *msg;
	struct rtattr *attr;
	int bytes;

	msg = (struct rtmsg *) NLMSG_DATA(hdr);
	bytes = IFA_PAYLOAD(hdr);

	DBG("rtm_family %d rtm_flags %d", msg->rtm_family, msg->rtm_flags);

	for (attr = RTA_DATA(msg); RTA_OK(attr, bytes);
					attr = RTA_NEXT(attr, bytes)) {
		int len = RTA_PAYLOAD(attr);

		switch (attr->rta_type) {
		case RTA_DST:
			DBG("  rta_type dst len %d", len);
			break;
		case RTA_SRC:
			DBG("  rta_type src len %d", len);
			break;
		case RTA_IIF:
			DBG("  rta_type iff len %d", len);
			break;
		case RTA_OIF:
			DBG("  rta_type oif len %d", len);
			break;
		case RTA_GATEWAY:
			DBG("  rta_type gateway len %d", len);
			break;
		default:
			DBG("  rta_type %d len %d", attr->rta_type, len);
			break;
		}
	}
}

static void parse_message(unsigned char *buf, size_t size)
{
	struct nlmsghdr *hdr = (void *) buf;

	if (!NLMSG_OK(hdr, size))
		return;

	switch (hdr->nlmsg_type) {
	case NLMSG_DONE:
		DBG("nlmsg_type done");
		return;
	case NLMSG_NOOP:
		DBG("nlmsg_type noop");
		return;
	case NLMSG_OVERRUN:
		DBG("nlmsg_type overrun");
		return;
	case NLMSG_ERROR:
		DBG("nlmsg_type error");
		return;
	case RTM_NEWLINK:
		DBG("nlmsg_type RTM_NEWLINK");
		parse_link(hdr);
		break;
	case RTM_DELLINK:
		DBG("nlmsg_type RTM_DELLINK");
		parse_link(hdr);
		break;
	case RTM_NEWADDR:
		DBG("nlmsg_type RTM_NEWADDR");
		parse_addr(hdr);
		break;
	case RTM_DELADDR:
		DBG("nlmsg_type RTM_DELADDR");
		parse_addr(hdr);
		break;
	case RTM_NEWROUTE:
		DBG("nlmsg_type RTM_NEWROUTE");
		parse_route(hdr);
		break;
	case RTM_DELROUTE:
		DBG("nlmsg_type RTM_DELROUTE");
		parse_route(hdr);
		break;
	default:
		DBG("nlmsg_type %d", hdr->nlmsg_type);
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

	parse_message(buf, len);

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
	addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE;
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
