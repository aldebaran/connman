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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <glib.h>

#include "connman.h"

static GStaticRWLock rtnl_lock = G_STATIC_RW_LOCK_INIT;
static GSList *rtnl_list = NULL;

static gint compare_priority(gconstpointer a, gconstpointer b)
{
	const struct connman_rtnl *rtnl1 = a;
	const struct connman_rtnl *rtnl2 = b;

	return rtnl2->priority - rtnl1->priority;
}

/**
 * connman_rtnl_register:
 * @rtnl: RTNL module
 *
 * Register a new RTNL module
 *
 * Returns: %0 on success
 */
int connman_rtnl_register(struct connman_rtnl *rtnl)
{
	DBG("rtnl %p name %s", rtnl, rtnl->name);

	g_static_rw_lock_writer_lock(&rtnl_lock);

	rtnl_list = g_slist_insert_sorted(rtnl_list, rtnl,
							compare_priority);

	g_static_rw_lock_writer_unlock(&rtnl_lock);

	return 0;
}

/**
 * connman_rtnl_unregister:
 * @rtnl: RTNL module
 *
 * Remove a previously registered RTNL module
 */
void connman_rtnl_unregister(struct connman_rtnl *rtnl)
{
	DBG("rtnl %p name %s", rtnl, rtnl->name);

	g_static_rw_lock_writer_lock(&rtnl_lock);

	rtnl_list = g_slist_remove(rtnl_list, rtnl);

	g_static_rw_lock_writer_unlock(&rtnl_lock);
}

static void process_newlink(unsigned short type, int index,
					unsigned flags, unsigned change)
{
	GSList *list;

	DBG("index %d", index);

	g_static_rw_lock_reader_lock(&rtnl_lock);

	for (list = rtnl_list; list; list = list->next) {
		struct connman_rtnl *rtnl = list->data;

		if (rtnl->newlink)
			rtnl->newlink(type, index, flags, change);
	}

	g_static_rw_lock_reader_unlock(&rtnl_lock);
}

static void process_dellink(unsigned short type, int index,
					unsigned flags, unsigned change)
{
	GSList *list;

	DBG("index %d", index);

	g_static_rw_lock_reader_lock(&rtnl_lock);

	for (list = rtnl_list; list; list = list->next) {
		struct connman_rtnl *rtnl = list->data;

		if (rtnl->dellink)
			rtnl->dellink(type, index, flags, change);
	}

	g_static_rw_lock_reader_unlock(&rtnl_lock);
}

static inline void print_inet(struct rtattr *attr, const char *name, int family)
{
	if (family == AF_INET) {
		struct in_addr addr;
		addr = *((struct in_addr *) RTA_DATA(attr));
		DBG("  attr %s (len %jd) %s\n",
				name, RTA_PAYLOAD(attr), inet_ntoa(addr));
	} else
		DBG("  attr %s (len %jd)\n", name, RTA_PAYLOAD(attr));
}

static inline void print_char(struct rtattr *attr, const char *name)
{
	DBG("  attr %s (len %jd) %s\n", name, RTA_PAYLOAD(attr),
						(char *) RTA_DATA(attr));
}

static inline void print_byte(struct rtattr *attr, const char *name)
{
	DBG("  attr %s (len %jd) 0x%02x\n", name, RTA_PAYLOAD(attr),
					*((unsigned char *) RTA_DATA(attr)));
}

static inline void print_attr(struct rtattr *attr, const char *name)
{
	if (name)
		DBG("  attr %s (len %jd)\n", name, RTA_PAYLOAD(attr));
	else
		DBG("  attr %d (len %jd)\n",
					attr->rta_type, RTA_PAYLOAD(attr));
}

static void rtnl_link(struct nlmsghdr *hdr)
{
#if 0
	struct ifinfomsg *msg;
	struct rtattr *attr;
	int bytes;

	msg = (struct ifinfomsg *) NLMSG_DATA(hdr);
	bytes = IFLA_PAYLOAD(hdr);

	DBG("ifi_index %d ifi_flags 0x%04x", msg->ifi_index, msg->ifi_flags);

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
			print_attr(attr, "wireless");
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
			print_byte(attr, "operstate");
			break;
		case IFLA_LINKMODE:
			print_byte(attr, "linkmode");
			break;
		default:
			print_attr(attr, NULL);
			break;
		}
	}
#endif
}

static void rtnl_newlink(struct nlmsghdr *hdr)
{
	struct ifinfomsg *msg;

	msg = (struct ifinfomsg *) NLMSG_DATA(hdr);

	DBG("ifi_index %d ifi_flags 0x%04x", msg->ifi_index, msg->ifi_flags);

	process_newlink(msg->ifi_type, msg->ifi_index,
					msg->ifi_flags, msg->ifi_change);

	rtnl_link(hdr);
}

static void rtnl_dellink(struct nlmsghdr *hdr)
{
	struct ifinfomsg *msg;

	msg = (struct ifinfomsg *) NLMSG_DATA(hdr);

	DBG("ifi_index %d ifi_flags 0x%04x", msg->ifi_index, msg->ifi_flags);

	process_dellink(msg->ifi_type, msg->ifi_index,
					msg->ifi_flags, msg->ifi_change);

	rtnl_link(hdr);
}

static void rtnl_addr(struct nlmsghdr *hdr)
{
	struct ifaddrmsg *msg;
	struct rtattr *attr;
	int bytes;

	msg = (struct ifaddrmsg *) NLMSG_DATA(hdr);
	bytes = IFA_PAYLOAD(hdr);

	DBG("ifa_family %d ifa_index %d", msg->ifa_family, msg->ifa_index);

	for (attr = IFA_RTA(msg); RTA_OK(attr, bytes);
					attr = RTA_NEXT(attr, bytes)) {
		switch (attr->rta_type) {
		case IFA_ADDRESS:
			print_inet(attr, "address", msg->ifa_family);
			break;
		case IFA_LOCAL:
			print_inet(attr, "local", msg->ifa_family);
			break;
		case IFA_LABEL:
			print_char(attr, "label");
			break;
		case IFA_BROADCAST:
			print_inet(attr, "broadcast", msg->ifa_family);
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
			print_inet(attr, "dst", msg->rtm_family);
			break;
		case RTA_SRC:
			print_inet(attr, "src", msg->rtm_family);
			break;
		case RTA_IIF:
			print_char(attr, "iif");
			break;
		case RTA_OIF:
			print_attr(attr, "oif");
			break;
		case RTA_GATEWAY:
			print_inet(attr, "gateway", msg->rtm_family);
			break;
		case RTA_PRIORITY:
			print_attr(attr, "priority");
			break;
		case RTA_PREFSRC:
			print_inet(attr, "prefsrc", msg->rtm_family);
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

static void rtnl_message(void *buf, size_t len)
{
	DBG("buf %p len %zd", buf, len);

	while (len > 0) {
		struct nlmsghdr *hdr = buf;
		struct nlmsgerr *err;

		if (!NLMSG_OK(hdr, len))
			break;

		DBG("len %d type %d flags 0x%04x seq %d",
					hdr->nlmsg_len, hdr->nlmsg_type,
					hdr->nlmsg_flags, hdr->nlmsg_seq);

		switch (hdr->nlmsg_type) {
		case NLMSG_NOOP:
			DBG("NOOP");
			return;
		case NLMSG_ERROR:
			err = NLMSG_DATA(hdr);
			DBG("ERROR %d (%s)", -err->error,
						strerror(-err->error));
			return;
		case NLMSG_DONE:
			DBG("DONE");
			return;
		case NLMSG_OVERRUN:
			DBG("OVERRUN");
			return;
		case RTM_NEWLINK:
			DBG("NEWLINK");
			rtnl_newlink(hdr);
			break;
		case RTM_DELLINK:
			DBG("DELLINK");
			rtnl_dellink(hdr);
			break;
		case RTM_NEWADDR:
			DBG("NEWADDR");
			rtnl_addr(hdr);
			break;
		case RTM_DELADDR:
			DBG("DELADDR");
			rtnl_addr(hdr);
			break;
		case RTM_NEWROUTE:
			DBG("NEWROUTE");
			rtnl_route(hdr);
			break;
		case RTM_DELROUTE:
			DBG("DELROUTE");
			rtnl_route(hdr);
			break;
		default:
			DBG("type %d", hdr->nlmsg_type);
			break;
		}

		len -= hdr->nlmsg_len;
		buf += hdr->nlmsg_len;
	}
}

static gboolean netlink_event(GIOChannel *chan,
				GIOCondition cond, gpointer data)
{
	unsigned char buf[4096];
	gsize len;
	GIOError err;

	if (cond & (G_IO_NVAL | G_IO_HUP | G_IO_ERR))
		return FALSE;

	memset(buf, 0, sizeof(buf));

	err = g_io_channel_read(chan, (gchar *) buf, sizeof(buf), &len);
	if (err) {
		if (err == G_IO_ERROR_AGAIN)
			return TRUE;
		return FALSE;
	}

	rtnl_message(buf, len);

	return TRUE;
}

static GIOChannel *channel = NULL;

int __connman_rtnl_send(const void *buf, size_t len)
{
	struct sockaddr_nl addr;
	int sk;

	DBG("buf %p len %zd", buf, len);

	sk = g_io_channel_unix_get_fd(channel);

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;

	return sendto(sk, buf, len, 0,
			(struct sockaddr *) &addr, sizeof(addr));
}

int connman_rtnl_send_getlink(void)
{
	struct {
		struct nlmsghdr hdr;
		struct rtgenmsg msg;
	} req;

	DBG("");

	memset(&req, 0, sizeof(req));
	req.hdr.nlmsg_len = sizeof(req.hdr) + sizeof(req.msg);
	req.hdr.nlmsg_type = RTM_GETLINK;
	req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.hdr.nlmsg_pid = 0;
	req.hdr.nlmsg_seq = 42;
	req.msg.rtgen_family = AF_INET;

	return __connman_rtnl_send(&req, sizeof(req));
}

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
	//addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR;
	//addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE;

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(sk);
		return -1;
	}

	channel = g_io_channel_unix_new(sk);
	g_io_channel_set_close_on_unref(channel, TRUE);

	g_io_add_watch(channel, G_IO_IN | G_IO_NVAL | G_IO_HUP | G_IO_ERR,
							netlink_event, NULL);

	return 0;
}

void __connman_rtnl_cleanup(void)
{
	DBG("");

	g_io_channel_shutdown(channel, TRUE, NULL);
	g_io_channel_unref(channel);

	channel = NULL;
}
