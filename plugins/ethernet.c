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
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <connman/plugin.h>
#include <connman/driver.h>
#include <connman/log.h>

static GStaticMutex ethernet_mutex = G_STATIC_MUTEX_INIT;
static GSList *ethernet_list = NULL;

static void create_element(struct connman_element *parent,
					enum connman_element_type type)
{
	struct connman_element *element;

	DBG("parent %p name %s", parent, parent->name);

	element = connman_element_create();

	element->type = type;
	element->netdev.index = parent->netdev.index;
	element->netdev.name = g_strdup(parent->netdev.name);

	connman_element_register(element, parent);
}

static void rtnl_link(struct nlmsghdr *hdr, const char *type)
{
	GSList *list;
	struct ifinfomsg *msg;
	int bytes;

	msg = (struct ifinfomsg *) NLMSG_DATA(hdr);
	bytes = IFLA_PAYLOAD(hdr);

	DBG("%s ifi_index %d ifi_flags 0x%04x",
				type, msg->ifi_index, msg->ifi_flags);

	g_static_mutex_lock(&ethernet_mutex);

	for (list = ethernet_list; list; list = list->next) {
		struct connman_element *element = list->data;

		if (element->type != CONNMAN_ELEMENT_TYPE_DEVICE)
			continue;

		if (element->netdev.index != msg->ifi_index)
			continue;

		if ((element->netdev.flags & IFF_RUNNING) ==
						(msg->ifi_flags & IFF_RUNNING))
			continue;

		element->netdev.flags = msg->ifi_flags;

		if (msg->ifi_flags & IFF_RUNNING) {
			DBG("carrier on");

			create_element(element, CONNMAN_ELEMENT_TYPE_DHCP);
			create_element(element, CONNMAN_ELEMENT_TYPE_ZEROCONF);
		} else {
			DBG("carrier off");

			connman_element_unregister_children(element);
		}
	}

	g_static_mutex_unlock(&ethernet_mutex);
}

static gboolean rtnl_event(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	unsigned char buf[1024];
	void *ptr = buf;
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

	DBG("buf %p len %zd", buf, len);

	while (len > 0) {
		struct nlmsghdr *hdr = ptr;
		struct nlmsgerr *err;

		if (!NLMSG_OK(hdr, len))
			break;

		DBG("len %d type %d flags 0x%04x seq %d",
					hdr->nlmsg_len, hdr->nlmsg_type,
					hdr->nlmsg_flags, hdr->nlmsg_seq);

		switch (hdr->nlmsg_type) {
		case NLMSG_ERROR:
			err = NLMSG_DATA(hdr);
			DBG("ERROR %d (%s)", -err->error,
						strerror(-err->error));
			break;

		case RTM_NEWLINK:
			rtnl_link(hdr, "NEWLINK");
			break;

		case RTM_DELLINK:
			rtnl_link(hdr, "DELLINK");
			break;
		}

		len -= hdr->nlmsg_len;
		ptr += hdr->nlmsg_len;
	}

	return TRUE;
}

static GIOChannel *channel = NULL;

static int rtnl_request(void)
{
	struct {
		struct nlmsghdr hdr;
		struct rtgenmsg msg;
	} req;

	struct sockaddr_nl addr;
	int sk;

	DBG("");

	memset(&req, 0, sizeof(req));
	req.hdr.nlmsg_len = sizeof(req.hdr) + sizeof(req.msg);
	req.hdr.nlmsg_type = RTM_GETLINK;
	req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.hdr.nlmsg_pid = 0;
	req.hdr.nlmsg_seq = 42;
	req.msg.rtgen_family = AF_INET;

	sk = g_io_channel_unix_get_fd(channel);

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;

	return sendto(sk, &req, sizeof(req), 0,
			(struct sockaddr *) &addr, sizeof(addr));
}

static int iface_up(struct connman_element *element)
{
	struct ifreq ifr;
	int sk, err;

	DBG("element %p", element);

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0)
		return -errno;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = element->netdev.index;

	if (ioctl(sk, SIOCGIFNAME, &ifr) < 0) {
		err = -errno;
		goto done;
	}

	if (ioctl(sk, SIOCGIFFLAGS, &ifr) < 0) {
		err = -errno;
		goto done;
	}

	if (ifr.ifr_flags & IFF_UP) {
		err = -EALREADY;
		goto done;
	}

	ifr.ifr_flags |= IFF_UP;

	if (ioctl(sk, SIOCSIFFLAGS, &ifr) < 0) {
		err = -errno;
		goto done;
	}

	err = 0;

done:
	close(sk);

	return err;
}

static int iface_down(struct connman_element *element)
{
	struct ifreq ifr;
	int sk, err;

	DBG("element %p", element);

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0)
		return -errno;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = element->netdev.index;

	if (ioctl(sk, SIOCGIFNAME, &ifr) < 0) {
		err = -errno;
		goto done;
	}

	if (ioctl(sk, SIOCGIFFLAGS, &ifr) < 0) {
		err = -errno;
		goto done;
	}

	if (!(ifr.ifr_flags & IFF_UP)) {
		err = -EALREADY;
		goto done;
	}

	ifr.ifr_flags &= ~IFF_UP;

	if (ioctl(sk, SIOCSIFFLAGS, &ifr) < 0)
		err = -errno;
	else
		err = 0;

done:
	close(sk);

	return err;
}

static int ethernet_probe(struct connman_element *element)
{
	DBG("element %p name %s", element, element->name);

	g_static_mutex_lock(&ethernet_mutex);
	ethernet_list = g_slist_append(ethernet_list, element);
	g_static_mutex_unlock(&ethernet_mutex);

	iface_up(element);

	rtnl_request();

	return 0;
}

static void ethernet_remove(struct connman_element *element)
{
	DBG("element %p name %s", element, element->name);

	iface_down(element);

	g_static_mutex_lock(&ethernet_mutex);
	ethernet_list = g_slist_remove(ethernet_list, element);
	g_static_mutex_unlock(&ethernet_mutex);
}

static struct connman_driver ethernet_driver = {
	.name		= "ethernet",
	.type		= CONNMAN_ELEMENT_TYPE_DEVICE,
	.subtype	= CONNMAN_ELEMENT_SUBTYPE_ETHERNET,
	.probe		= ethernet_probe,
	.remove		= ethernet_remove,
};

static int rtnl_init(void)
{
	struct sockaddr_nl addr;
	int sk, err;

	DBG("");

	sk = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (sk < 0)
		return -errno;

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = RTMGRP_LINK;

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		err = -errno;
		close(sk);
		return err;
	}

	channel = g_io_channel_unix_new(sk);
	g_io_channel_set_close_on_unref(channel, TRUE);

	g_io_add_watch(channel, G_IO_IN | G_IO_NVAL | G_IO_HUP | G_IO_ERR,
							rtnl_event, NULL);

	return 0;
}

static void rtnl_cleanup(void)
{
	DBG("");

	g_io_channel_shutdown(channel, TRUE, NULL);
	g_io_channel_unref(channel);

	channel = NULL;
}

static int ethernet_init(void)
{
	int err;

	err = rtnl_init();
	if (err < 0)
		return err;

	err = connman_driver_register(&ethernet_driver);
	if (err < 0) {
		rtnl_cleanup();
		return err;
	}

	return 0;
}

static void ethernet_exit(void)
{
	connman_driver_unregister(&ethernet_driver);

	rtnl_cleanup();
}

CONNMAN_PLUGIN_DEFINE("ethernet", "Ethernet interface plugin", VERSION,
						ethernet_init, ethernet_exit)
