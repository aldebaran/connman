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

#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <glib.h>

#include "connman.h"

#define print(arg...) do { } while (0)
//#define print(arg...) connman_info(arg)

struct watch_data {
	unsigned int id;
	int index;
	connman_rtnl_link_cb_t newlink;
	void *user_data;
};

static GSList *watch_list = NULL;
static unsigned int watch_id = 0;

static GHashTable *ipconfig_hash = NULL;
static GSList *ipconfig_list = NULL;

static void register_ipconfig(struct connman_ipconfig *ipconfig)
{
	ipconfig_list = g_slist_append(ipconfig_list, ipconfig);
}

static void unregister_ipconfig(struct connman_ipconfig *ipconfig)
{
	ipconfig_list = g_slist_remove(ipconfig_list, ipconfig);
}

static void free_ipconfig(gpointer data)
{
	struct connman_ipconfig *ipconfig = data;

	unregister_ipconfig(ipconfig);

	connman_ipconfig_unref(ipconfig);
}

/**
 * connman_rtnl_add_newlink_watch:
 * @index: network device index
 * @callback: callback function
 * @user_data: callback data;
 *
 * Add a new RTNL watch for newlink events
 *
 * Returns: %0 on failure and a unique id on success
 */
unsigned int connman_rtnl_add_newlink_watch(int index,
			connman_rtnl_link_cb_t callback, void *user_data)
{
	struct connman_ipconfig *ipconfig;
	struct watch_data *watch;

	watch = g_try_new0(struct watch_data, 1);
	if (watch == NULL)
		return 0;

	watch->id = ++watch_id;
	watch->index = index;

	watch->newlink = callback;
	watch->user_data = user_data;

	watch_list = g_slist_prepend(watch_list, watch);

	DBG("id %d", watch->id);

	ipconfig = g_hash_table_lookup(ipconfig_hash, GINT_TO_POINTER(index));
	if (ipconfig != NULL) {
		unsigned int flags = __connman_ipconfig_get_flags(ipconfig);

		if (callback)
			callback(flags, 0, user_data);
	}

	return watch->id;
}

/**
 * connman_rtnl_remove_watch:
 * @id: watch identifier
 *
 * Remove the RTNL watch for the identifier
 */
void connman_rtnl_remove_watch(unsigned int id)
{
	GSList *list;

	DBG("id %d", id);

	if (id == 0)
		return;

	for (list = watch_list; list; list = list->next) {
		struct watch_data *watch = list->data;

		if (watch->id  == id) {
			watch_list = g_slist_remove(watch_list, watch);
			g_free(watch);
			break;
		}
	}
}

static void trigger_newlink(gpointer key, gpointer value, gpointer user_data)
{
	struct connman_rtnl *rtnl = user_data;
	struct connman_ipconfig *ipconfig = value;
	int index = GPOINTER_TO_INT(key);

	if (index < 0 || ipconfig == NULL)
		return;

	if (rtnl->newlink) {
		unsigned short type = __connman_ipconfig_get_type(ipconfig);
		unsigned int flags = __connman_ipconfig_get_flags(ipconfig);

		rtnl->newlink(type, index, flags, 0);
	}
}

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

	rtnl_list = g_slist_insert_sorted(rtnl_list, rtnl,
							compare_priority);

	g_hash_table_foreach(ipconfig_hash, trigger_newlink, rtnl);

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

	rtnl_list = g_slist_remove(rtnl_list, rtnl);
}

static void process_newlink(unsigned short type, int index,
					unsigned flags, unsigned change)
{
	struct connman_ipconfig *ipconfig;
	GSList *list;

	switch (type) {
	case ARPHRD_ETHER:
	case ARPHRD_LOOPBACK:
	case ARPHRD_NONE:
		ipconfig = g_hash_table_lookup(ipconfig_hash,
						GINT_TO_POINTER(index));
		if (ipconfig == NULL) {
			ipconfig = connman_ipconfig_create(index);
			if (ipconfig != NULL) {
				g_hash_table_insert(ipconfig_hash,
					GINT_TO_POINTER(index), ipconfig);

				register_ipconfig(ipconfig);
			}
		}

		if (ipconfig != NULL)
			__connman_ipconfig_update_link(ipconfig,
							flags, change);
		break;
	}

	for (list = rtnl_list; list; list = list->next) {
		struct connman_rtnl *rtnl = list->data;

		if (rtnl->newlink)
			rtnl->newlink(type, index, flags, change);
	}

	for (list = watch_list; list; list = list->next) {
		struct watch_data *watch = list->data;

		if (watch->index != index)
			continue;

		if (watch->newlink)
			watch->newlink(flags, change, watch->user_data);
	}
}

static void process_dellink(unsigned short type, int index,
					unsigned flags, unsigned change)
{
	GSList *list;

	for (list = rtnl_list; list; list = list->next) {
		struct connman_rtnl *rtnl = list->data;

		if (rtnl->dellink)
			rtnl->dellink(type, index, flags, change);
	}

	switch (type) {
	case ARPHRD_ETHER:
	case ARPHRD_LOOPBACK:
	case ARPHRD_NONE:
		g_hash_table_remove(ipconfig_hash, GINT_TO_POINTER(index));
		break;
	}
}

static void extract_addr(struct ifaddrmsg *msg, int bytes,
						const char **label,
						struct in_addr *local,
						struct in_addr *address,
						struct in_addr *broadcast)
{
	struct rtattr *attr;

	for (attr = IFA_RTA(msg); RTA_OK(attr, bytes);
					attr = RTA_NEXT(attr, bytes)) {
		switch (attr->rta_type) {
		case IFA_ADDRESS:
			if (address != NULL)
				*address = *((struct in_addr *) RTA_DATA(attr));
			break;
		case IFA_LOCAL:
			if (local != NULL)
				*local = *((struct in_addr *) RTA_DATA(attr));
			break;
		case IFA_BROADCAST:
			if (broadcast != NULL)
				*broadcast = *((struct in_addr *) RTA_DATA(attr));
			break;
		case IFA_LABEL:
			if (label != NULL)
				*label = RTA_DATA(attr);
			break;
		}
	}
}

static void process_newaddr(unsigned char family, unsigned char prefixlen,
				int index, struct ifaddrmsg *msg, int bytes)
{
	GSList *list;
	const char *label;
	struct in_addr address = { INADDR_ANY };

	if (family != AF_INET)
		return;

	extract_addr(msg, bytes, &label, &address, NULL, NULL);

	for (list = ipconfig_list; list; list = list->next) {
		struct connman_ipconfig *ipconfig = list->data;

		if (__connman_ipconfig_get_index(ipconfig) != index)
			continue;

		__connman_ipconfig_add_address(ipconfig, label, prefixlen,
						inet_ntoa(address), NULL);
	}
}

static void process_deladdr(unsigned char family, unsigned char prefixlen,
				int index, struct ifaddrmsg *msg, int bytes)
{
	GSList *list;
	const char *label;
	struct in_addr address = { INADDR_ANY };

	if (family != AF_INET)
		return;

	extract_addr(msg, bytes, &label, &address, NULL, NULL);

	for (list = ipconfig_list; list; list = list->next) {
		struct connman_ipconfig *ipconfig = list->data;

		if (__connman_ipconfig_get_index(ipconfig) != index)
			continue;

		__connman_ipconfig_del_address(ipconfig, label, prefixlen,
						inet_ntoa(address), NULL);
	}
}

static void extract_route(struct rtmsg *msg, int bytes, int *index,
						struct in_addr *dst,
						struct in_addr *gateway)
{
	struct rtattr *attr;

	for (attr = RTM_RTA(msg); RTA_OK(attr, bytes);
					attr = RTA_NEXT(attr, bytes)) {
		switch (attr->rta_type) {
		case RTA_DST:
			if (dst != NULL)
				*dst = *((struct in_addr *) RTA_DATA(attr));
			break;
		case RTA_GATEWAY:
			if (gateway != NULL)
				*gateway = *((struct in_addr *) RTA_DATA(attr));
			break;
		case RTA_OIF:
			if (index != NULL)
				*index = *((int *) RTA_DATA(attr));
			break;
		}
	}
}

static void process_newroute(unsigned char family, unsigned char scope,
						struct rtmsg *msg, int bytes)
{
	GSList *list;
	struct in_addr dst = { INADDR_ANY }, gateway = { INADDR_ANY };
	char dststr[16], gatewaystr[16];
	int index = -1;

	if (family != AF_INET)
		return;

	extract_route(msg, bytes, &index, &dst, &gateway);

	inet_ntop(family, &dst, dststr, sizeof(dststr));
	inet_ntop(family, &gateway, gatewaystr, sizeof(gatewaystr));

	for (list = ipconfig_list; list; list = list->next) {
		struct connman_ipconfig *ipconfig = list->data;

		if (__connman_ipconfig_get_index(ipconfig) != index)
			continue;

		__connman_ipconfig_add_route(ipconfig, scope,
							dststr, gatewaystr);
	}

	if (scope != RT_SCOPE_UNIVERSE || dst.s_addr != INADDR_ANY)
		return;

	for (list = rtnl_list; list; list = list->next) {
		struct connman_rtnl *rtnl = list->data;

		if (rtnl->newgateway)
			rtnl->newgateway(index, gatewaystr);
	}
}

static void process_delroute(unsigned char family, unsigned char scope,
						struct rtmsg *msg, int bytes)
{
	GSList *list;
	struct in_addr dst = { INADDR_ANY }, gateway = { INADDR_ANY };
	char dststr[16], gatewaystr[16];
	int index = -1;

	if (family != AF_INET)
		return;

	extract_route(msg, bytes, &index, &dst, &gateway);

	inet_ntop(family, &dst, dststr, sizeof(dststr));
	inet_ntop(family, &gateway, gatewaystr, sizeof(gatewaystr));

	for (list = ipconfig_list; list; list = list->next) {
		struct connman_ipconfig *ipconfig = list->data;

		if (__connman_ipconfig_get_index(ipconfig) != index)
			continue;

		__connman_ipconfig_del_route(ipconfig, scope,
							dststr, gatewaystr);
	}

	if (scope != RT_SCOPE_UNIVERSE || dst.s_addr != INADDR_ANY)
		return;

	for (list = rtnl_list; list; list = list->next) {
		struct connman_rtnl *rtnl = list->data;

		if (rtnl->delgateway)
			rtnl->delgateway(index, gatewaystr);
	}
}

static inline void print_inet(struct rtattr *attr, const char *name,
							unsigned char family)
{
	if (family == AF_INET) {
		struct in_addr addr;
		addr = *((struct in_addr *) RTA_DATA(attr));
		print("  attr %s (len %d) %s\n", name,
				(int) RTA_PAYLOAD(attr), inet_ntoa(addr));
	} else
		print("  attr %s (len %d)\n", name, (int) RTA_PAYLOAD(attr));
}

static inline void print_string(struct rtattr *attr, const char *name)
{
	print("  attr %s (len %d) %s\n", name, (int) RTA_PAYLOAD(attr),
						(char *) RTA_DATA(attr));
}

static inline void print_byte(struct rtattr *attr, const char *name)
{
	print("  attr %s (len %d) 0x%02x\n", name, (int) RTA_PAYLOAD(attr),
					*((unsigned char *) RTA_DATA(attr)));
}

static inline void print_integer(struct rtattr *attr, const char *name)
{
	print("  attr %s (len %d) %d\n", name, (int) RTA_PAYLOAD(attr),
						*((int *) RTA_DATA(attr)));
}

static inline void print_attr(struct rtattr *attr, const char *name)
{
	if (name)
		print("  attr %s (len %d)\n", name, (int) RTA_PAYLOAD(attr));
	else
		print("  attr %d (len %d)\n",
				attr->rta_type, (int) RTA_PAYLOAD(attr));
}

static void rtnl_link(struct nlmsghdr *hdr)
{
	struct ifinfomsg *msg;
	struct rtattr *attr;
	int bytes;

	msg = (struct ifinfomsg *) NLMSG_DATA(hdr);
	bytes = IFLA_PAYLOAD(hdr);

	print("ifi_index %d ifi_flags 0x%04x", msg->ifi_index, msg->ifi_flags);

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
			print_string(attr, "ifname");
			break;
		case IFLA_MTU:
			print_integer(attr, "mtu");
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
}

static void rtnl_newlink(struct nlmsghdr *hdr)
{
	struct ifinfomsg *msg = (struct ifinfomsg *) NLMSG_DATA(hdr);

	rtnl_link(hdr);

	process_newlink(msg->ifi_type, msg->ifi_index,
					msg->ifi_flags, msg->ifi_change);
}

static void rtnl_dellink(struct nlmsghdr *hdr)
{
	struct ifinfomsg *msg = (struct ifinfomsg *) NLMSG_DATA(hdr);

	rtnl_link(hdr);

	process_dellink(msg->ifi_type, msg->ifi_index,
					msg->ifi_flags, msg->ifi_change);
}

static void rtnl_addr(struct nlmsghdr *hdr)
{
	struct ifaddrmsg *msg;
	struct rtattr *attr;
	int bytes;

	msg = (struct ifaddrmsg *) NLMSG_DATA(hdr);
	bytes = IFA_PAYLOAD(hdr);

	print("ifa_family %d ifa_index %d", msg->ifa_family, msg->ifa_index);

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
			print_string(attr, "label");
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

static void rtnl_newaddr(struct nlmsghdr *hdr)
{
	struct ifaddrmsg *msg = (struct ifaddrmsg *) NLMSG_DATA(hdr);

	rtnl_addr(hdr);

	process_newaddr(msg->ifa_family, msg->ifa_prefixlen, msg->ifa_index,
						msg, IFA_PAYLOAD(hdr));
}

static void rtnl_deladdr(struct nlmsghdr *hdr)
{
	struct ifaddrmsg *msg = (struct ifaddrmsg *) NLMSG_DATA(hdr);

	rtnl_addr(hdr);

	process_deladdr(msg->ifa_family, msg->ifa_prefixlen, msg->ifa_index,
						msg, IFA_PAYLOAD(hdr));
}

static void rtnl_route(struct nlmsghdr *hdr)
{
	struct rtmsg *msg;
	struct rtattr *attr;
	int bytes;

	msg = (struct rtmsg *) NLMSG_DATA(hdr);
	bytes = RTM_PAYLOAD(hdr);

	print("rtm_family %d rtm_table %d rtm_protocol %d",
			msg->rtm_family, msg->rtm_table, msg->rtm_protocol);
	print("rtm_scope %d rtm_type %d rtm_flags 0x%04x",
				msg->rtm_scope, msg->rtm_type, msg->rtm_flags);

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
			print_string(attr, "iif");
			break;
		case RTA_OIF:
			print_integer(attr, "oif");
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
			print_integer(attr, "table");
			break;
		default:
			print_attr(attr, NULL);
			break;
		}
	}
}

static void rtnl_newroute(struct nlmsghdr *hdr)
{
	struct rtmsg *msg = (struct rtmsg *) NLMSG_DATA(hdr);

	rtnl_route(hdr);

	if (msg->rtm_table == RT_TABLE_MAIN &&
				msg->rtm_protocol == RTPROT_BOOT &&
						msg->rtm_type == RTN_UNICAST)
		process_newroute(msg->rtm_family, msg->rtm_scope,
						msg, RTM_PAYLOAD(hdr));
}

static void rtnl_delroute(struct nlmsghdr *hdr)
{
	struct rtmsg *msg = (struct rtmsg *) NLMSG_DATA(hdr);

	rtnl_route(hdr);

	if (msg->rtm_table == RT_TABLE_MAIN &&
				msg->rtm_protocol == RTPROT_BOOT &&
						msg->rtm_type == RTN_UNICAST)
		process_delroute(msg->rtm_family, msg->rtm_scope,
						msg, RTM_PAYLOAD(hdr));
}

static const char *type2string(uint16_t type)
{
	switch (type) {
	case NLMSG_NOOP:
		return "NOOP";
	case NLMSG_ERROR:
		return "ERROR";
	case NLMSG_DONE:
		return "DONE";
	case NLMSG_OVERRUN:
		return "OVERRUN";
	case RTM_GETLINK:
		return "GETLINK";
	case RTM_NEWLINK:
		return "NEWLINK";
	case RTM_DELLINK:
		return "DELLINK";
	case RTM_NEWADDR:
		return "NEWADDR";
	case RTM_DELADDR:
		return "DELADDR";
	case RTM_GETROUTE:
		return "GETROUTE";
	case RTM_NEWROUTE:
		return "NEWROUTE";
	case RTM_DELROUTE:
		return "DELROUTE";
	default:
		return "UNKNOWN";
	}
}

static GIOChannel *channel = NULL;

struct rtnl_request {
	struct nlmsghdr hdr;
	struct rtgenmsg msg;
};
#define RTNL_REQUEST_SIZE  (sizeof(struct nlmsghdr) + sizeof(struct rtgenmsg))

static GSList *request_list = NULL;
static guint32 request_seq = 0;

static struct rtnl_request *find_request(guint32 seq)
{
	GSList *list;

	for (list = request_list; list; list = list->next) {
		struct rtnl_request *req = list->data;

		if (req->hdr.nlmsg_seq == seq)
			return req;
	}

	return NULL;
}

static int send_request(struct rtnl_request *req)
{
	struct sockaddr_nl addr;
	int sk;

	DBG("%s len %d type %d flags 0x%04x seq %d",
				type2string(req->hdr.nlmsg_type),
				req->hdr.nlmsg_len, req->hdr.nlmsg_type,
				req->hdr.nlmsg_flags, req->hdr.nlmsg_seq);

	sk = g_io_channel_unix_get_fd(channel);

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;

	return sendto(sk, req, req->hdr.nlmsg_len, 0,
				(struct sockaddr *) &addr, sizeof(addr));
}

static int queue_request(struct rtnl_request *req)
{
	request_list = g_slist_append(request_list, req);

	if (g_slist_length(request_list) > 1)
		return 0;

	return send_request(req);
}

static int process_response(guint32 seq)
{
	struct rtnl_request *req;

	DBG("seq %d", seq);

	req = find_request(seq);
	if (req != NULL) {
		request_list = g_slist_remove(request_list, req);
		g_free(req);
	}

	req = g_slist_nth_data(request_list, 0);
	if (req == NULL)
		return 0;

	return send_request(req);
}

static void rtnl_message(void *buf, size_t len)
{
	DBG("buf %p len %zd", buf, len);

	while (len > 0) {
		struct nlmsghdr *hdr = buf;
		struct nlmsgerr *err;

		if (!NLMSG_OK(hdr, len))
			break;

		DBG("%s len %d type %d flags 0x%04x seq %d",
					type2string(hdr->nlmsg_type),
					hdr->nlmsg_len, hdr->nlmsg_type,
					hdr->nlmsg_flags, hdr->nlmsg_seq);

		switch (hdr->nlmsg_type) {
		case NLMSG_NOOP:
		case NLMSG_OVERRUN:
			return;
		case NLMSG_DONE:
			process_response(hdr->nlmsg_seq);
			return;
		case NLMSG_ERROR:
			err = NLMSG_DATA(hdr);
			DBG("error %d (%s)", -err->error,
						strerror(-err->error));
			return;
		case RTM_NEWLINK:
			rtnl_newlink(hdr);
			break;
		case RTM_DELLINK:
			rtnl_dellink(hdr);
			break;
		case RTM_NEWADDR:
			rtnl_newaddr(hdr);
			break;
		case RTM_DELADDR:
			rtnl_deladdr(hdr);
			break;
		case RTM_NEWROUTE:
			rtnl_newroute(hdr);
			break;
		case RTM_DELROUTE:
			rtnl_delroute(hdr);
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

static int send_getlink(void)
{
	struct rtnl_request *req;

	DBG("");

	req = g_try_malloc0(RTNL_REQUEST_SIZE);
	if (req == NULL)
		return -ENOMEM;

	req->hdr.nlmsg_len = RTNL_REQUEST_SIZE;
	req->hdr.nlmsg_type = RTM_GETLINK;
	req->hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req->hdr.nlmsg_pid = 0;
	req->hdr.nlmsg_seq = request_seq++;
	req->msg.rtgen_family = AF_INET;

	return queue_request(req);
}

static int send_getaddr(void)
{
	struct rtnl_request *req;

	DBG("");

	req = g_try_malloc0(RTNL_REQUEST_SIZE);
	if (req == NULL)
		return -ENOMEM;

	req->hdr.nlmsg_len = RTNL_REQUEST_SIZE;
	req->hdr.nlmsg_type = RTM_GETADDR;
	req->hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req->hdr.nlmsg_pid = 0;
	req->hdr.nlmsg_seq = request_seq++;
	req->msg.rtgen_family = AF_INET;

	return queue_request(req);
}

int connman_rtnl_send_getroute(void)
{
	struct rtnl_request *req;

	DBG("");

	req = g_try_malloc0(RTNL_REQUEST_SIZE);
	if (req == NULL)
		return -ENOMEM;

	req->hdr.nlmsg_len = RTNL_REQUEST_SIZE;
	req->hdr.nlmsg_type = RTM_GETROUTE;
	req->hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req->hdr.nlmsg_pid = 0;
	req->hdr.nlmsg_seq = request_seq++;
	req->msg.rtgen_family = AF_INET;

	return queue_request(req);
}

int __connman_rtnl_init(void)
{
	struct sockaddr_nl addr;
	int sk;

	DBG("");

	ipconfig_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal,
							NULL, free_ipconfig);

	sk = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (sk < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE;

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

void __connman_rtnl_start(void)
{
	DBG("");

	send_getlink();
	send_getaddr();
	connman_rtnl_send_getroute();
}

void __connman_rtnl_cleanup(void)
{
	GSList *list;

	DBG("");

	g_slist_free(ipconfig_list);
	ipconfig_list = NULL;

	g_hash_table_destroy(ipconfig_hash);
	ipconfig_hash = NULL;

	for (list = watch_list; list; list = list->next) {
		struct watch_data *watch = list->data;

		DBG("removing watch %d", watch->id);

		g_free(watch);
		list->data = NULL;
	}

	g_slist_free(watch_list);
	watch_list = NULL;

	for (list = request_list; list; list = list->next) {
		struct rtnl_request *req = list->data;

		DBG("%s len %d type %d flags 0x%04x seq %d",
				type2string(req->hdr.nlmsg_type),
				req->hdr.nlmsg_len, req->hdr.nlmsg_type,
				req->hdr.nlmsg_flags, req->hdr.nlmsg_seq);

		g_free(req);
		list->data = NULL;
	}

	g_slist_free(request_list);
	request_list = NULL;

	g_io_channel_shutdown(channel, TRUE, NULL);
	g_io_channel_unref(channel);

	channel = NULL;
}
