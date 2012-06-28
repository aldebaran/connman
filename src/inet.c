/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2012  Intel Corporation. All rights reserved.
 *  Copyright (C) 2003-2005  Go-Core Project
 *  Copyright (C) 2003-2006  Helsinki University of Technology
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

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <net/route.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/icmp6.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <ctype.h>

#include "connman.h"

#define NLMSG_TAIL(nmsg)				\
	((struct rtattr *) (((uint8_t*) (nmsg)) +	\
	NLMSG_ALIGN((nmsg)->nlmsg_len)))

int __connman_inet_rtnl_addattr_l(struct nlmsghdr *n, size_t max_length,
				int type, const void *data, size_t data_length)
{
	size_t length;
	struct rtattr *rta;

	length = RTA_LENGTH(data_length);

	if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(length) > max_length)
		return -E2BIG;

	rta = NLMSG_TAIL(n);
	rta->rta_type = type;
	rta->rta_len = length;
	memcpy(RTA_DATA(rta), data, data_length);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(length);

	return 0;
}

int __connman_inet_modify_address(int cmd, int flags,
				int index, int family,
				const char *address,
				const char *peer,
				unsigned char prefixlen,
				const char *broadcast)
{
	uint8_t request[NLMSG_ALIGN(sizeof(struct nlmsghdr)) +
			NLMSG_ALIGN(sizeof(struct ifaddrmsg)) +
			RTA_LENGTH(sizeof(struct in6_addr)) +
			RTA_LENGTH(sizeof(struct in6_addr))];

	struct nlmsghdr *header;
	struct sockaddr_nl nl_addr;
	struct ifaddrmsg *ifaddrmsg;
	struct in6_addr ipv6_addr;
	struct in_addr ipv4_addr, ipv4_dest, ipv4_bcast;
	int sk, err;

	DBG("cmd %#x flags %#x index %d family %d address %s peer %s "
		"prefixlen %hhu broadcast %s", cmd, flags, index, family,
		address, peer, prefixlen, broadcast);

	if (address == NULL)
		return -EINVAL;

	if (family != AF_INET && family != AF_INET6)
		return -EINVAL;

	memset(&request, 0, sizeof(request));

	header = (struct nlmsghdr *)request;
	header->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	header->nlmsg_type = cmd;
	header->nlmsg_flags = NLM_F_REQUEST | flags;
	header->nlmsg_seq = 1;

	ifaddrmsg = NLMSG_DATA(header);
	ifaddrmsg->ifa_family = family;
	ifaddrmsg->ifa_prefixlen = prefixlen;
	ifaddrmsg->ifa_flags = IFA_F_PERMANENT;
	ifaddrmsg->ifa_scope = RT_SCOPE_UNIVERSE;
	ifaddrmsg->ifa_index = index;

	if (family == AF_INET) {
		if (inet_pton(AF_INET, address, &ipv4_addr) < 1)
			return -1;

		if (broadcast != NULL)
			inet_pton(AF_INET, broadcast, &ipv4_bcast);
		else
			ipv4_bcast.s_addr = ipv4_addr.s_addr |
				htonl(0xfffffffflu >> prefixlen);

		if (peer != NULL) {
			if (inet_pton(AF_INET, peer, &ipv4_dest) < 1)
				return -1;

			err = __connman_inet_rtnl_addattr_l(header,
							sizeof(request),
							IFA_ADDRESS,
							&ipv4_dest,
							sizeof(ipv4_dest));
			if (err < 0)
				return err;
		}

		err = __connman_inet_rtnl_addattr_l(header,
						sizeof(request),
						IFA_LOCAL,
						&ipv4_addr,
						sizeof(ipv4_addr));
		if (err < 0)
			return err;

		err = __connman_inet_rtnl_addattr_l(header,
						sizeof(request),
						IFA_BROADCAST,
						&ipv4_bcast,
						sizeof(ipv4_bcast));
		if (err < 0)
			return err;

	} else if (family == AF_INET6) {
		if (inet_pton(AF_INET6, address, &ipv6_addr) < 1)
			return -1;

		err = __connman_inet_rtnl_addattr_l(header,
						sizeof(request),
						IFA_LOCAL,
						&ipv6_addr,
						sizeof(ipv6_addr));
		if (err < 0)
			return err;
	}

	sk = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (sk < 0)
		return -errno;

	memset(&nl_addr, 0, sizeof(nl_addr));
	nl_addr.nl_family = AF_NETLINK;

	if ((err = sendto(sk, request, header->nlmsg_len, 0,
			(struct sockaddr *) &nl_addr, sizeof(nl_addr))) < 0)
		goto done;

	err = 0;

done:
	close(sk);

	return err;
}

int connman_inet_ifindex(const char *name)
{
	struct ifreq ifr;
	int sk, err;

	if (name == NULL)
		return -1;

	sk = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sk < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));

	err = ioctl(sk, SIOCGIFINDEX, &ifr);

	close(sk);

	if (err < 0)
		return -1;

	return ifr.ifr_ifindex;
}

char *connman_inet_ifname(int index)
{
	struct ifreq ifr;
	int sk, err;

	if (index < 0)
		return NULL;

	sk = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
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

short int connman_inet_ifflags(int index)
{
	struct ifreq ifr;
	int sk, err;

	sk = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sk < 0)
		return -errno;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = index;

	if (ioctl(sk, SIOCGIFNAME, &ifr) < 0) {
		err = -errno;
		goto done;
	}

	if (ioctl(sk, SIOCGIFFLAGS, &ifr) < 0) {
		err = -errno;
		goto done;
	}

	err = ifr.ifr_flags;

done:
	close(sk);

	return err;
}

int connman_inet_ifup(int index)
{
	struct ifreq ifr;
	int sk, err;

	sk = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sk < 0)
		return -errno;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = index;

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

int connman_inet_ifdown(int index)
{
	struct ifreq ifr;
	int sk, err;

	sk = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sk < 0)
		return -errno;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = index;

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

static char *index2addr(int index)
{
	struct ifreq ifr;
	struct ether_addr eth;
	char *str;
	int sk, err;

	if (index < 0)
		return NULL;

	sk = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
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

	memcpy(&eth, &ifr.ifr_hwaddr.sa_data, sizeof(eth));
	snprintf(str, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
						eth.ether_addr_octet[0],
						eth.ether_addr_octet[1],
						eth.ether_addr_octet[2],
						eth.ether_addr_octet[3],
						eth.ether_addr_octet[4],
						eth.ether_addr_octet[5]);

	return str;
}

static char *index2ident(int index, const char *prefix)
{
	struct ifreq ifr;
	struct ether_addr eth;
	char *str;
	int sk, err, len;

	if (index < 0)
		return NULL;

	sk = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
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

	memcpy(&eth, &ifr.ifr_hwaddr.sa_data, sizeof(eth));
	snprintf(str, len, "%s%02x%02x%02x%02x%02x%02x",
						prefix ? prefix : "",
						eth.ether_addr_octet[0],
						eth.ether_addr_octet[1],
						eth.ether_addr_octet[2],
						eth.ether_addr_octet[3],
						eth.ether_addr_octet[4],
						eth.ether_addr_octet[5]);

	return str;
}

connman_bool_t connman_inet_is_cfg80211(int index)
{
	connman_bool_t result = FALSE;
	char phy80211_path[PATH_MAX];
	struct stat st;
	struct ifreq ifr;
	int sk;

	sk = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sk < 0)
		return FALSE;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = index;

	if (ioctl(sk, SIOCGIFNAME, &ifr) < 0)
		goto done;

	snprintf(phy80211_path, PATH_MAX,
				"/sys/class/net/%s/phy80211", ifr.ifr_name);

	if (stat(phy80211_path, &st) == 0 && (st.st_mode & S_IFDIR))
		result = TRUE;

done:
	close(sk);

	return result;
}

struct connman_device *connman_inet_create_device(int index)
{
	enum connman_device_type type;
	struct connman_device *device;
	char *devname, *ident = NULL;
	char *addr = NULL, *name = NULL;

	if (index < 0)
		return NULL;

	devname = connman_inet_ifname(index);
	if (devname == NULL)
		return NULL;

	if (__connman_device_isfiltered(devname) == TRUE) {
		connman_info("Ignoring interface %s (filtered)", devname);
		free(devname);
		return NULL;
	}

	type = __connman_rtnl_get_device_type(index);

	switch (type) {
	case CONNMAN_DEVICE_TYPE_UNKNOWN:
		connman_info("Ignoring interface %s (type unknown)", devname);
		free(devname);
		return NULL;
	case CONNMAN_DEVICE_TYPE_ETHERNET:
	case CONNMAN_DEVICE_TYPE_GADGET:
	case CONNMAN_DEVICE_TYPE_WIFI:
	case CONNMAN_DEVICE_TYPE_WIMAX:
		name = index2ident(index, "");
		addr = index2addr(index);
		break;
	case CONNMAN_DEVICE_TYPE_BLUETOOTH:
	case CONNMAN_DEVICE_TYPE_CELLULAR:
	case CONNMAN_DEVICE_TYPE_GPS:
	case CONNMAN_DEVICE_TYPE_VENDOR:
		name = strdup(devname);
		break;
	}

	device = connman_device_create(name, type);
	if (device == NULL)
		goto done;

	switch (type) {
	case CONNMAN_DEVICE_TYPE_UNKNOWN:
	case CONNMAN_DEVICE_TYPE_VENDOR:
	case CONNMAN_DEVICE_TYPE_GPS:
		break;
	case CONNMAN_DEVICE_TYPE_ETHERNET:
	case CONNMAN_DEVICE_TYPE_GADGET:
		ident = index2ident(index, NULL);
		break;
	case CONNMAN_DEVICE_TYPE_WIFI:
	case CONNMAN_DEVICE_TYPE_WIMAX:
		ident = index2ident(index, NULL);
		break;
	case CONNMAN_DEVICE_TYPE_BLUETOOTH:
		break;
	case CONNMAN_DEVICE_TYPE_CELLULAR:
		ident = index2ident(index, NULL);
		break;
	}

	connman_device_set_index(device, index);
	connman_device_set_interface(device, devname);

	if (ident != NULL) {
		connman_device_set_ident(device, ident);
		free(ident);
	}

	connman_device_set_string(device, "Address", addr);

done:
	free(devname);
	free(name);
	free(addr);

	return device;
}

struct in6_ifreq {
	struct in6_addr ifr6_addr;
	__u32 ifr6_prefixlen;
	unsigned int ifr6_ifindex;
};

int connman_inet_set_ipv6_address(int index,
		struct connman_ipaddress *ipaddress)
{
	int err;
	unsigned char prefix_len;
	const char *address;

	if (ipaddress->local == NULL)
		return 0;

	prefix_len = ipaddress->prefixlen;
	address = ipaddress->local;

	DBG("index %d address %s prefix_len %d", index, address, prefix_len);

	err = __connman_inet_modify_address(RTM_NEWADDR,
				NLM_F_REPLACE | NLM_F_ACK, index, AF_INET6,
				address, NULL, prefix_len, NULL);
	if (err < 0) {
		connman_error("%s: %s", __func__, strerror(-err));
		return err;
	}

	return 0;
}

int connman_inet_set_address(int index, struct connman_ipaddress *ipaddress)
{
	int err;
	unsigned char prefix_len;
	const char *address, *broadcast, *peer;

	if (ipaddress->local == NULL)
		return -1;

	prefix_len = ipaddress->prefixlen;
	address = ipaddress->local;
	broadcast = ipaddress->broadcast;
	peer = ipaddress->peer;

	DBG("index %d address %s prefix_len %d", index, address, prefix_len);

	err = __connman_inet_modify_address(RTM_NEWADDR,
				NLM_F_REPLACE | NLM_F_ACK, index, AF_INET,
				address, peer, prefix_len, broadcast);
	if (err < 0) {
		connman_error("%s: %s", __func__, strerror(-err));
		return err;
	}

	return 0;
}

int connman_inet_clear_ipv6_address(int index, const char *address,
							int prefix_len)
{
	int err;

	DBG("index %d address %s prefix_len %d", index, address, prefix_len);

	err = __connman_inet_modify_address(RTM_DELADDR, 0, index, AF_INET6,
				address, NULL, prefix_len, NULL);
	if (err < 0) {
		connman_error("%s: %s", __func__, strerror(-err));
		return err;
	}

	return 0;
}

int connman_inet_clear_address(int index, struct connman_ipaddress *ipaddress)
{
	int err;
	unsigned char prefix_len;
	const char *address, *broadcast, *peer;

	prefix_len = ipaddress->prefixlen;
	address = ipaddress->local;
	broadcast = ipaddress->broadcast;
	peer = ipaddress->peer;

	DBG("index %d address %s prefix_len %d", index, address, prefix_len);

	err = __connman_inet_modify_address(RTM_DELADDR, 0, index, AF_INET,
				address, peer, prefix_len, broadcast);
	if (err < 0) {
		connman_error("%s: %s", __func__, strerror(-err));
		return err;
	}

	return 0;
}

int connman_inet_add_host_route(int index, const char *host,
				const char *gateway)
{
	return connman_inet_add_network_route(index, host, gateway, NULL);
}

int connman_inet_del_host_route(int index, const char *host)
{
	return connman_inet_del_network_route(index, host);
}

int connman_inet_add_network_route(int index, const char *host,
					const char *gateway,
					const char *netmask)
{
	struct ifreq ifr;
	struct rtentry rt;
	struct sockaddr_in addr;
	int sk, err;

	DBG("index %d host %s gateway %s netmask %s", index,
		host, gateway, netmask);

	sk = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sk < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = index;

	if (ioctl(sk, SIOCGIFNAME, &ifr) < 0) {
		close(sk);
		return -1;
	}

	DBG("ifname %s", ifr.ifr_name);

	memset(&rt, 0, sizeof(rt));
	rt.rt_flags = RTF_UP;
	if (gateway != NULL)
		rt.rt_flags |= RTF_GATEWAY;
	if (netmask == NULL)
		rt.rt_flags |= RTF_HOST;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(host);
	memcpy(&rt.rt_dst, &addr, sizeof(rt.rt_dst));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	if (gateway != NULL)
		addr.sin_addr.s_addr = inet_addr(gateway);
	else
		addr.sin_addr.s_addr = INADDR_ANY;
	memcpy(&rt.rt_gateway, &addr, sizeof(rt.rt_gateway));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	if (netmask != NULL)
		addr.sin_addr.s_addr = inet_addr(netmask);
	else
		addr.sin_addr.s_addr = INADDR_ANY;
	memcpy(&rt.rt_genmask, &addr, sizeof(rt.rt_genmask));

	rt.rt_dev = ifr.ifr_name;

	err = ioctl(sk, SIOCADDRT, &rt);
	if (err < 0)
		connman_error("Adding host route failed (%s)",
							strerror(errno));

	close(sk);

	return err;
}

int connman_inet_del_network_route(int index, const char *host)
{
	struct ifreq ifr;
	struct rtentry rt;
	struct sockaddr_in addr;
	int sk, err;

	DBG("index %d host %s", index, host);

	sk = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sk < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = index;

	if (ioctl(sk, SIOCGIFNAME, &ifr) < 0) {
		close(sk);
		return -1;
	}

	DBG("ifname %s", ifr.ifr_name);

	memset(&rt, 0, sizeof(rt));
	rt.rt_flags = RTF_UP | RTF_HOST;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(host);
	memcpy(&rt.rt_dst, &addr, sizeof(rt.rt_dst));

	rt.rt_dev = ifr.ifr_name;

	err = ioctl(sk, SIOCDELRT, &rt);
	if (err < 0)
		connman_error("Deleting host route failed (%s)",
							strerror(errno));

	close(sk);

	return err;
}

int connman_inet_del_ipv6_network_route(int index, const char *host,
						unsigned char prefix_len)
{
	struct in6_rtmsg rt;
	int sk, err;

	DBG("index %d host %s", index, host);

	if (host == NULL)
		return -EINVAL;

	memset(&rt, 0, sizeof(rt));

	rt.rtmsg_dst_len = prefix_len;

	err = inet_pton(AF_INET6, host, &rt.rtmsg_dst);
	if (err < 0)
		goto out;

	rt.rtmsg_flags = RTF_UP | RTF_HOST;

	rt.rtmsg_metric = 1;
	rt.rtmsg_ifindex = index;

	sk = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sk < 0) {
		err = -1;
		goto out;
	}

	err = ioctl(sk, SIOCDELRT, &rt);
	close(sk);
out:
	if (err < 0)
		connman_error("Del IPv6 host route error (%s)",
						strerror(errno));

	return err;
}

int connman_inet_del_ipv6_host_route(int index, const char *host)
{
	return connman_inet_del_ipv6_network_route(index, host, 128);
}

int connman_inet_add_ipv6_network_route(int index, const char *host,
					const char *gateway,
					unsigned char prefix_len)
{
	struct in6_rtmsg rt;
	int sk, err;

	DBG("index %d host %s gateway %s", index, host, gateway);

	if (host == NULL)
		return -EINVAL;

	memset(&rt, 0, sizeof(rt));

	rt.rtmsg_dst_len = prefix_len;

	err = inet_pton(AF_INET6, host, &rt.rtmsg_dst);
	if (err < 0)
		goto out;

	rt.rtmsg_flags = RTF_UP | RTF_HOST;

	if (gateway != NULL) {
		rt.rtmsg_flags |= RTF_GATEWAY;
		inet_pton(AF_INET6, gateway, &rt.rtmsg_gateway);
	}

	rt.rtmsg_metric = 1;
	rt.rtmsg_ifindex = index;

	sk = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sk < 0) {
		err = -1;
		goto out;
	}

	err = ioctl(sk, SIOCADDRT, &rt);
	close(sk);
out:
	if (err < 0)
		connman_error("Set IPv6 host route error (%s)",
						strerror(errno));

	return err;
}

int connman_inet_add_ipv6_host_route(int index, const char *host,
					const char *gateway)
{
	return connman_inet_add_ipv6_network_route(index, host, gateway, 128);
}

int connman_inet_set_ipv6_gateway_address(int index, const char *gateway)
{
	struct in6_rtmsg rt;
	int sk, err;

	DBG("index %d gateway %s", index, gateway);

	if (gateway == NULL)
		return -EINVAL;

	memset(&rt, 0, sizeof(rt));

	err = inet_pton(AF_INET6, gateway, &rt.rtmsg_gateway);
	if (err < 0)
		goto out;

	rt.rtmsg_flags = RTF_UP | RTF_GATEWAY;
	rt.rtmsg_metric = 1;
	rt.rtmsg_dst_len = 0;
	rt.rtmsg_ifindex = index;

	sk = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sk < 0) {
		err = -1;
		goto out;
	}

	err = ioctl(sk, SIOCADDRT, &rt);
	close(sk);
out:
	if (err < 0)
		connman_error("Set default IPv6 gateway error (%s)",
						strerror(errno));

	return err;
}

int connman_inet_clear_ipv6_gateway_address(int index, const char *gateway)
{
	struct in6_rtmsg rt;
	int sk, err;

	DBG("index %d gateway %s", index, gateway);

	if (gateway == NULL)
		return -EINVAL;

	memset(&rt, 0, sizeof(rt));

	err = inet_pton(AF_INET6, gateway, &rt.rtmsg_gateway);
	if (err < 0)
		goto out;

	rt.rtmsg_flags = RTF_UP | RTF_GATEWAY;
	rt.rtmsg_metric = 1;
	rt.rtmsg_dst_len = 0;
	rt.rtmsg_ifindex = index;

	sk = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sk < 0) {
		err = -1;
		goto out;
	}

	err = ioctl(sk, SIOCDELRT, &rt);
	close(sk);
out:
	if (err < 0)
		connman_error("Clear default IPv6 gateway error (%s)",
						strerror(errno));

	return err;
}

int connman_inet_set_gateway_address(int index, const char *gateway)
{
	struct ifreq ifr;
	struct rtentry rt;
	struct sockaddr_in addr;
	int sk, err;

	DBG("index %d gateway %s", index, gateway);

	sk = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sk < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = index;

	if (ioctl(sk, SIOCGIFNAME, &ifr) < 0) {
		close(sk);
		return -1;
	}

	DBG("ifname %s", ifr.ifr_name);

	memset(&rt, 0, sizeof(rt));
	rt.rt_flags = RTF_UP | RTF_GATEWAY;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	memcpy(&rt.rt_dst, &addr, sizeof(rt.rt_dst));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(gateway);
	memcpy(&rt.rt_gateway, &addr, sizeof(rt.rt_gateway));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	memcpy(&rt.rt_genmask, &addr, sizeof(rt.rt_genmask));

	err = ioctl(sk, SIOCADDRT, &rt);
	if (err < 0)
		connman_error("Setting default gateway route failed (%s)",
							strerror(errno));

	close(sk);

	return err;
}

int connman_inet_set_gateway_interface(int index)
{
	struct ifreq ifr;
	struct rtentry rt;
	struct sockaddr_in addr;
	int sk, err;

	DBG("index %d", index);

	sk = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sk < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = index;

	if (ioctl(sk, SIOCGIFNAME, &ifr) < 0) {
		close(sk);
		return -1;
	}

	DBG("ifname %s", ifr.ifr_name);

	memset(&rt, 0, sizeof(rt));
	rt.rt_flags = RTF_UP;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;

	memcpy(&rt.rt_genmask, &addr, sizeof(rt.rt_genmask));
	memcpy(&rt.rt_dst, &addr, sizeof(rt.rt_dst));
	memcpy(&rt.rt_gateway, &addr, sizeof(rt.rt_gateway));

	rt.rt_dev = ifr.ifr_name;

	err = ioctl(sk, SIOCADDRT, &rt);
	if (err < 0)
		connman_error("Setting default interface route failed (%s)",
							strerror(errno));
	close(sk);

	return err;
}

int connman_inet_set_ipv6_gateway_interface(int index)
{
	struct ifreq ifr;
	struct rtentry rt;
	struct sockaddr_in6 addr;
	const struct in6_addr any = IN6ADDR_ANY_INIT;
	int sk, err;

	DBG("index %d", index);

	sk = socket(PF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sk < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = index;

	if (ioctl(sk, SIOCGIFNAME, &ifr) < 0) {
		close(sk);
		return -1;
	}

	DBG("ifname %s", ifr.ifr_name);

	memset(&rt, 0, sizeof(rt));
	rt.rt_flags = RTF_UP;

	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_addr = any;

	memcpy(&rt.rt_genmask, &addr, sizeof(rt.rt_genmask));
	memcpy(&rt.rt_dst, &addr, sizeof(rt.rt_dst));
	memcpy(&rt.rt_gateway, &addr, sizeof(rt.rt_gateway));

	rt.rt_dev = ifr.ifr_name;

	err = ioctl(sk, SIOCADDRT, &rt);
	if (err < 0)
		connman_error("Setting default interface route failed (%s)",
							strerror(errno));
	close(sk);

	return err;
}

int connman_inet_clear_gateway_address(int index, const char *gateway)
{
	struct ifreq ifr;
	struct rtentry rt;
	struct sockaddr_in addr;
	int sk, err;

	DBG("index %d gateway %s", index, gateway);

	sk = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sk < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = index;

	if (ioctl(sk, SIOCGIFNAME, &ifr) < 0) {
		close(sk);
		return -1;
	}

	DBG("ifname %s", ifr.ifr_name);

	memset(&rt, 0, sizeof(rt));
	rt.rt_flags = RTF_UP | RTF_GATEWAY;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	memcpy(&rt.rt_dst, &addr, sizeof(rt.rt_dst));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(gateway);
	memcpy(&rt.rt_gateway, &addr, sizeof(rt.rt_gateway));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	memcpy(&rt.rt_genmask, &addr, sizeof(rt.rt_genmask));

	err = ioctl(sk, SIOCDELRT, &rt);
	if (err < 0)
		connman_error("Removing default gateway route failed (%s)",
							strerror(errno));

	close(sk);

	return err;
}

int connman_inet_clear_gateway_interface(int index)
{
	struct ifreq ifr;
	struct rtentry rt;
	struct sockaddr_in addr;
	int sk, err;

	DBG("index %d", index);

	sk = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sk < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = index;

	if (ioctl(sk, SIOCGIFNAME, &ifr) < 0) {
		close(sk);
		return -1;
	}

	DBG("ifname %s", ifr.ifr_name);

	memset(&rt, 0, sizeof(rt));
	rt.rt_flags = RTF_UP;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;

	memcpy(&rt.rt_genmask, &addr, sizeof(rt.rt_genmask));
	memcpy(&rt.rt_dst, &addr, sizeof(rt.rt_dst));
	memcpy(&rt.rt_gateway, &addr, sizeof(rt.rt_gateway));

	rt.rt_dev = ifr.ifr_name;

	err = ioctl(sk, SIOCDELRT, &rt);
	if (err < 0)
		connman_error("Removing default interface route failed (%s)",
							strerror(errno));
	close(sk);

	return err;
}

int connman_inet_clear_ipv6_gateway_interface(int index)
{
	struct ifreq ifr;
	struct rtentry rt;
	struct sockaddr_in6 addr;
	const struct in6_addr any = IN6ADDR_ANY_INIT;
	int sk, err;

	DBG("index %d", index);

	sk = socket(PF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sk < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = index;

	if (ioctl(sk, SIOCGIFNAME, &ifr) < 0) {
		close(sk);
		return -1;
	}

	DBG("ifname %s", ifr.ifr_name);

	memset(&rt, 0, sizeof(rt));
	rt.rt_flags = RTF_UP;

	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_addr = any;

	memcpy(&rt.rt_genmask, &addr, sizeof(rt.rt_genmask));
	memcpy(&rt.rt_dst, &addr, sizeof(rt.rt_dst));
	memcpy(&rt.rt_gateway, &addr, sizeof(rt.rt_gateway));

	rt.rt_dev = ifr.ifr_name;

	err = ioctl(sk, SIOCDELRT, &rt);
	if (err < 0)
		connman_error("Removing default interface route failed (%s)",
							strerror(errno));
	close(sk);

	return err;
}

connman_bool_t connman_inet_compare_subnet(int index, const char *host)
{
	struct ifreq ifr;
	struct in_addr _host_addr;
	in_addr_t host_addr, netmask_addr, if_addr;
	struct sockaddr_in *netmask, *addr;
	int sk;

	DBG("host %s", host);

	if (host == NULL)
		return FALSE;

	if (inet_aton(host, &_host_addr) == 0)
		return -1;
	host_addr = _host_addr.s_addr;

	sk = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sk < 0)
		return FALSE;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = index;

	if (ioctl(sk, SIOCGIFNAME, &ifr) < 0) {
		close(sk);
		return FALSE;
	}

	if (ioctl(sk, SIOCGIFNETMASK, &ifr) < 0) {
		close(sk);
		return FALSE;
	}

	netmask = (struct sockaddr_in *)&ifr.ifr_netmask;
	netmask_addr = netmask->sin_addr.s_addr;

	if (ioctl(sk, SIOCGIFADDR, &ifr) < 0) {
		close(sk);
		return FALSE;
	}

	close(sk);

	addr = (struct sockaddr_in *)&ifr.ifr_addr;
	if_addr = addr->sin_addr.s_addr;

	return ((if_addr & netmask_addr) == (host_addr & netmask_addr));
}

int connman_inet_remove_from_bridge(int index, const char *bridge)
{
	struct ifreq ifr;
	int sk, err;

	if (bridge == NULL)
		return -EINVAL;

	sk = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sk < 0)
		return sk;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, bridge, IFNAMSIZ - 1);
	ifr.ifr_ifindex = index;

	err = ioctl(sk, SIOCBRDELIF, &ifr);

	close(sk);

	if (err < 0) {
		connman_error("Remove interface from bridge error %s",
							strerror(errno));
		return err;
	}

	return 0;
}

int connman_inet_add_to_bridge(int index, const char *bridge)
{
	struct ifreq ifr;
	int sk, err;

	if (bridge == NULL)
		return -EINVAL;

	sk = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sk < 0)
		return sk;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, bridge, IFNAMSIZ - 1);
	ifr.ifr_ifindex = index;

	err = ioctl(sk, SIOCBRADDIF, &ifr);

	close(sk);

	if (err < 0) {
		connman_error("Add interface to bridge error %s",
							strerror(errno));
		return err;
	}

	return 0;
}

int connman_inet_set_mtu(int index, int mtu)
{
	struct ifreq ifr;
	int sk, err;

	sk = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sk < 0)
		return sk;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = index;

	err = ioctl(sk, SIOCGIFNAME, &ifr);
	if (err == 0) {
		ifr.ifr_mtu = mtu;
		err = ioctl(sk, SIOCSIFMTU, &ifr);
	}

	close(sk);
	return err;
}

int connman_inet_setup_tunnel(char *tunnel, int mtu)
{
	struct ifreq ifr;
	int sk, err, index;
	__u32 mask;
	__u32 flags;

	if (tunnel == NULL)
		return -EINVAL;

	sk = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sk < 0)
		return sk;

	index = if_nametoindex(tunnel);

	err = connman_inet_set_mtu(index, mtu);
	if (err < 0)
		return err;
	else if (err)
		goto done;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, tunnel, IFNAMSIZ);
	err = ioctl(sk, SIOCGIFFLAGS, &ifr);
	if (err)
		goto done;

	mask = IFF_UP;
	flags = IFF_UP;

	if ((ifr.ifr_flags ^ flags) & mask) {
		ifr.ifr_flags &= ~mask;
		ifr.ifr_flags |= mask & flags;
		err = ioctl(sk, SIOCSIFFLAGS, &ifr);
		if (err)
			connman_error("SIOCSIFFLAGS failed: %s",
							strerror(errno));
	}

done:
	close(sk);
	return err;
}

int connman_inet_create_tunnel(char **iface)
{
	struct ifreq ifr;
	int i, fd;

	fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		i = -errno;
		connman_error("Failed to open /dev/net/tun: %s",
				strerror(errno));
		return i;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	for (i = 0; i < 256; i++) {
		sprintf(ifr.ifr_name, "tun%d", i);

		if (!ioctl(fd, TUNSETIFF, (void *)&ifr))
			break;
	}

	if (i == 256) {
		connman_error("Failed to find available tun device");
		close(fd);
		return -ENODEV;
	}

	*iface = g_strdup(ifr.ifr_name);

	return fd;
}

struct rs_cb_data {
	GIOChannel *channel;
	__connman_inet_rs_cb_t callback;
	struct sockaddr_in6 addr;
	guint rs_timeout;
	guint watch_id;
	void *user_data;
};

#define CMSG_BUF_LEN 512
#define IN6ADDR_ALL_NODES_MC_INIT \
	{ { { 0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,0x1 } } } /* ff02::1 */
#define IN6ADDR_ALL_ROUTERS_MC_INIT \
	{ { { 0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,0x2 } } } /* ff02::2 */

static const struct in6_addr in6addr_all_nodes_mc = IN6ADDR_ALL_NODES_MC_INIT;
static const struct in6_addr in6addr_all_routers_mc =
						IN6ADDR_ALL_ROUTERS_MC_INIT;

static void rs_cleanup(struct rs_cb_data *data)
{
	if (data->channel != NULL) {
		g_io_channel_shutdown(data->channel, TRUE, NULL);
		g_io_channel_unref(data->channel);
		data->channel = NULL;
	}

	if (data->rs_timeout > 0)
		g_source_remove(data->rs_timeout);

	if (data->watch_id > 0)
		g_source_remove(data->watch_id);

	g_free(data);
}

static gboolean rs_timeout_cb(gpointer user_data)
{
	struct rs_cb_data *data = user_data;

	DBG("user data %p", user_data);

	if (data == NULL)
		return FALSE;

	if (data->callback != NULL)
		data->callback(NULL, 0, data->user_data);

	data->rs_timeout = 0;
	rs_cleanup(data);
	return FALSE;
}

static int icmpv6_recv(int fd, gpointer user_data)
{
	struct msghdr mhdr;
	struct iovec iov;
	unsigned char chdr[CMSG_BUF_LEN];
	unsigned char buf[1540];
	struct rs_cb_data *data = user_data;
	struct nd_router_advert *hdr;
	struct sockaddr_in6 saddr;
	ssize_t len;

	DBG("");

	iov.iov_len = sizeof(buf);
	iov.iov_base = buf;

	mhdr.msg_name = (void *)&saddr;
	mhdr.msg_namelen = sizeof(struct sockaddr_in6);
	mhdr.msg_iov = &iov;
	mhdr.msg_iovlen = 1;
	mhdr.msg_control = (void *)chdr;
	mhdr.msg_controllen = CMSG_BUF_LEN;

	len = recvmsg(fd, &mhdr, 0);
	if (len < 0) {
		data->callback(NULL, 0, data->user_data);
		rs_cleanup(data);
		return -errno;
	}

	hdr = (struct nd_router_advert *)buf;
	DBG("code %d len %zd hdr %zd", hdr->nd_ra_code, len,
				sizeof(struct nd_router_advert));
	if (hdr->nd_ra_code != 0)
		return 0;

	data->callback(hdr, len, data->user_data);
	rs_cleanup(data);

	return len;
}

static gboolean icmpv6_event(GIOChannel *chan, GIOCondition cond,
								gpointer data)
{
	int fd, ret;

	DBG("");

	if (cond & (G_IO_NVAL | G_IO_HUP | G_IO_ERR))
		return FALSE;

	fd = g_io_channel_unix_get_fd(chan);
	ret = icmpv6_recv(fd, data);
	if (ret == 0)
		return TRUE;

	return FALSE;
}

/* Adapted from RFC 1071 "C" Implementation Example */
static uint16_t csum(const void *phdr, const void *data, socklen_t datalen)
{
	register unsigned long sum = 0;
	socklen_t count;
	uint16_t *addr;
	int i;

	/* caller must make sure datalen is even */

	addr = (uint16_t *)phdr;
	for (i = 0; i < 20; i++)
		sum += *addr++;

	count = datalen;
	addr = (uint16_t *)data;

	while (count > 1) {
		sum += *(addr++);
		count -= 2;
	}

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return (uint16_t)~sum;
}

static int ndisc_send_unspec(int type, int oif, const struct in6_addr *dest)
{
	struct _phdr {
		struct in6_addr src;
		struct in6_addr dst;
		uint32_t plen;
		uint8_t reserved[3];
		uint8_t nxt;
	} phdr;

	struct {
		struct ip6_hdr ip;
		union {
			struct icmp6_hdr icmp;
			struct nd_neighbor_solicit ns;
			struct nd_router_solicit rs;
		} i;
	} frame;

	struct msghdr msgh;
	struct cmsghdr *cmsg;
	struct in6_pktinfo *pinfo;
	struct sockaddr_in6 dst;
	char cbuf[CMSG_SPACE(sizeof(*pinfo))];
	struct iovec iov;
	int fd, datalen, ret;

	DBG("");

	fd = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
	if (fd < 0)
		return -errno;

	memset(&frame, 0, sizeof(frame));
	memset(&dst, 0, sizeof(dst));

	datalen = sizeof(frame.i.rs); /* 8, csum() safe */
	dst.sin6_addr = *dest;

	/* Fill in the IPv6 header */
	frame.ip.ip6_vfc = 0x60;
	frame.ip.ip6_plen = htons(datalen);
	frame.ip.ip6_nxt = IPPROTO_ICMPV6;
	frame.ip.ip6_hlim = 255;
	frame.ip.ip6_dst = dst.sin6_addr;
	/* all other fields are already set to zero */

	/* Prepare pseudo header for csum */
	memset(&phdr, 0, sizeof(phdr));
	phdr.dst = dst.sin6_addr;
	phdr.plen = htonl(datalen);
	phdr.nxt = IPPROTO_ICMPV6;

	/* Fill in remaining ICMP header fields */
	frame.i.icmp.icmp6_type = type;
	frame.i.icmp.icmp6_cksum = csum(&phdr, &frame.i, datalen);

	iov.iov_base = &frame;
	iov.iov_len = sizeof(frame.ip) + datalen;

	dst.sin6_family = AF_INET6;
	msgh.msg_name = &dst;
	msgh.msg_namelen = sizeof(dst);
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	msgh.msg_flags = 0;

	memset(cbuf, 0, CMSG_SPACE(sizeof(*pinfo)));
	cmsg = (struct cmsghdr *)cbuf;
	pinfo = (struct in6_pktinfo *)CMSG_DATA(cmsg);
	pinfo->ipi6_ifindex = oif;

	cmsg->cmsg_len = CMSG_LEN(sizeof(*pinfo));
	cmsg->cmsg_level = IPPROTO_IPV6;
	cmsg->cmsg_type = IPV6_PKTINFO;
	msgh.msg_control = cmsg;
	msgh.msg_controllen = cmsg->cmsg_len;

	ret = sendmsg(fd, &msgh, 0);

	close(fd);
	return ret;
}

static inline void ipv6_addr_set(struct in6_addr *addr,
				uint32_t w1, uint32_t w2,
				uint32_t w3, uint32_t w4)
{
	addr->s6_addr32[0] = w1;
	addr->s6_addr32[1] = w2;
	addr->s6_addr32[2] = w3;
	addr->s6_addr32[3] = w4;
}

static inline void ipv6_addr_solict_mult(const struct in6_addr *addr,
					struct in6_addr *solicited)
{
	ipv6_addr_set(solicited, htonl(0xFF020000), 0, htonl(0x1),
			htonl(0xFF000000) | addr->s6_addr32[3]);
}

static int if_mc_group(int sock, int ifindex, const struct in6_addr *mc_addr,
								int cmd)
{
	unsigned int val = 0;
	struct ipv6_mreq mreq;
	int ret;

	memset(&mreq, 0, sizeof(mreq));
	mreq.ipv6mr_interface = ifindex;
	mreq.ipv6mr_multiaddr = *mc_addr;

	ret = setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
			&val, sizeof(int));

	if (ret < 0)
		return ret;

	return setsockopt(sock, IPPROTO_IPV6, cmd, &mreq, sizeof(mreq));
}

int __connman_inet_ipv6_send_rs(int index, int timeout,
			__connman_inet_rs_cb_t callback, void *user_data)
{
	struct rs_cb_data *data;
	struct icmp6_filter filter;
	struct in6_addr solicit;
	struct in6_addr dst = in6addr_all_routers_mc;
	int sk;

	DBG("");

	if (timeout <= 0)
		return -EINVAL;

	data = g_try_malloc0(sizeof(struct rs_cb_data));
	if (data == NULL)
		return -ENOMEM;

	data->callback = callback;
	data->user_data = user_data;
	data->rs_timeout = g_timeout_add_seconds(timeout, rs_timeout_cb, data);

	sk = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMPV6);
	if (sk < 0)
		return -errno;

	ICMP6_FILTER_SETBLOCKALL(&filter);
	ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &filter);

	setsockopt(sk, IPPROTO_ICMPV6, ICMP6_FILTER, &filter,
						sizeof(struct icmp6_filter));

	ipv6_addr_solict_mult(&dst, &solicit);
	if_mc_group(sk, index, &in6addr_all_nodes_mc, IPV6_JOIN_GROUP);
	if_mc_group(sk, index, &solicit, IPV6_JOIN_GROUP);

	data->channel = g_io_channel_unix_new(sk);
	g_io_channel_set_close_on_unref(data->channel, TRUE);

	g_io_channel_set_encoding(data->channel, NULL, NULL);
	g_io_channel_set_buffered(data->channel, FALSE);

	data->watch_id = g_io_add_watch(data->channel,
			G_IO_IN | G_IO_NVAL | G_IO_HUP | G_IO_ERR,
			icmpv6_event, data);

	ndisc_send_unspec(ND_ROUTER_SOLICIT, index, &dst);

	return 0;
}

GSList *__connman_inet_ipv6_get_prefixes(struct nd_router_advert *hdr,
					unsigned int length)
{
	GSList *prefixes = NULL;
	uint8_t *pos;
	int len;

	if (length <= sizeof(struct nd_router_advert))
		return NULL;

	len = length - sizeof(struct nd_router_advert);
	pos = (uint8_t *)hdr + sizeof(struct nd_router_advert);

	while (len > 0) {
		struct nd_opt_prefix_info *pinfo;
		char prefix_str[INET6_ADDRSTRLEN+1], *str;
		const char *prefix;
		int optlen;

		if (len < 2)
			break;

		optlen = pos[1] << 3;
		if (optlen == 0 || optlen > len)
			break;

		switch (pos[0]) {
		case ND_OPT_PREFIX_INFORMATION:
			pinfo = (struct nd_opt_prefix_info *)pos;
			prefix = inet_ntop(AF_INET6, &pinfo->nd_opt_pi_prefix,
					prefix_str, INET6_ADDRSTRLEN);
			if (prefix == NULL)
				break;

			str = g_strdup_printf("%s/%d", prefix,
						pinfo->nd_opt_pi_prefix_len);
			prefixes = g_slist_append(prefixes, str);

			DBG("prefix %s", str);

			break;
		}

		len -= optlen;
		pos += optlen;
	}

	return prefixes;
}

static int get_dest_addr(int family, int index, char *buf, int len)
{
	struct ifreq ifr;
	void *addr;
	int sk;

	sk = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sk < 0)
		return -errno;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = index;

	if (ioctl(sk, SIOCGIFNAME, &ifr) < 0) {
		DBG("SIOCGIFNAME (%d/%s)", errno, strerror(errno));
		close(sk);
		return -errno;
	}

	if (ioctl(sk, SIOCGIFFLAGS, &ifr) < 0) {
		DBG("SIOCGIFFLAGS (%d/%s)", errno, strerror(errno));
		close(sk);
		return -errno;
	}

	if ((ifr.ifr_flags & IFF_POINTOPOINT) == 0) {
		close(sk);
		errno = EINVAL;
		return -errno;
	}

	DBG("index %d %s", index, ifr.ifr_name);

	if (ioctl(sk, SIOCGIFDSTADDR, &ifr) < 0) {
		connman_error("Get destination address failed (%s)",
							strerror(errno));
		close(sk);
		return -errno;
	}

	close(sk);

	switch (family) {
	case AF_INET:
		addr = &((struct sockaddr_in *)&ifr.ifr_dstaddr)->sin_addr;
		break;
	case AF_INET6:
		addr = &((struct sockaddr_in6 *)&ifr.ifr_dstaddr)->sin6_addr;
		break;
	default:
		errno = EINVAL;
		return -errno;
	}

	if (inet_ntop(family, addr, buf, len) == NULL) {
		DBG("error %d/%s", errno, strerror(errno));
		return -errno;
	}

	return 0;
}

int connman_inet_get_dest_addr(int index, char **dest)
{
	char addr[INET_ADDRSTRLEN];
	int ret;

	ret = get_dest_addr(PF_INET, index, addr, INET_ADDRSTRLEN);
	if (ret < 0)
		return ret;

	*dest = g_strdup(addr);

	DBG("destination %s", *dest);

	return 0;
}

int connman_inet_ipv6_get_dest_addr(int index, char **dest)
{
	char addr[INET6_ADDRSTRLEN];
	int ret;

	ret = get_dest_addr(PF_INET6, index, addr, INET6_ADDRSTRLEN);
	if (ret < 0)
		return ret;

	*dest = g_strdup(addr);

	DBG("destination %s", *dest);

	return 0;
}

int __connman_inet_rtnl_open(struct __connman_inet_rtnl_handle *rth)
{
	int sndbuf = 1024;
	int rcvbuf = 1024 * 4;

	rth->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (rth->fd < 0) {
		connman_error("Can not open netlink socket: %s",
						strerror(errno));
		return -errno;
	}

	if (setsockopt(rth->fd, SOL_SOCKET, SO_SNDBUF, &sndbuf,
			sizeof(sndbuf)) < 0) {
		connman_error("SO_SNDBUF: %s", strerror(errno));
		return -errno;
	}

	if (setsockopt(rth->fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf,
			sizeof(rcvbuf)) < 0) {
		connman_error("SO_RCVBUF: %s", strerror(errno));
		return -errno;
	}

	memset(&rth->local, 0, sizeof(rth->local));
	rth->local.nl_family = AF_NETLINK;
	rth->local.nl_groups = 0;

	if (bind(rth->fd, (struct sockaddr *)&rth->local,
						sizeof(rth->local)) < 0) {
		connman_error("Can not bind netlink socket: %s",
							strerror(errno));
		return -errno;
	}

	rth->seq = time(NULL);

	DBG("fd %d", rth->fd);

	return 0;
}

struct inet_rtnl_cb_data {
	GIOChannel *channel;
	__connman_inet_rtnl_cb_t callback;
	guint rtnl_timeout;
	guint watch_id;
	struct __connman_inet_rtnl_handle *rtnl;
	void *user_data;
};

static void inet_rtnl_cleanup(struct inet_rtnl_cb_data *data)
{
	struct __connman_inet_rtnl_handle *rth = data->rtnl;

	if (data->channel != NULL) {
		g_io_channel_shutdown(data->channel, TRUE, NULL);
		g_io_channel_unref(data->channel);
		data->channel = NULL;
	}

	DBG("data %p", data);

	if (data->rtnl_timeout > 0)
		g_source_remove(data->rtnl_timeout);

	if (data->watch_id > 0)
		g_source_remove(data->watch_id);

	if (rth != NULL) {
		__connman_inet_rtnl_close(rth);
		g_free(rth);
	}

	g_free(data);
}

static gboolean inet_rtnl_timeout_cb(gpointer user_data)
{
	struct inet_rtnl_cb_data *data = user_data;

	DBG("user data %p", user_data);

	if (data == NULL)
		return FALSE;

	if (data->callback != NULL)
		data->callback(NULL, data->user_data);

	data->rtnl_timeout = 0;
	inet_rtnl_cleanup(data);
	return FALSE;
}

static int inet_rtnl_recv(GIOChannel *chan, gpointer user_data)
{
	struct inet_rtnl_cb_data *rtnl_data = user_data;
	struct __connman_inet_rtnl_handle *rth = rtnl_data->rtnl;
	struct nlmsghdr *h = NULL;
	struct sockaddr_nl nladdr;
	socklen_t addr_len = sizeof(nladdr);
	unsigned char buf[4096];
	void *ptr = buf;
	gsize len;
	int status, fd;

	memset(buf, 0, sizeof(buf));
	memset(&nladdr, 0, sizeof(nladdr));

	fd = g_io_channel_unix_get_fd(chan);

	status = recvfrom(fd, buf, sizeof(buf), 0,
                       (struct sockaddr *) &nladdr, &addr_len);
	if (status < 0) {
		if (errno == EINTR || errno == EAGAIN)
			return 0;

		return -1;
	}

	if (status == 0)
		return -1;

	if (nladdr.nl_pid != 0) { /* not sent by kernel, ignore */
		DBG("Received msg from %u, ignoring it", nladdr.nl_pid);
		return 0;
	}

	len = status;

	while (len > 0) {
		struct nlmsgerr *err;

		h = ptr;

		if (!NLMSG_OK(h, len)) {
			return -1;
			break;
		}

		if (h->nlmsg_seq != rth->seq) {
			/* Skip this msg */
			DBG("skip %d/%d len %d", rth->seq,
				h->nlmsg_seq, h->nlmsg_len);

			len -= h->nlmsg_len;
			ptr += h->nlmsg_len;
			continue;
		}

		switch (h->nlmsg_type) {
		case NLMSG_NOOP:
		case NLMSG_OVERRUN:
			return -1;

		case NLMSG_ERROR:
			err = (struct nlmsgerr *)NLMSG_DATA(h);
			connman_error("RTNETLINK answers %s (%d)",
				strerror(-err->error), -err->error);
			return err->error;
		}

		break;
	}

	if (h->nlmsg_seq == rth->seq) {
		DBG("received %d seq %d", h->nlmsg_len, h->nlmsg_seq);

		rtnl_data->callback(h, rtnl_data->user_data);

		if (rtnl_data->rtnl_timeout > 0) {
			g_source_remove(rtnl_data->rtnl_timeout);
			rtnl_data->rtnl_timeout = 0;
		}

		__connman_inet_rtnl_close(rth);
		g_free(rth);
	}

	return 0;
}

static gboolean inet_rtnl_event(GIOChannel *chan, GIOCondition cond,
							gpointer user_data)
{
	int ret;

	DBG("");

	if (cond & (G_IO_NVAL | G_IO_HUP | G_IO_ERR))
		return FALSE;

	ret = inet_rtnl_recv(chan, user_data);
	if (ret != 0)
		return TRUE;

	return FALSE;
}

int __connman_inet_rtnl_talk(struct __connman_inet_rtnl_handle *rtnl,
			struct nlmsghdr *n, int timeout,
			__connman_inet_rtnl_cb_t callback, void *user_data)
{
	struct sockaddr_nl nladdr;
	struct inet_rtnl_cb_data *data;
	unsigned seq;
	int err;

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;

	n->nlmsg_seq = seq = ++rtnl->seq;

	if (callback != NULL) {
		data = g_try_malloc0(sizeof(struct inet_rtnl_cb_data));
		if (data == NULL)
			return -ENOMEM;

		data->callback = callback;
		data->user_data = user_data;
		data->rtnl = rtnl;
		data->rtnl_timeout = g_timeout_add_seconds(timeout,
						inet_rtnl_timeout_cb, data);

		data->channel = g_io_channel_unix_new(rtnl->fd);
		g_io_channel_set_close_on_unref(data->channel, TRUE);

		g_io_channel_set_encoding(data->channel, NULL, NULL);
		g_io_channel_set_buffered(data->channel, FALSE);

		data->watch_id = g_io_add_watch(data->channel,
				G_IO_IN | G_IO_NVAL | G_IO_HUP | G_IO_ERR,
						inet_rtnl_event, data);
	} else
		n->nlmsg_flags |= NLM_F_ACK;

	err = sendto(rtnl->fd, &rtnl->req.n, rtnl->req.n.nlmsg_len, 0,
		(struct sockaddr *) &nladdr, sizeof(nladdr));
	DBG("handle %p len %d err %d", rtnl, rtnl->req.n.nlmsg_len, err);
	if (err < 0) {
		connman_error("Can not talk to rtnetlink");
		return -errno;
	}

	if ((unsigned int)err != rtnl->req.n.nlmsg_len) {
		connman_error("Sent %d bytes, msg truncated", err);
		return -EINVAL;
	}

	return 0;
}

void __connman_inet_rtnl_close(struct __connman_inet_rtnl_handle *rth)
{
	DBG("handle %p", rth);

	if (rth->fd >= 0) {
		close(rth->fd);
		rth->fd = -1;
	}
}

int __connman_inet_rtnl_addattr32(struct nlmsghdr *n, size_t maxlen, int type,
				__u32 data)
{
	int len = RTA_LENGTH(4);
	struct rtattr *rta;

	if (NLMSG_ALIGN(n->nlmsg_len) + len > maxlen) {
		DBG("Error! max allowed bound %zd exceeded", maxlen);
		return -1;
	}
	rta = NLMSG_TAIL(n);
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), &data, 4);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + len;

	return 0;
}

int connman_inet_check_ipaddress(const char *host)
{
	struct addrinfo hints;
	struct addrinfo *addr;
	int result;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_flags = AI_NUMERICHOST;
	addr = NULL;

	result = getaddrinfo(host, NULL, &hints, &addr);
	if (result == 0)
		result = addr->ai_family;
	freeaddrinfo(addr);

	return result;
}

/* Check routine modified from ics-dhcp 4.2.3-P2 */
connman_bool_t connman_inet_check_hostname(const char *ptr, size_t len)
{
	const char *p;

	/*
	 * Not empty or complete length not over 255 characters.
	 */
	if ((len == 0) || (len > 256))
		return FALSE;

	/*
	 * Consists of [[:alnum:]-]+ labels separated by [.]
	 * a [_] is against RFC but seems to be "widely used"
	 */
	for (p = ptr; (*p != 0) && (len-- > 0); p++) {

		if ((*p == '-') || (*p == '_')) {
			/*
			 * Not allowed at begin or end of a label.
			 */
			if (((p - ptr) == 0) || (len == 0) || (p[1] == '.'))
				return FALSE;

		} else if (*p == '.') {
			/*
			 * Each label has to be 1-63 characters;
			 * we allow [.] at the end ('foo.bar.')
			 */
			size_t d = p - ptr;

			if ((d <= 0) || (d >= 64))
				return FALSE;

			ptr = p + 1; /* Jump to the next label */

		} else if (isalnum((unsigned char)*p) == 0) {
			/*
			 * Also numbers at the begin are fine
			 */
			return FALSE;
		}
	}

	return TRUE;
}
