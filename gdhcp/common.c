/*
 *  DHCP library with GLib integration
 *
 *  Copyright (C) 2007-2010  Intel Corporation. All rights reserved.
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
#include <sys/ioctl.h>
#include <stdint.h>
#include <string.h>
#include <endian.h>
#include <net/if_arp.h>
#include <linux/if.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>

#include "gdhcp.h"
#include "common.h"

static const DHCPOption client_options[] = {
	{ OPTION_IP,			0x01 }, /* subnet-mask */
	{ OPTION_IP | OPTION_LIST,	0x03 }, /* routers */
	{ OPTION_IP | OPTION_LIST,	0x06 }, /* domain-name-servers */
	{ OPTION_STRING,		0x0c }, /* hostname */
	{ OPTION_STRING,		0x0f }, /* domain-name */
	{ OPTION_IP | OPTION_LIST,	0x2a }, /* ntp-servers */
	{ OPTION_U32,			0x33 }, /* dhcp-lease-time */
	/* Options below will not be exposed to user */
	{ OPTION_IP,			0x32 }, /* requested-ip */
	{ OPTION_U8,			0x35 }, /* message-type */
	{ OPTION_U32,			0x36 }, /* server-id */
	{ OPTION_U16,			0x39 }, /* max-size */
	{ OPTION_STRING,		0x3c }, /* vendor */
	{ OPTION_STRING,		0x3d }, /* client-id */
	{ OPTION_UNKNOWN,		0x00 },
};

GDHCPOptionType dhcp_get_code_type(uint8_t code)
{
	int i;

	for (i = 0; client_options[i].code; i++) {
		if (client_options[i].code == code)
			return client_options[i].type;
	}

	return OPTION_UNKNOWN;
}

uint8_t *dhcp_get_option(struct dhcp_packet *packet, int code)
{
	int len, rem;
	uint8_t *optionptr;
	uint8_t overload = 0;

	/* option bytes: [code][len][data1][data2]..[dataLEN] */
	optionptr = packet->options;
	rem = sizeof(packet->options);

	while (1) {
		if (rem <= 0)
			/* Bad packet, malformed option field */
			return NULL;

		if (optionptr[OPT_CODE] == DHCP_PADDING) {
			rem--;
			optionptr++;

			continue;
		}

		if (optionptr[OPT_CODE] == DHCP_END) {
			if (overload & FILE_FIELD) {
				overload &= ~FILE_FIELD;

				optionptr = packet->file;
				rem = sizeof(packet->file);

				continue;
			} else if (overload & SNAME_FIELD) {
				overload &= ~SNAME_FIELD;

				optionptr = packet->sname;
				rem = sizeof(packet->sname);

				continue;
			}

			break;
		}

		len = 2 + optionptr[OPT_LEN];

		rem -= len;
		if (rem < 0)
			continue; /* complain and return NULL */

		if (optionptr[OPT_CODE] == code)
			return optionptr + OPT_DATA;

		if (optionptr[OPT_CODE] == DHCP_OPTION_OVERLOAD)
			overload |= optionptr[OPT_DATA];

		optionptr += len;
	}

	return NULL;
}

int dhcp_end_option(uint8_t *optionptr)
{
	int i = 0;

	while (optionptr[i] != DHCP_END) {
		if (optionptr[i] != DHCP_PADDING)
			i += optionptr[i + OPT_LEN] + OPT_DATA - 1;

		i++;
	}

	return i;
}

/*
 * Add an option (supplied in binary form) to the options.
 * Option format: [code][len][data1][data2]..[dataLEN]
 */
void dhcp_add_binary_option(struct dhcp_packet *packet, uint8_t *addopt)
{
	unsigned len;
	uint8_t *optionptr = packet->options;
	unsigned end = dhcp_end_option(optionptr);

	len = OPT_DATA + addopt[OPT_LEN];

	/* end position + (option code/length + addopt length) + end option */
	if (end + len + 1 >= DHCP_OPTIONS_BUFSIZE)
		/* option did not fit into the packet */
		return;

	memcpy(optionptr + end, addopt, len);

	optionptr[end + len] = DHCP_END;
}

void dhcp_add_simple_option(struct dhcp_packet *packet, uint8_t code,
							uint32_t data)
{
	uint8_t option[6], len;
	GDHCPOptionType type = dhcp_get_code_type(code);

	if (type == OPTION_UNKNOWN)
		return;

	option[OPT_CODE] = code;

	len = dhcp_option_lengths[type & OPTION_TYPE_MASK];
	option[OPT_LEN] = len;

#if __BYTE_ORDER == __BIG_ENDIAN
	data <<= 8 * (4 - len);
#endif

	dhcp_put_unaligned(data, (uint32_t *) &option[OPT_DATA]);
	dhcp_add_binary_option(packet, option);

	return;
}

void dhcp_init_header(struct dhcp_packet *packet, char type)
{
	memset(packet, 0, sizeof(*packet));

	packet->op = BOOTREQUEST;

	switch (type) {
	case DHCPOFFER:
	case DHCPACK:
	case DHCPNAK:
		packet->op = BOOTREPLY;
	}

	packet->htype = 1;
	packet->hlen = 6;
	packet->cookie = htonl(DHCP_MAGIC);
	packet->options[0] = DHCP_END;

	dhcp_add_simple_option(packet, DHCP_MESSAGE_TYPE, type);
}

static gboolean check_vendor(uint8_t  *option_vendor, const char *vendor)
{
	uint8_t vendor_length = sizeof(vendor) - 1;

	if (option_vendor[OPT_LEN - OPT_DATA] != vendor_length)
		return FALSE;

	if (memcmp(option_vendor, vendor, vendor_length) != 0)
		return FALSE;

	return TRUE;
}

static void check_broken_vendor(struct dhcp_packet *packet)
{
	uint8_t *vendor;

	if (packet->op != BOOTREQUEST)
		return;

	vendor = dhcp_get_option(packet, DHCP_VENDOR);
	if (vendor == NULL)
		return;

	if (check_vendor(vendor, "MSFT 98") == TRUE)
		packet->flags |= htons(BROADCAST_FLAG);
}

int dhcp_recv_l3_packet(struct dhcp_packet *packet, int fd)
{
	int n;

	memset(packet, 0, sizeof(*packet));

	n = read(fd, packet, sizeof(*packet));
	if (n < 0)
		return -errno;

	if (packet->cookie != htonl(DHCP_MAGIC))
		return -EPROTO;

	check_broken_vendor(packet);

	return n;
}

/* TODO: Use glib checksum */
uint16_t dhcp_checksum(void *addr, int count)
{
	/*
	 * Compute Internet Checksum for "count" bytes
	 * beginning at location "addr".
	 */
	int32_t sum = 0;
	uint16_t *source = (uint16_t *) addr;

	while (count > 1)  {
		/*  This is the inner loop */
		sum += *source++;
		count -= 2;
	}

	/*  Add left-over byte, if any */
	if (count > 0) {
		/* Make sure that the left-over byte is added correctly both
		 * with little and big endian hosts */
		uint16_t tmp = 0;
		*(uint8_t *) &tmp = *(uint8_t *) source;
		sum += tmp;
	}
	/*  Fold 32-bit sum to 16 bits */
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}

int dhcp_send_raw_packet(struct dhcp_packet *dhcp_pkt,
		uint32_t source_ip, int source_port, uint32_t dest_ip,
			int dest_port, const uint8_t *dest_arp, int ifindex)
{
	struct sockaddr_ll dest;
	struct ip_udp_dhcp_packet packet;
	int fd, n;

	enum {
		IP_UPD_DHCP_SIZE = sizeof(struct ip_udp_dhcp_packet) -
						EXTEND_FOR_BUGGY_SERVERS,
		UPD_DHCP_SIZE = IP_UPD_DHCP_SIZE -
				offsetof(struct ip_udp_dhcp_packet, udp),
	};

	fd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
	if (fd < 0)
		return -errno;

	memset(&dest, 0, sizeof(dest));
	memset(&packet, 0, sizeof(packet));
	packet.data = *dhcp_pkt;

	dest.sll_family = AF_PACKET;
	dest.sll_protocol = htons(ETH_P_IP);
	dest.sll_ifindex = ifindex;
	dest.sll_halen = 6;
	memcpy(dest.sll_addr, dest_arp, 6);
	if (bind(fd, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
		close(fd);
		return -errno;
	}

	packet.ip.protocol = IPPROTO_UDP;
	packet.ip.saddr = source_ip;
	packet.ip.daddr = dest_ip;
	packet.udp.source = htons(source_port);
	packet.udp.dest = htons(dest_port);
	/* size, excluding IP header: */
	packet.udp.len = htons(UPD_DHCP_SIZE);
	/* for UDP checksumming, ip.len is set to UDP packet len */
	packet.ip.tot_len = packet.udp.len;
	packet.udp.check = dhcp_checksum(&packet, IP_UPD_DHCP_SIZE);
	/* but for sending, it is set to IP packet len */
	packet.ip.tot_len = htons(IP_UPD_DHCP_SIZE);
	packet.ip.ihl = sizeof(packet.ip) >> 2;
	packet.ip.version = IPVERSION;
	packet.ip.ttl = IPDEFTTL;
	packet.ip.check = dhcp_checksum(&packet.ip, sizeof(packet.ip));

	/*
	 * Currently we send full-sized DHCP packets (zero padded).
	 * If you need to change this: last byte of the packet is
	 * packet.data.options[dhcp_end_option(packet.data.options)]
	 */
	n = sendto(fd, &packet, IP_UPD_DHCP_SIZE, 0,
			(struct sockaddr *) &dest, sizeof(dest));
	if (n < 0)
		return -errno;

	close(fd);

	return n;
}

int dhcp_send_kernel_packet(struct dhcp_packet *dhcp_pkt,
				uint32_t source_ip, int source_port,
				uint32_t dest_ip, int dest_port)
{
	struct sockaddr_in client;
	int fd, n, opt = 1;

	enum {
		DHCP_SIZE = sizeof(struct dhcp_packet) -
					EXTEND_FOR_BUGGY_SERVERS,
	};

	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0)
		return -errno;

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	memset(&client, 0, sizeof(client));
	client.sin_family = AF_INET;
	client.sin_port = htons(source_port);
	client.sin_addr.s_addr = source_ip;
	if (bind(fd, (struct sockaddr *) &client, sizeof(client)) < 0) {
		close(fd);
		return -errno;
	}

	memset(&client, 0, sizeof(client));
	client.sin_family = AF_INET;
	client.sin_port = htons(dest_port);
	client.sin_addr.s_addr = dest_ip;
	if (connect(fd, (struct sockaddr *) &client, sizeof(client)) < 0) {
		close(fd);
		return -errno;
	}

	n = write(fd, dhcp_pkt, DHCP_SIZE);

	close(fd);

	if (n < 0)
		return -errno;

	return n;
}

int dhcp_l3_socket(int port, const char *interface)
{
	int fd, opt = 1;
	struct sockaddr_in addr;

	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
				interface, strlen(interface) + 1) < 0) {
		close(fd);
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		close(fd);
		return -1;
	}

	return fd;
}

char *get_interface_name(int index)
{
	struct ifreq ifr;
	int sk, err;

	if (index < 0)
		return NULL;

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0) {
		perror("Open socket error");
		return NULL;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = index;

	err = ioctl(sk, SIOCGIFNAME, &ifr);
	if (err < 0) {
		perror("Get interface name error");
		close(sk);
		return NULL;
	}

	close(sk);

	return g_strdup(ifr.ifr_name);
}

gboolean interface_is_up(int index)
{
	int sk, err;
	struct ifreq ifr;
	gboolean ret = FALSE;

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0) {
		perror("Open socket error");
		return FALSE;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = index;

	err = ioctl(sk, SIOCGIFNAME, &ifr);
	if (err < 0) {
		perror("Get interface name error");
		goto done;
	}

	err = ioctl(sk, SIOCGIFFLAGS, &ifr);
	if (err < 0) {
		perror("Get interface flags error");
		goto done;
	}

	if (ifr.ifr_flags & IFF_UP)
		ret = TRUE;

done:
	close(sk);

	return ret;
}
