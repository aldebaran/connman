/*
 *
 *  DHCP client library with GLib integration
 *
 *  Copyright (C) 2009-2010  Intel Corporation. All rights reserved.
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
#include <arpa/inet.h>

#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>

#include <linux/if.h>
#include <linux/filter.h>

#include <glib.h>

#include "gdhcp.h"
#include "common.h"

#define DISCOVER_TIMEOUT 3
#define DISCOVER_RETRIES 5

#define REQUEST_TIMEOUT 3
#define REQUEST_RETRIES 5

typedef enum _listen_mode {
	L_NONE,
	L2,
	L3,
} ListenMode;

typedef enum _dhcp_client_state {
	INIT_SELECTING,
	REQUESTING,
	BOUND,
	RENEWING,
	REBINDING,
	RELEASED,
} ClientState;

struct _GDHCPClient {
	gint ref_count;
	GDHCPType type;
	ClientState state;
	int ifindex;
	char *interface;
	uint8_t mac_address[6];
	uint32_t xid;
	uint32_t server_ip;
	uint32_t requested_ip;
	char *assigned_ip;
	uint32_t lease_seconds;
	ListenMode listen_mode;
	int listener_sockfd;
	uint8_t retry_times;
	uint8_t ack_retry_times;
	guint timeout;
	guint listener_watch;
	GIOChannel *listener_channel;
	GList *require_list;
	GList *request_list;
	GHashTable *code_value_hash;
	GHashTable *send_value_hash;
	GDHCPClientEventFunc lease_available_cb;
	gpointer lease_available_data;
	GDHCPClientEventFunc no_lease_cb;
	gpointer no_lease_data;
	GDHCPClientEventFunc lease_lost_cb;
	gpointer lease_lost_data;
	GDHCPClientEventFunc address_conflict_cb;
	gpointer address_conflict_data;
	GDHCPDebugFunc debug_func;
	gpointer debug_data;
};

static inline void debug(GDHCPClient *client, const char *format, ...)
{
	char str[256];
	va_list ap;

	if (client->debug_func == NULL)
		return;

	va_start(ap, format);

	if (vsnprintf(str, sizeof(str), format, ap) > 0)
		client->debug_func(str, client->debug_data);

	va_end(ap);
}

/* Initialize the packet with the proper defaults */
static void init_packet(GDHCPClient *dhcp_client,
		struct dhcp_packet *packet, char type)
{
	dhcp_init_header(packet, type);

	memcpy(packet->chaddr, dhcp_client->mac_address, 6);
}

static void add_request_options(GDHCPClient *dhcp_client,
				struct dhcp_packet *packet)
{
	int len = 0;
	GList *list;
	uint8_t code;
	int end = dhcp_end_option(packet->options);

	for (list = dhcp_client->request_list; list; list = list->next) {
		code = (uint8_t) GPOINTER_TO_INT(list->data);

		packet->options[end + OPT_DATA + len] = code;
		len++;
	}

	if (len) {
		packet->options[end + OPT_CODE] = DHCP_PARAM_REQ;
		packet->options[end + OPT_LEN] = len;
		packet->options[end + OPT_DATA + len] = DHCP_END;
	}
}

static void add_binary_option(gpointer key, gpointer value, gpointer user_data)
{
	uint8_t *option = value;
	struct dhcp_packet *packet = user_data;

	dhcp_add_binary_option(packet, option);
}

static void add_send_options(GDHCPClient *dhcp_client,
				struct dhcp_packet *packet)
{
	g_hash_table_foreach(dhcp_client->send_value_hash,
				add_binary_option, packet);
}

static int send_discover(GDHCPClient *dhcp_client, uint32_t requested)
{
	struct dhcp_packet packet;

	debug(dhcp_client, "sending DHCP discover request");

	init_packet(dhcp_client, &packet, DHCPDISCOVER);

	packet.xid = dhcp_client->xid;

	if (requested)
		dhcp_add_simple_option(&packet, DHCP_REQUESTED_IP, requested);

	/* Explicitly saying that we want RFC-compliant packets helps
	 * some buggy DHCP servers to NOT send bigger packets */
	dhcp_add_simple_option(&packet, DHCP_MAX_SIZE, htons(576));

	add_request_options(dhcp_client, &packet);

	add_send_options(dhcp_client, &packet);

	return dhcp_send_raw_packet(&packet, INADDR_ANY, CLIENT_PORT,
					INADDR_BROADCAST, SERVER_PORT,
					MAC_BCAST_ADDR, dhcp_client->ifindex);
}

static int send_select(GDHCPClient *dhcp_client)
{
	struct dhcp_packet packet;
	struct in_addr addr;

	debug(dhcp_client, "sending DHCP select request");

	init_packet(dhcp_client, &packet, DHCPREQUEST);

	packet.xid = dhcp_client->xid;

	dhcp_add_simple_option(&packet, DHCP_REQUESTED_IP,
					dhcp_client->requested_ip);
	dhcp_add_simple_option(&packet, DHCP_SERVER_ID, dhcp_client->server_ip);

	add_request_options(dhcp_client, &packet);

	add_send_options(dhcp_client, &packet);

	addr.s_addr = dhcp_client->requested_ip;

	return dhcp_send_raw_packet(&packet, INADDR_ANY, CLIENT_PORT,
					INADDR_BROADCAST, SERVER_PORT,
					MAC_BCAST_ADDR, dhcp_client->ifindex);
}

static int send_renew(GDHCPClient *dhcp_client)
{
	struct dhcp_packet packet;

	debug(dhcp_client, "sending DHCP renew request");

	init_packet(dhcp_client , &packet, DHCPREQUEST);
	packet.xid = dhcp_client->xid;
	packet.ciaddr = dhcp_client->requested_ip;

	add_request_options(dhcp_client, &packet);

	add_send_options(dhcp_client, &packet);

	return dhcp_send_kernel_packet(&packet,
		dhcp_client->requested_ip, CLIENT_PORT,
		dhcp_client->server_ip, SERVER_PORT);
}

static int send_rebound(GDHCPClient *dhcp_client)
{
	struct dhcp_packet packet;

	debug(dhcp_client, "sending DHCP rebound request");

	init_packet(dhcp_client , &packet, DHCPREQUEST);
	packet.xid = dhcp_client->xid;
	packet.ciaddr = dhcp_client->requested_ip;

	add_request_options(dhcp_client, &packet);

	add_send_options(dhcp_client, &packet);

	return dhcp_send_raw_packet(&packet, INADDR_ANY, CLIENT_PORT,
					INADDR_BROADCAST, SERVER_PORT,
					MAC_BCAST_ADDR, dhcp_client->ifindex);
}

static int send_release(GDHCPClient *dhcp_client,
			uint32_t server, uint32_t ciaddr)
{
	struct dhcp_packet packet;

	debug(dhcp_client, "sending DHCP release request");

	init_packet(dhcp_client, &packet, DHCPRELEASE);
	packet.xid = rand();
	packet.ciaddr = ciaddr;

	dhcp_add_simple_option(&packet, DHCP_SERVER_ID, server);

	return dhcp_send_kernel_packet(&packet, ciaddr, CLIENT_PORT,
						server, SERVER_PORT);
}

static gboolean interface_is_up(int index)
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

static char *get_interface_name(int index)
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

static void get_interface_mac_address(int index, uint8_t *mac_address)
{
	struct ifreq ifr;
	int sk, err;

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0) {
		perror("Open socket error");
		return;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = index;

	err = ioctl(sk, SIOCGIFNAME, &ifr);
	if (err < 0) {
		perror("Get interface name error");
		goto done;
	}

	err = ioctl(sk, SIOCGIFHWADDR, &ifr);
	if (err < 0) {
		perror("Get mac address error");
		goto done;
	}

	memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);

done:
	close(sk);
}

static void remove_value(gpointer data, gpointer user_data)
{
	char *value = data;
	g_free(value);
}

static void remove_option_value(gpointer data)
{
	GList *option_value = data;

	g_list_foreach(option_value, remove_value, NULL);
}

GDHCPClient *g_dhcp_client_new(GDHCPType type,
			int ifindex, GDHCPClientError *error)
{
	GDHCPClient *dhcp_client;

	if (ifindex < 0) {
		*error = G_DHCP_CLIENT_ERROR_INVALID_INDEX;
		return NULL;
	}

	dhcp_client = g_try_new0(GDHCPClient, 1);
	if (dhcp_client == NULL) {
		*error = G_DHCP_CLIENT_ERROR_NOMEM;
		return NULL;
	}

	dhcp_client->interface = get_interface_name(ifindex);
	if (dhcp_client->interface == NULL) {
		*error = G_DHCP_CLIENT_ERROR_INTERFACE_UNAVAILABLE;
		goto error;
	}

	if (interface_is_up(ifindex) == FALSE) {
		*error = G_DHCP_CLIENT_ERROR_INTERFACE_DOWN;
		goto error;
	}

	get_interface_mac_address(ifindex, dhcp_client->mac_address);

	dhcp_client->listener_sockfd = -1;
	dhcp_client->listener_channel = NULL;
	dhcp_client->listen_mode = L_NONE;
	dhcp_client->ref_count = 1;
	dhcp_client->type = type;
	dhcp_client->ifindex = ifindex;
	dhcp_client->lease_available_cb = NULL;
	dhcp_client->no_lease_cb = NULL;
	dhcp_client->lease_lost_cb = NULL;
	dhcp_client->address_conflict_cb = NULL;
	dhcp_client->listener_watch = 0;
	dhcp_client->retry_times = 0;
	dhcp_client->ack_retry_times = 0;
	dhcp_client->code_value_hash = g_hash_table_new_full(g_direct_hash,
				g_direct_equal, NULL, remove_option_value);
	dhcp_client->send_value_hash = g_hash_table_new_full(g_direct_hash,
				g_direct_equal, NULL, g_free);
	dhcp_client->request_list = NULL;
	dhcp_client->require_list = NULL;

	*error = G_DHCP_CLIENT_ERROR_NONE;

	return dhcp_client;

error:
	g_free(dhcp_client->interface);
	g_free(dhcp_client);
	return NULL;
}

#define SERVER_AND_CLIENT_PORTS  ((67 << 16) + 68)

static int dhcp_l2_socket(int ifindex)
{
	int fd;
	struct sockaddr_ll sock;

	/*
	 * Comment:
	 *
	 *	I've selected not to see LL header, so BPF doesn't see it, too.
	 *	The filter may also pass non-IP and non-ARP packets, but we do
	 *	a more complete check when receiving the message in userspace.
	 *
	 * and filter shamelessly stolen from:
	 *
	 *	http://www.flamewarmaster.de/software/dhcpclient/
	 *
	 * There are a few other interesting ideas on that page (look under
	 * "Motivation").  Use of netlink events is most interesting.  Think
	 * of various network servers listening for events and reconfiguring.
	 * That would obsolete sending HUP signals and/or make use of restarts.
	 *
	 * Copyright: 2006, 2007 Stefan Rompf <sux@loplof.de>.
	 * License: GPL v2.
	 *
	 * TODO: make conditional?
	 */
	static const struct sock_filter filter_instr[] = {
		/* check for udp */
		BPF_STMT(BPF_LD|BPF_B|BPF_ABS, 9),
		/* L5, L1, is UDP? */
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, IPPROTO_UDP, 2, 0),
		/* ugly check for arp on ethernet-like and IPv4 */
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 2), /* L1: */
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0x08000604, 3, 4),/* L3, L4 */
		/* skip IP header */
		BPF_STMT(BPF_LDX|BPF_B|BPF_MSH, 0), /* L5: */
		/* check udp source and destination ports */
		BPF_STMT(BPF_LD|BPF_W|BPF_IND, 0),
		/* L3, L4 */
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, SERVER_AND_CLIENT_PORTS, 0, 1),
		/* returns */
		BPF_STMT(BPF_RET|BPF_K, 0x0fffffff), /* L3: pass */
		BPF_STMT(BPF_RET|BPF_K, 0), /* L4: reject */
	};

	static const struct sock_fprog filter_prog = {
		.len = sizeof(filter_instr) / sizeof(filter_instr[0]),
		/* casting const away: */
		.filter = (struct sock_filter *) filter_instr,
	};

	fd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
	if (fd < 0)
		return fd;

	if (SERVER_PORT == 67 && CLIENT_PORT == 68)
		/* Use only if standard ports are in use */
		setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &filter_prog,
							sizeof(filter_prog));

	sock.sll_family = AF_PACKET;
	sock.sll_protocol = htons(ETH_P_IP);
	sock.sll_ifindex = ifindex;

	if (bind(fd, (struct sockaddr *) &sock, sizeof(sock)) != 0) {
		close(fd);
		return -errno;
	}

	return fd;
}

static gboolean sanity_check(struct ip_udp_dhcp_packet *packet, int bytes)
{
	if (packet->ip.protocol != IPPROTO_UDP)
		return FALSE;

	if (packet->ip.version != IPVERSION)
		return FALSE;

	if (packet->ip.ihl != sizeof(packet->ip) >> 2)
		return FALSE;

	if (packet->udp.dest != htons(CLIENT_PORT))
		return FALSE;

	if (ntohs(packet->udp.len) != (uint16_t)(bytes - sizeof(packet->ip)))
		return FALSE;

	return TRUE;
}

static int dhcp_recv_l2_packet(struct dhcp_packet *dhcp_pkt, int fd)
{
	int bytes;
	struct ip_udp_dhcp_packet packet;
	uint16_t check;

	memset(&packet, 0, sizeof(packet));

	bytes = read(fd, &packet, sizeof(packet));
	if (bytes < 0)
		return -1;

	if (bytes < (int) (sizeof(packet.ip) + sizeof(packet.udp)))
		return -1;

	if (bytes < ntohs(packet.ip.tot_len))
		/* packet is bigger than sizeof(packet), we did partial read */
		return -1;

	/* ignore any extra garbage bytes */
	bytes = ntohs(packet.ip.tot_len);

	if (sanity_check(&packet, bytes) == FALSE)
		return -1;

	check = packet.ip.check;
	packet.ip.check = 0;
	if (check != dhcp_checksum(&packet.ip, sizeof(packet.ip)))
		return -1;

	/* verify UDP checksum. IP header has to be modified for this */
	memset(&packet.ip, 0, offsetof(struct iphdr, protocol));
	/* ip.xx fields which are not memset: protocol, check, saddr, daddr */
	packet.ip.tot_len = packet.udp.len; /* yes, this is needed */
	check = packet.udp.check;
	packet.udp.check = 0;
	if (check && check != dhcp_checksum(&packet, bytes))
		return -1;

	memcpy(dhcp_pkt, &packet.data, bytes - (sizeof(packet.ip) +
							sizeof(packet.udp)));

	if (dhcp_pkt->cookie != htonl(DHCP_MAGIC))
		return -1;

	return bytes - (sizeof(packet.ip) + sizeof(packet.udp));
}

static gboolean check_package_owner(GDHCPClient *dhcp_client,
					struct dhcp_packet *packet)
{
	if (packet->xid != dhcp_client->xid)
		return FALSE;

	if (packet->hlen != 6)
		return FALSE;

	if (memcmp(packet->chaddr, dhcp_client->mac_address, 6))
		return FALSE;

	return TRUE;
}

static void start_request(GDHCPClient *dhcp_client);

static gboolean request_timeout(gpointer user_data)
{
	GDHCPClient *dhcp_client = user_data;

	debug(dhcp_client, "request timeout (retries %d)",
					dhcp_client->retry_times);

	dhcp_client->retry_times++;

	start_request(dhcp_client);

	return FALSE;
}

static gboolean listener_event(GIOChannel *channel, GIOCondition condition,
							gpointer user_data);

static int switch_listening_mode(GDHCPClient *dhcp_client,
					ListenMode listen_mode)
{
	GIOChannel *listener_channel;
	int listener_sockfd;

	debug(dhcp_client, "switch listening mode (%d ==> %d)",
				dhcp_client->listen_mode, listen_mode);

	if (dhcp_client->listen_mode == listen_mode)
		return 0;

	if (dhcp_client->listen_mode != L_NONE) {
		g_source_remove(dhcp_client->listener_watch);
		dhcp_client->listener_channel = NULL;
		dhcp_client->listen_mode = L_NONE;
		dhcp_client->listener_sockfd = -1;
		dhcp_client->listener_watch = 0;
	}

	if (listen_mode == L_NONE)
		return 0;

	if (listen_mode == L2)
		listener_sockfd = dhcp_l2_socket(dhcp_client->ifindex);
	else if (listen_mode == L3)
		listener_sockfd = dhcp_l3_socket(CLIENT_PORT,
						dhcp_client->interface);
	else
		return -EIO;

	if (listener_sockfd < 0)
		return -EIO;

	listener_channel = g_io_channel_unix_new(listener_sockfd);
	if (listener_channel == NULL) {
		/* Failed to create listener channel */
		close(listener_sockfd);
		return -EIO;
	}

	dhcp_client->listen_mode = listen_mode;
	dhcp_client->listener_sockfd = listener_sockfd;
	dhcp_client->listener_channel = listener_channel;

	g_io_channel_set_close_on_unref(listener_channel, TRUE);
	dhcp_client->listener_watch =
			g_io_add_watch_full(listener_channel,
						G_PRIORITY_HIGH, G_IO_IN,
						listener_event, dhcp_client,
								NULL);
	g_io_channel_unref(dhcp_client->listener_channel);

	return 0;
}

static void start_request(GDHCPClient *dhcp_client)
{
	debug(dhcp_client, "start request (retries %d)",
					dhcp_client->retry_times);

	if (dhcp_client->retry_times == REQUEST_RETRIES) {
		dhcp_client->state = INIT_SELECTING;

		if (dhcp_client->no_lease_cb != NULL)
			dhcp_client->no_lease_cb(dhcp_client,
					dhcp_client->no_lease_data);

		return;
	}

	if (dhcp_client->retry_times == 0) {
		dhcp_client->state = REQUESTING;
		switch_listening_mode(dhcp_client, L2);
	}

	send_select(dhcp_client);

	dhcp_client->timeout = g_timeout_add_seconds_full(G_PRIORITY_HIGH,
							REQUEST_TIMEOUT,
							request_timeout,
							dhcp_client,
							NULL);
}

static uint32_t get_lease(struct dhcp_packet *packet)
{
	uint8_t *option_u8;
	uint32_t lease_seconds;

	option_u8 = dhcp_get_option(packet, DHCP_LEASE_TIME);
	if (option_u8 == NULL)
		return 3600;

	lease_seconds = dhcp_get_unaligned((uint32_t *) option_u8);
	lease_seconds = ntohl(lease_seconds);
	/* paranoia: must not be prone to overflows */
	lease_seconds &= 0x0fffffff;
	if (lease_seconds < 10)
		lease_seconds = 10;

	return lease_seconds;
}

static void restart_dhcp(GDHCPClient *dhcp_client, int retry_times)
{
	debug(dhcp_client, "restart DHCP (retries %d)", retry_times);

	if (dhcp_client->timeout > 0) {
		g_source_remove(dhcp_client->timeout);
		dhcp_client->timeout = 0;
	}

	dhcp_client->retry_times = retry_times;
	dhcp_client->requested_ip = 0;
	switch_listening_mode(dhcp_client, L2);

	g_dhcp_client_start(dhcp_client);
}

static gboolean start_rebound_timeout(gpointer user_data)
{
	GDHCPClient *dhcp_client = user_data;

	debug(dhcp_client, "start rebound timeout");

	switch_listening_mode(dhcp_client, L2);

	dhcp_client->lease_seconds >>= 1;

	/* We need to have enough time to receive ACK package*/
	if (dhcp_client->lease_seconds <= 6) {

		/* ip need to be cleared */
		if (dhcp_client->lease_lost_cb != NULL)
			dhcp_client->lease_lost_cb(dhcp_client,
					dhcp_client->lease_lost_data);

		restart_dhcp(dhcp_client, 0);
	} else {
		send_rebound(dhcp_client);

		dhcp_client->timeout =
				g_timeout_add_seconds_full(G_PRIORITY_HIGH,
						dhcp_client->lease_seconds >> 1,
							start_rebound_timeout,
								dhcp_client,
								NULL);
	}

	return FALSE;
}

static void start_rebound(GDHCPClient *dhcp_client)
{
	debug(dhcp_client, "start rebound");

	dhcp_client->state = REBINDING;

	dhcp_client->timeout = g_timeout_add_seconds_full(G_PRIORITY_HIGH,
						dhcp_client->lease_seconds >> 1,
							start_rebound_timeout,
								dhcp_client,
								NULL);
}

static gboolean start_renew_timeout(gpointer user_data)
{
	GDHCPClient *dhcp_client = user_data;

	debug(dhcp_client, "start renew timeout");

	dhcp_client->state = RENEWING;

	dhcp_client->lease_seconds >>= 1;

	switch_listening_mode(dhcp_client, L3);
	if (dhcp_client->lease_seconds <= 60)
		start_rebound(dhcp_client);
	else {
		send_renew(dhcp_client);

		dhcp_client->timeout =
				g_timeout_add_seconds_full(G_PRIORITY_HIGH,
						dhcp_client->lease_seconds >> 1,
							start_renew_timeout,
								dhcp_client,
								NULL);
	}

	return FALSE;
}

static void start_bound(GDHCPClient *dhcp_client)
{
	debug(dhcp_client, "start bound");

	dhcp_client->state = BOUND;

	dhcp_client->timeout = g_timeout_add_seconds_full(G_PRIORITY_HIGH,
					dhcp_client->lease_seconds >> 1,
					start_renew_timeout, dhcp_client,
							NULL);
}

static gboolean restart_dhcp_timeout(gpointer user_data)
{
	GDHCPClient *dhcp_client = user_data;

	debug(dhcp_client, "restart DHCP timeout");

	dhcp_client->ack_retry_times++;

	restart_dhcp(dhcp_client, dhcp_client->ack_retry_times);

	return FALSE;
}

static char *get_ip(uint32_t ip)
{
	struct in_addr addr;

	addr.s_addr = ip;

	return g_strdup(inet_ntoa(addr));
}

/* get a rough idea of how long an option will be */
static const uint8_t len_of_option_as_string[] = {
	[OPTION_IP] = sizeof("255.255.255.255 "),
	[OPTION_STRING] = 1,
	[OPTION_U8] = sizeof("255 "),
	[OPTION_U16] = sizeof("65535 "),
	[OPTION_U32] = sizeof("4294967295 "),
};

static int sprint_nip(char *dest, const char *pre, const uint8_t *ip)
{
	return sprintf(dest, "%s%u.%u.%u.%u", pre, ip[0], ip[1], ip[2], ip[3]);
}

/* Create "opt_value1 option_value2 ..." string */
static char *malloc_option_value_string(uint8_t *option, GDHCPOptionType type)
{
	unsigned upper_length;
	int len, optlen;
	char *dest, *ret;

	len = option[OPT_LEN - OPT_DATA];
	type &= OPTION_TYPE_MASK;
	optlen = dhcp_option_lengths[type];
	if (optlen == 0)
		return NULL;
	upper_length = len_of_option_as_string[type] *
			((unsigned)len / (unsigned)optlen);
	dest = ret = malloc(upper_length + 1);
	if (ret == NULL)
		return NULL;

	while (len >= optlen) {
		switch (type) {
		case OPTION_IP:
			dest += sprint_nip(dest, "", option);
			break;
		case OPTION_U16: {
			uint16_t val_u16 = dhcp_get_unaligned(
						(uint16_t *) option);
			dest += sprintf(dest, "%u", ntohs(val_u16));
			break;
		}
		case OPTION_U32: {
			uint32_t val_u32 = dhcp_get_unaligned(
						(uint32_t *) option);
			dest += sprintf(dest, type == OPTION_U32 ? "%lu" :
					"%ld", (unsigned long) ntohl(val_u32));
			break;
		}
		case OPTION_STRING:
			memcpy(dest, option, len);
			dest[len] = '\0';
			return ret;
		default:
			break;
		}
		option += optlen;
		len -= optlen;
		if (len <= 0)
			break;
		*dest++ = ' ';
		*dest = '\0';
	}

	return ret;
}

static GList *get_option_value_list(char *value)
{
	char *pos = value;
	GList *list = NULL;

	if (pos == NULL)
		return NULL;

	while ((pos = strchr(pos, ' ')) != NULL) {
		*pos = '\0';

		list = g_list_append(list, g_strdup(value));

		value = ++pos;
	}

	list = g_list_append(list, g_strdup(value));

	return list;
}

static void get_request(GDHCPClient *dhcp_client, struct dhcp_packet *packet)
{
	GDHCPOptionType type;
	GList *list, *value_list;
	char *option_value;
	uint8_t *option;
	uint8_t code;

	for (list = dhcp_client->request_list; list; list = list->next) {
		code = (uint8_t) GPOINTER_TO_INT(list->data);

		option = dhcp_get_option(packet, code);
		if (option == NULL) {
			g_hash_table_remove(dhcp_client->code_value_hash,
						GINT_TO_POINTER((int) code));
			continue;
		}

		type =  dhcp_get_code_type(code);

		option_value = malloc_option_value_string(option, type);
		if (option_value == NULL)
			g_hash_table_remove(dhcp_client->code_value_hash,
						GINT_TO_POINTER((int) code));

		value_list = get_option_value_list(option_value);

		g_free(option_value);

		if (value_list == NULL)
			g_hash_table_remove(dhcp_client->code_value_hash,
						GINT_TO_POINTER((int) code));
		else
			g_hash_table_insert(dhcp_client->code_value_hash,
				GINT_TO_POINTER((int) code), value_list);
	}
}

static gboolean listener_event(GIOChannel *channel, GIOCondition condition,
							gpointer user_data)
{
	GDHCPClient *dhcp_client = user_data;
	struct dhcp_packet packet;
	uint8_t *message_type, *option_u8;
	int re;

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		dhcp_client->listener_watch = 0;
		return FALSE;
	}

	if (dhcp_client->listen_mode == L_NONE)
		return FALSE;

	if (dhcp_client->listen_mode == L2)
		re = dhcp_recv_l2_packet(&packet, dhcp_client->listener_sockfd);
	else if (dhcp_client->listen_mode == L3)
		re = dhcp_recv_l3_packet(&packet, dhcp_client->listener_sockfd);
	else
		re = -EIO;

	if (re < 0)
		return TRUE;

	if (check_package_owner(dhcp_client, &packet) == FALSE)
		return TRUE;

	message_type = dhcp_get_option(&packet, DHCP_MESSAGE_TYPE);
	if (message_type == NULL)
		/* No message type option, ignore pakcage */
		return TRUE;

	debug(dhcp_client, "received DHCP packet (current state %d)",
							dhcp_client->state);

	switch (dhcp_client->state) {
	case INIT_SELECTING:
		if (*message_type != DHCPOFFER)
			return TRUE;

		g_source_remove(dhcp_client->timeout);
		dhcp_client->timeout = 0;
		dhcp_client->retry_times = 0;

		option_u8 = dhcp_get_option(&packet, DHCP_SERVER_ID);
		dhcp_client->server_ip =
				dhcp_get_unaligned((uint32_t *) option_u8);
		dhcp_client->requested_ip = packet.yiaddr;

		dhcp_client->state = REQUESTING;

		start_request(dhcp_client);

		return TRUE;
	case REQUESTING:
	case RENEWING:
	case REBINDING:
		if (*message_type == DHCPACK) {
			dhcp_client->retry_times = 0;

			if (dhcp_client->timeout > 0)
				g_source_remove(dhcp_client->timeout);
			dhcp_client->timeout = 0;

			dhcp_client->lease_seconds = get_lease(&packet);

			get_request(dhcp_client, &packet);

			switch_listening_mode(dhcp_client, L_NONE);

			g_free(dhcp_client->assigned_ip);
			dhcp_client->assigned_ip = get_ip(packet.yiaddr);

			/* Address should be set up here */
			if (dhcp_client->lease_available_cb != NULL)
				dhcp_client->lease_available_cb(dhcp_client,
					dhcp_client->lease_available_data);

			start_bound(dhcp_client);
		} else if (*message_type == DHCPNAK) {
			dhcp_client->retry_times = 0;

			if (dhcp_client->timeout > 0)
				g_source_remove(dhcp_client->timeout);

			dhcp_client->timeout = g_timeout_add_seconds_full(
							G_PRIORITY_HIGH, 3,
							restart_dhcp_timeout,
							dhcp_client,
							NULL);
		}

		break;
	default:
		break;
	}

	debug(dhcp_client, "processed DHCP packet (new state %d)",
							dhcp_client->state);

	return TRUE;
}

static gboolean discover_timeout(gpointer user_data)
{
	GDHCPClient *dhcp_client = user_data;

	dhcp_client->retry_times++;

	g_dhcp_client_start(dhcp_client);

	return FALSE;
}

int g_dhcp_client_start(GDHCPClient *dhcp_client)
{
	int re;

	if (dhcp_client->retry_times == DISCOVER_RETRIES) {
		if (dhcp_client->no_lease_cb != NULL)
			dhcp_client->no_lease_cb(dhcp_client,
					dhcp_client->no_lease_data);

		return 0;
	}

	if (dhcp_client->retry_times == 0) {
		g_free(dhcp_client->assigned_ip);
		dhcp_client->assigned_ip = NULL;

		dhcp_client->state = INIT_SELECTING;
		re = switch_listening_mode(dhcp_client, L2);
		if (re != 0)
			return re;

		dhcp_client->xid = rand();
	}

	send_discover(dhcp_client, 0);

	dhcp_client->timeout = g_timeout_add_seconds_full(G_PRIORITY_HIGH,
							DISCOVER_TIMEOUT,
							discover_timeout,
							dhcp_client,
							NULL);
	return 0;
}

void g_dhcp_client_stop(GDHCPClient *dhcp_client)
{
	switch_listening_mode(dhcp_client, L_NONE);

	if (dhcp_client->state == BOUND ||
			dhcp_client->state == RENEWING ||
				dhcp_client->state == REBINDING)
		send_release(dhcp_client, dhcp_client->server_ip,
					dhcp_client->requested_ip);

	if (dhcp_client->timeout > 0) {
		g_source_remove(dhcp_client->timeout);
		dhcp_client->timeout = 0;
	}

	if (dhcp_client->listener_watch > 0) {
		g_source_remove(dhcp_client->listener_watch);
		dhcp_client->listener_watch = 0;
	}

	dhcp_client->listener_channel = NULL;

	dhcp_client->retry_times = 0;
	dhcp_client->ack_retry_times = 0;

	dhcp_client->requested_ip = 0;
	dhcp_client->state = RELEASED;
	dhcp_client->lease_seconds = 0;
}

GList *g_dhcp_client_get_option(GDHCPClient *dhcp_client,
					unsigned char option_code)
{
	return g_hash_table_lookup(dhcp_client->code_value_hash,
					GINT_TO_POINTER((int) option_code));
}

void g_dhcp_client_register_event(GDHCPClient *dhcp_client,
					GDHCPClientEvent event,
					GDHCPClientEventFunc func,
							gpointer data)
{
	switch (event) {
	case G_DHCP_CLIENT_EVENT_LEASE_AVAILABLE:
		dhcp_client->lease_available_cb = func;
		dhcp_client->lease_available_data = data;
		return;
	case G_DHCP_CLIENT_EVENT_NO_LEASE:
		dhcp_client->no_lease_cb = func;
		dhcp_client->no_lease_data = data;
		return;
	case G_DHCP_CLIENT_EVENT_LEASE_LOST:
		dhcp_client->lease_lost_cb = func;
		dhcp_client->lease_lost_data = data;
		return;
	case G_DHCP_CLIENT_EVENT_ADDRESS_CONFLICT:
		dhcp_client->address_conflict_cb = func;
		dhcp_client->address_conflict_data = data;
		return;
	}
}

int g_dhcp_client_get_index(GDHCPClient *dhcp_client)
{
	return dhcp_client->ifindex;
}

char *g_dhcp_client_get_address(GDHCPClient *dhcp_client)
{
	return g_strdup(dhcp_client->assigned_ip);
}

GDHCPClientError g_dhcp_client_set_request(GDHCPClient *dhcp_client,
						unsigned char option_code)
{
	if (g_list_find(dhcp_client->request_list,
			GINT_TO_POINTER((int) option_code)) == NULL)
		dhcp_client->request_list = g_list_prepend(
					dhcp_client->request_list,
					(GINT_TO_POINTER((int) option_code)));

	return G_DHCP_CLIENT_ERROR_NONE;
}

static uint8_t *alloc_dhcp_option(int code, const char *str, int extra)
{
	uint8_t *storage;
	int len = strnlen(str, 255);

	storage = malloc(len + extra + OPT_DATA);
	storage[OPT_CODE] = code;
	storage[OPT_LEN] = len + extra;
	memcpy(storage + extra + OPT_DATA, str, len);

	return storage;
}

/* Now only support send hostname */
GDHCPClientError g_dhcp_client_set_send(GDHCPClient *dhcp_client,
		unsigned char option_code, const char *option_value)
{
	uint8_t *binary_option;

	if (option_code == G_DHCP_HOST_NAME && option_value != NULL) {
		binary_option = alloc_dhcp_option(option_code,
							option_value, 0);

		g_hash_table_insert(dhcp_client->send_value_hash,
			GINT_TO_POINTER((int) option_code), binary_option);
	}

	return G_DHCP_CLIENT_ERROR_NONE;
}

GDHCPClient *g_dhcp_client_ref(GDHCPClient *dhcp_client)
{
	if (dhcp_client == NULL)
		return NULL;

	g_atomic_int_inc(&dhcp_client->ref_count);

	return dhcp_client;
}

void g_dhcp_client_unref(GDHCPClient *dhcp_client)
{
	if (dhcp_client == NULL)
		return;

	if (g_atomic_int_dec_and_test(&dhcp_client->ref_count) == FALSE)
		return;

	g_dhcp_client_stop(dhcp_client);

	g_free(dhcp_client->interface);
	g_free(dhcp_client->assigned_ip);

	g_list_free(dhcp_client->request_list);
	g_list_free(dhcp_client->require_list);

	g_hash_table_destroy(dhcp_client->code_value_hash);
	g_hash_table_destroy(dhcp_client->send_value_hash);

	g_free(dhcp_client);
}

void g_dhcp_client_set_debug(GDHCPClient *dhcp_client,
				GDHCPDebugFunc func, gpointer user_data)
{
	if (dhcp_client == NULL)
		return;

	dhcp_client->debug_func = func;
	dhcp_client->debug_data = user_data;
}
