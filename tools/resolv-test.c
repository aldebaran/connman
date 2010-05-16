/*
 *
 *  Connection Manager
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

#include <unistd.h>
#include <string.h>
#include <resolv.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>

static int do_connect(const char *server)
{
	struct sockaddr_in sin;
	int sk;

	sk = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	//sk = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sk < 0)
		return -1;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(53);
	sin.sin_addr.s_addr = inet_addr(server);

	if (connect(sk, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
		close(sk);
		return -1;
	}

	return sk;
}

int main(int argc, char *argv[])
{
	ns_msg msg;
	ns_rr rr;
	int rcode;
	const char *nameserver;
	unsigned char buf[4096];
	int i, sk, err, len, off = 0;

	if (argc < 2) {
		printf("missing argument\n");
		return 1;
	}

	if (argc > 2)
		nameserver = argv[2];
	else
		nameserver = "127.0.0.1";

	sk = do_connect(nameserver);
	if (sk < 0) {
		printf("Can't connect\n");
		return 1;
	}

	len = res_mkquery(ns_o_query, argv[1], ns_c_in, ns_t_a,
				NULL, 0, NULL, buf + off, sizeof(buf) - off);
	printf("query len: %d\n", len);

	if (off > 0) {
		buf[0] = len >> 8;
		buf[1] = len & 0xff;
	}

	//for (i = 0; i < len + off; i++)
	//	printf("%02x ", buf[i]);
	//printf("\n");

	err = send(sk, buf, len + off, 0);
	printf("send result: %d\n", err);

	len = recv(sk, buf, sizeof(buf), 0);
	printf("answer len: %d\n", len);

	//for (i = 0; i < len + off; i++)
	//	printf("%02x ", buf[i]);
	//printf("\n");

	close(sk);

	ns_initparse(buf + off, len - off, &msg);

	rcode = ns_msg_getflag(msg, ns_f_rcode);

	printf("msg id: 0x%04x\n", ns_msg_id(msg));
	printf("msg rcode: %d\n", rcode);
	printf("msg count: %d\n", ns_msg_count(msg, ns_s_an));

	for (i = 0; i < ns_msg_count(msg, ns_s_an); i++) {
		char result[100];

		ns_parserr(&msg, ns_s_an, i, &rr);

		if (ns_rr_class(rr) != ns_c_in)
			continue;

		if (ns_rr_type(rr) != ns_t_a)
			continue;

		if (ns_rr_rdlen(rr) != NS_INADDRSZ)
			continue;

		inet_ntop(AF_INET, ns_rr_rdata(rr), result, sizeof(result));

		printf("result: %s\n", result);
	}

	return 0;
}
