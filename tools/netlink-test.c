/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2013  BWM CarIT GmbH.
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

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/genetlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <net/if.h>

#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <errno.h>

#include <glib.h>

#include "../src/shared/netlink.h"
#include "../src/shared/nfacct.h"
#include "../src/shared/nfnetlink_acct_copy.h"

#define NFGEN_DATA(nlh) ((void *)((char *)(nlh) +			\
				NLMSG_ALIGN(sizeof(struct nfgenmsg))))
#define NLA_DATA(nla)  ((void *)((char*)(nla) + NLA_HDRLEN))
#define NLA_OK(nla,len) ((len) >= (int)sizeof(struct nlattr) &&		\
				(nla)->nla_len >= sizeof(struct nlattr) && \
				(nla)->nla_len <= (len))
#define NLA_NEXT(nla,attrlen) ((attrlen) -= NLA_ALIGN((nla)->nla_len),	\
				(struct nlattr*)(((char*)(nla)) +       \
						NLA_ALIGN((nla)->nla_len)))

static GMainLoop *mainloop;

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	printf("%s%s\n", prefix, str);
}

static void getlink_callback(unsigned int error, uint16_t type, const void *data,
						uint32_t len, void *user_data)
{
	const struct ifinfomsg *ifi = data;
	struct rtattr *rta;
	int bytes;
	char ifname[IF_NAMESIZE];
	uint32_t index, flags;

	g_assert_cmpuint(error, ==, 0);

	bytes = len - NLMSG_ALIGN(sizeof(struct ifinfomsg));

	memset(ifname, 0, sizeof(ifname));

	index = ifi->ifi_index;
	flags = ifi->ifi_flags;

	for (rta = IFLA_RTA(ifi); RTA_OK(rta, bytes);
					rta = RTA_NEXT(rta, bytes)) {
		switch (rta->rta_type) {
		case IFLA_IFNAME:
			if (RTA_PAYLOAD(rta) <= IF_NAMESIZE)
				strcpy(ifname, RTA_DATA(rta));
			break;
		}
	}

	printf("index=%d flags=0x%08x name=%s\n", index, flags, ifname);

	g_main_loop_quit(mainloop);
}

static void test_case_1(void)
{
	struct netlink_info *netlink;
	struct ifinfomsg msg;

	netlink = netlink_new(NETLINK_ROUTE);

	printf("\n");
	netlink_set_debug(netlink, do_debug, "[NETLINK] ", NULL);

	memset(&msg, 0, sizeof(msg));

	netlink_send(netlink, RTM_GETLINK, NLM_F_DUMP, &msg, sizeof(msg),
						getlink_callback, NULL, NULL);

	mainloop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(mainloop);
	g_main_loop_unref(mainloop);

	netlink_destroy(netlink);
}

static void test_nfacct_dump_callback(unsigned int error, uint16_t type,
				const void *data, uint32_t len, void *user_data)
{
	const struct nfgenmsg *msg = data;
	const struct nlattr *attr;
	uint64_t packets = 0 , bytes = 0;
	char *name = NULL;
	int attrlen;

	if (error == EINVAL)
		printf("nfnetlink_acct not loaded\n");

	g_assert_cmpuint(error, ==, 0);

	attrlen = len - NLMSG_ALIGN(sizeof(struct nfgenmsg));

	for (attr = NFGEN_DATA(msg); NLA_OK(attr, attrlen);
		     attr = NLA_NEXT(attr, attrlen)) {
		switch (attr->nla_type) {
		case NFACCT_NAME:
			name = NLA_DATA(attr);
			break;
		case NFACCT_PKTS:
			packets = be64toh(*(uint64_t *) NLA_DATA(attr));
			break;
		case NFACCT_BYTES:
			bytes = be64toh(*(uint64_t *) NLA_DATA(attr));
			break;
		case NFACCT_USE:
			break;
		}
	}

	printf("%s packets %" PRIu64 " bytes %" PRIu64 "\n",
		name, packets, bytes);

	g_main_loop_quit(mainloop);
}

static void test_nfacct_callback(unsigned int error, uint16_t type,
				const void *data, uint32_t len, void *user_data)
{
	if (error == EINVAL)
		printf("nfnetlink_acct not loaded\n");

	g_assert_cmpuint(error, ==, 0);
}

static void append_attr_str(struct nlattr *attr,
                                uint16_t type, size_t size, const char *str)
{
	char *dst;

	attr->nla_len = NLA_HDRLEN + size;
	attr->nla_type = NFACCT_NAME;

	dst = (char *)NLA_DATA(attr);
	strncpy(dst, str, size);
	dst[size - 1] = '\0';
}

static void test_nfacct_new(struct netlink_info *netlink, const char *name)
{
	struct nfgenmsg *hdr;
	size_t len, name_len;

	name_len = strlen(name) + 1;
	len = NLMSG_ALIGN(sizeof(struct nfgenmsg)) +
		NLA_ALIGN(sizeof(struct nlattr)) +
		name_len;

	hdr = g_malloc0(len);

	hdr->nfgen_family = AF_UNSPEC;
	hdr->version = NFNETLINK_V0;
	hdr->res_id = 0;

	append_attr_str(NLA_DATA(hdr), NFACCT_NAME, name_len, name);

	netlink_send(netlink,
			NFNL_SUBSYS_ACCT << 8 | NFNL_MSG_ACCT_NEW,
			NLM_F_CREATE | NLM_F_ACK, hdr, len,
			test_nfacct_callback, NULL, NULL);

	g_free(hdr);
}

static void test_nfacct_del(struct netlink_info *netlink, const char *name)
{
	struct nfgenmsg *hdr;
	size_t len, name_len;

	name_len = strlen(name) + 1;
	len = NLMSG_ALIGN(sizeof(struct nfgenmsg)) +
		NLA_ALIGN(sizeof(struct nlattr)) +
		name_len;

	hdr = g_malloc0(len);

	hdr->nfgen_family = AF_UNSPEC;
	hdr->version = NFNETLINK_V0;
	hdr->res_id = 0;

	append_attr_str(NLA_DATA(hdr), NFACCT_NAME, name_len, name);

	netlink_send(netlink,
			NFNL_SUBSYS_ACCT << 8 | NFNL_MSG_ACCT_DEL,
			NLM_F_ACK, hdr, len,
			test_nfacct_callback, NULL, NULL);

	g_free(hdr);
}

static void test_nfacct_dump(struct netlink_info *netlink)
{
	struct nfgenmsg hdr;

	memset(&hdr, 0, sizeof(hdr));
	hdr.nfgen_family = AF_UNSPEC;
	hdr.version = NFNETLINK_V0;
	hdr.res_id = 0;

	netlink_send(netlink,
			NFNL_SUBSYS_ACCT << 8 | NFNL_MSG_ACCT_GET,
			NLM_F_DUMP , &hdr, sizeof(hdr),
			test_nfacct_dump_callback, NULL, NULL);
}

static void test_case_2(void)
{
	struct netlink_info *netlink;

	netlink = netlink_new(NETLINK_NETFILTER);

	printf("\n");
	netlink_set_debug(netlink, do_debug, "[NETLINK] ", NULL);

	test_nfacct_new(netlink, "session-foo");
	test_nfacct_dump(netlink);
	test_nfacct_del(netlink, "session-foo");

	mainloop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(mainloop);
	g_main_loop_unref(mainloop);

	netlink_destroy(netlink);
}


static void nfacct_add_callback(unsigned int error, void *user_data)
{
	const char *name = user_data;

	if (error == EINVAL)
		printf("nfnetlink_acct not loaded\n");

	g_assert_cmpuint(error, ==, 0);

	printf("nfacct_add: error %d name %s\n", error, name);
}

static void nfacct_get_callback(unsigned int error, const char *name,
				uint64_t packets, uint64_t bytes,
				void *user_data)
{
	const char *expected_name = user_data;

	if (error == EINVAL)
		printf("nfnetlink_acct not loaded\n");

	g_assert_cmpuint(error, ==, 0);

	if (!name) {
		/* end of dump */
		return;
	}

	printf("nfacct_get: error %d name %s packets %" PRIu64
		" bytes %" PRIu64 "\n", error, name, packets, bytes);

	g_assert_cmpstr(expected_name, ==,  name);
	g_assert_cmpuint(packets, ==, 0);
	g_assert_cmpuint(bytes, ==, 0);
}

static void nfacct_dump_callback(unsigned int error, const char *name,
					uint64_t packets, uint64_t bytes,
					void *user_data)
{
	const char *expected_name = user_data;

	if (error == EINVAL)
		printf("nfnetlink_acct not loaded\n");

	g_assert_cmpuint(error, ==, 0);

	if (!name) {
		/* end of dump */
		return;
	}

	printf("nfacct_dump: error %d name %s packets %" PRIu64
		" bytes %" PRIu64 "\n", error, name, packets, bytes);

	g_assert_cmpstr(expected_name, ==, name);
	g_assert_cmpuint(packets, ==, 0);
	g_assert_cmpuint(bytes, ==, 0);
}

static void nfacct_del_callback(unsigned int error, void *user_data)
{
	g_assert_cmpuint(error, ==, 0);

	g_main_loop_quit(mainloop);
}

static void nfacct_case_1(void)
{
	struct nfacct_info *nfacct;
	char *name = "session-bar";

	printf("\n");
	nfacct = nfacct_new();

	nfacct_add(nfacct, name, nfacct_add_callback, name);
	nfacct_get(nfacct, name, false, nfacct_get_callback, name);
	nfacct_dump(nfacct, false, nfacct_dump_callback, name);
	nfacct_del(nfacct, name, nfacct_del_callback, name);

	mainloop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(mainloop);
	g_main_loop_unref(mainloop);

	nfacct_destroy(nfacct);
}

int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/netlink/Test case 1", test_case_1);
	g_test_add_func("/netlink/Test case 2", test_case_2);
	g_test_add_func("/nfacct/Test case 1", nfacct_case_1);

	return g_test_run();
}
