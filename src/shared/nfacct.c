/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2013  BWM Car IT GmbH.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License version 2.1 as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/netfilter/nfnetlink.h>

#include <gdbus.h>

#include "src/shared/netlink.h"
#include "src/shared/nfacct.h"
#include "src/shared/nfnetlink_acct_copy.h"

#define NFMSG_LEN(len)	(NLMSG_HDRLEN + NLMSG_ALIGN(GENL_HDRLEN + (len)))
#define NFGEN_DATA(nlh) ((void *)((char *)(nlh) +			\
				NLMSG_ALIGN(sizeof(struct nfgenmsg))))
#define NLA_DATA(nla)  ((void *)((char*)(nla) + NLA_HDRLEN))
#define NLA_OK(nla,len) ((len) >= (int)sizeof(struct nlattr) &&		\
				(nla)->nla_len >= sizeof(struct nlattr) && \
				(nla)->nla_len <= (len))
#define NLA_NEXT(nla,attrlen) ((attrlen) -= NLA_ALIGN((nla)->nla_len),	\
				(struct nlattr*)(((char*)(nla)) +       \
						NLA_ALIGN((nla)->nla_len)))
struct cb_data {
	void *cb;
	void *user_data;
	void *data;
};

static inline struct cb_data *cb_data_new(void *cb, void *user_data)
{
	struct cb_data *ret;

	ret = g_new0(struct cb_data, 1);
	ret->cb = cb;
	ret->user_data = user_data;

	return ret;
}

struct nfacct_info {
	struct netlink_info *netlink;
};

struct nfacct_info *nfacct_new(void)
{
	struct nfacct_info *nfacct;

	nfacct = g_try_new0(struct nfacct_info, 1);
	if (!nfacct)
		return NULL;

	nfacct->netlink = netlink_new(NETLINK_NETFILTER);
	if (!nfacct->netlink) {
		g_free(nfacct);
		return NULL;
	}

	return nfacct;
}

void nfacct_destroy(struct nfacct_info *nfacct)
{
	if (!nfacct)
		return;

	netlink_destroy(nfacct->netlink);

	g_free(nfacct);
}

static struct nfgenmsg *create_nfgenmsg(size_t size)
{
	struct nfgenmsg *msg;

	msg = g_try_malloc0(size);
	if (!msg)
		return NULL;

	msg->nfgen_family = AF_UNSPEC;
	msg->version = NFNETLINK_V0;
	msg->res_id = 0;

	return msg;
}

static size_t attr_name_size(const char *name)
{
	size_t size;

	if (!name)
		return 0;

	size = strlen(name) + 1;
	if (size > NFACCT_NAME_MAX)
		size = NFACCT_NAME_MAX;

	return size;
}

static size_t calc_msg_size(const char *name)
{
	return NFMSG_LEN(NLA_HDRLEN + attr_name_size(name));
}

static int set_attr_name(struct nfgenmsg *msg, const char *name)
{
	struct nlattr *attr = NFGEN_DATA(msg);
	char *dst;
	size_t size;

	size = attr_name_size(name);

	attr->nla_len = NLA_HDRLEN + size;
	attr->nla_type = NFACCT_NAME;

	dst = (char *)NLA_DATA(attr);
	strncpy(dst, name, size);
	dst[size - 1] = '\0';

	return 0;
}

static void nfacct_add_callback(unsigned int error, uint16_t type, const void *data,
				uint32_t len, void *user_data)
{
	struct cb_data *cbd = user_data;
	nfacct_add_func_t callback = cbd->cb;

	callback(error, cbd->user_data);

	g_free(cbd);
}

unsigned int nfacct_add(struct nfacct_info *nfacct, const char *name,
				nfacct_add_func_t function,
				void *user_data)
{
	struct cb_data *cbd = cb_data_new(function, user_data);
	struct nfgenmsg *msg;
	size_t len;
	unsigned id;

	len = calc_msg_size(name);
	msg = create_nfgenmsg(len);
	if (!msg)
		return 0;

	set_attr_name(msg, name);

	id = netlink_send(nfacct->netlink,
			NFNL_SUBSYS_ACCT << 8 | NFNL_MSG_ACCT_NEW,
			NLM_F_CREATE | NLM_F_ACK, msg, len,
			nfacct_add_callback, cbd, NULL);
	if (id == 0)
		g_free(cbd);

	g_free(msg);

	return id;
}

static void parse_nlattr_acct(const struct nlattr *attr,
				char **name, uint64_t *packets, uint64_t *bytes)
{
	switch (attr->nla_type) {
	case NFACCT_NAME:
		*name = NLA_DATA(attr);
		break;
	case NFACCT_PKTS:
		*packets = be64toh(*(uint64_t *) NLA_DATA(attr));
		break;
	case NFACCT_BYTES:
		*bytes = be64toh(*(uint64_t *) NLA_DATA(attr));
		break;
	case NFACCT_USE:
		/* ignored */
		break;
	}
}

static void nfacct_dump_callback(unsigned int error, uint16_t type, const void *data,
				uint32_t len, void *user_data)
{
	struct cb_data *cbd = user_data;
	nfacct_dump_func_t callback = cbd->cb;
	const struct nlattr *attr;
	uint64_t packets = 0, bytes = 0;
	char *name = NULL;

	if (error != 0)
		goto done;

	for (attr = NFGEN_DATA(data); NLA_OK(attr, len);
			attr = NLA_NEXT(attr, len))
		parse_nlattr_acct(attr, &name, &packets, &bytes);

done:
	callback(error, name, packets, bytes, cbd->user_data);

	if (type < NLMSG_MIN_TYPE)
		g_free(cbd);
}

unsigned int nfacct_dump(struct nfacct_info *nfacct, bool zero,
				nfacct_dump_func_t function, void *user_data)
{
	struct cb_data *cbd = cb_data_new(function, user_data);
	struct nfgenmsg *msg;
	uint16_t cmd;
	size_t len;
	unsigned id;

	len = calc_msg_size(NULL);
	msg = create_nfgenmsg(len);
	if (!msg)
		return 0;

	if (zero == false)
		cmd = NFNL_MSG_ACCT_GET;
	else
		cmd = NFNL_MSG_ACCT_GET_CTRZERO;

	id = netlink_send(nfacct->netlink,
			NFNL_SUBSYS_ACCT << 8 | cmd,
			NLM_F_DUMP, msg, len,
			nfacct_dump_callback, cbd, NULL);
	if (id == 0)
		g_free(cbd);

	g_free(msg);

	return id;
}

static void nfacct_get_callback(unsigned int error, uint16_t type, const void *data,
				uint32_t len, void *user_data)
{
	struct cb_data *cbd = user_data;
	nfacct_get_func_t callback = cbd->cb;
	const struct nlattr *attr;
	uint64_t packets = 0, bytes = 0;
	char *name = NULL;

	if (error != 0)
		goto done;

	for (attr = NFGEN_DATA(data); NLA_OK(attr, len);
			attr = NLA_NEXT(attr, len))
		parse_nlattr_acct(attr, &name, &packets, &bytes);

done:
	callback(error, name, packets, bytes, cbd->user_data);

	if (type < NLMSG_MIN_TYPE)
		g_free(cbd);
}

unsigned int nfacct_get(struct nfacct_info *nfacct, const char *name, bool zero,
			nfacct_get_func_t function, void *user_data)
{
	struct cb_data *cbd = cb_data_new(function, user_data);
	struct nfgenmsg *msg;
	uint16_t cmd;
	size_t len;
	unsigned id;

	len = calc_msg_size(name);
	msg = create_nfgenmsg(len);
	if (!msg)
		return 0;

	set_attr_name(msg, name);

	if (zero == false)
		cmd = NFNL_MSG_ACCT_GET;
	else
		cmd = NFNL_MSG_ACCT_GET_CTRZERO;

	id = netlink_send(nfacct->netlink,
			NFNL_SUBSYS_ACCT << 8 | cmd,
			NLM_F_ACK, msg, len,
			nfacct_get_callback, cbd, NULL);
	if (id == 0)
		g_free(cbd);

	g_free(msg);

	return id;
}

static void nfacct_del_callback(unsigned int error, uint16_t type, const void *data,
				uint32_t len, void *user_data)
{
	struct cb_data *cbd = user_data;
	nfacct_del_func_t callback = cbd->cb;

	callback(error, cbd->user_data);

	g_free(cbd);
}

unsigned int nfacct_del(struct nfacct_info *nfacct, const char *name,
				nfacct_del_func_t function, void *user_data)
{
	struct cb_data *cbd = cb_data_new(function, user_data);
	struct nfgenmsg *msg;
	size_t len;
	unsigned id;

	len = calc_msg_size(name);
	msg = create_nfgenmsg(len);
	if (!msg)
		return 0;

	set_attr_name(msg, name);

	id = netlink_send(nfacct->netlink,
			NFNL_SUBSYS_ACCT << 8 | NFNL_MSG_ACCT_DEL,
			NLM_F_ACK, msg, len,
			nfacct_del_callback, cbd, NULL);
	if (id == 0)
		g_free(cbd);

	g_free(msg);

	return id;
}
