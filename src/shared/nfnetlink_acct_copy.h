/*
 * include/uapi/linux/netfilter/nfnetlink_acct.h
 * Copyright (C) 2011 Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2.  See the file COPYING for more details.
 */

#ifndef _UAPI_NFNL_ACCT_H_
#define _UAPI_NFNL_ACCT_H_

#ifndef NFNL_SUBSYS_ACCT
#define NFNL_SUBSYS_ACCT	7
#endif

#ifndef NFACCT_NAME_MAX
#define NFACCT_NAME_MAX		32
#endif

enum nfnl_acct_msg_types {
	NFNL_MSG_ACCT_NEW,
	NFNL_MSG_ACCT_GET,
	NFNL_MSG_ACCT_GET_CTRZERO,
	NFNL_MSG_ACCT_DEL,
	NFNL_MSG_ACCT_MAX
};

enum nfnl_acct_type {
	NFACCT_UNSPEC,
	NFACCT_NAME,
	NFACCT_PKTS,
	NFACCT_BYTES,
	NFACCT_USE,
	__NFACCT_MAX
};
#define NFACCT_MAX (__NFACCT_MAX - 1)


#endif /* _UAPI_NFNL_ACCT_H_ */
