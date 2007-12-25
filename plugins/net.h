/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007  Intel Corporation. All rights reserved.
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

#include <arpa/inet.h>

int __net_ifaddr(int ifindex, struct in_addr *addr);
char *__net_ifname(int ifindex);
void __net_free(void *ptr);

int __net_clear(int ifindex);
int __net_set(int ifindex, struct in_addr *addr, struct in_addr *mask,
				struct in_addr *route, struct in_addr *bcast,
						struct in_addr *namesrv);
