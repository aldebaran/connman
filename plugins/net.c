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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>

#include "net.h"

static int __net_ifindex(const char *sysfs)
{
	char *pathname;
	char buf[8];
	size_t size;
	ssize_t len;
	int fd, val = -EIO;

	if (sysfs == NULL)
		return -1;

	size = strlen(sysfs) + 9;

	pathname = malloc(size);

	sprintf(pathname, "%s/ifindex", sysfs);

	fd = open(pathname, O_RDONLY);

	free(pathname);

	if (fd < 0)
		return -errno;

	memset(buf, 0, sizeof(buf));

	len = read(fd, buf, sizeof(buf) - 1);
	if (len < 0) {
		val = -errno;
		goto done;
	}

	val = atoi(buf);

done:
	close(fd);

	return val;
}

int __net_ifaddr(const char *sysfs, struct in_addr *addr)
{
	struct ifreq ifr;
	int sk, ifindex;

	ifindex = __net_ifindex(sysfs);
	if (ifindex < 0)
		return ifindex;

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0)
		return -errno;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = ifindex;

	if (ioctl(sk, SIOCGIFNAME, &ifr) < 0) {
		close(sk);
		return -errno;
	}

	if (ioctl(sk, SIOCGIFADDR, &ifr) < 0) {
		close(sk);
		return -errno;
	}

	close(sk);

	*addr = ((struct sockaddr_in *) (&ifr.ifr_addr))->sin_addr;

	return 0;
}

char *__net_ifname(const char *sysfs)
{
	struct ifreq ifr;
	int sk, err, ifindex;

	ifindex = __net_ifindex(sysfs);
	if (ifindex < 0)
		return NULL;

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0)
		return NULL;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = ifindex;

	err = ioctl(sk, SIOCGIFNAME, &ifr);

	close(sk);

	if (err < 0)
		return NULL;

	return strdup(ifr.ifr_name);
}

void __net_free(void *ptr)
{
	if (ptr)
		free(ptr);
}

int __net_clear(const char *sysfs)
{
	char *ifname, cmd[128];

	ifname = __net_ifname(sysfs);
	if (ifname == NULL)
		return -1;

	sprintf(cmd, "resolvconf -d %s", ifname);
	printf("[NET] %s\n", cmd);
	system(cmd);

	sprintf(cmd, "ip addr flush dev %s", ifname);
	printf("[NET] %s\n", cmd);
	system(cmd);

	__net_free(ifname);

	return 0;
}

int __net_set(const char *sysfs, struct in_addr *addr, struct in_addr *mask,
				struct in_addr *route, struct in_addr *bcast,
						struct in_addr *namesrv)
{
	char *ifname, cmd[128], msk[32], brd[32];

	ifname = __net_ifname(sysfs);
	if (ifname == NULL)
		return -1;

	__net_clear(sysfs);

	sprintf(msk, "%s", "24");
	sprintf(brd, "%s", inet_ntoa(*bcast));
	sprintf(cmd, "ip addr add %s/%s brd %s dev %s",
				inet_ntoa(*addr), msk, brd, ifname);
	printf("[NET] %s\n", cmd);
	system(cmd);

	sprintf(cmd, "ip route add default via %s dev %s",
					inet_ntoa(*route), ifname);
	printf("[NET] %s\n", cmd);
	system(cmd);

	sprintf(cmd, "echo \"nameserver %s\" | resolvconf -a %s",
					inet_ntoa(*namesrv), ifname);
	printf("[NET] %s\n", cmd);
	system(cmd);

	__net_free(ifname);

	return 0;
}
