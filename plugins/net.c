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

char *__net_ifname(const char *sysfs)
{
	struct ifreq ifr;
	int sk, err, ifindex;

	ifindex = __net_ifindex(sysfs);
	if (ifindex < 0)
		return NULL;

	sk = socket (PF_INET, SOCK_DGRAM, 0);
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
