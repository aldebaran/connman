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

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <linux/if_alg.h>

static void build_hash(int sk, char *map, size_t size, const char *pathname)
{
	unsigned char hash[20];
	ssize_t written, length;
	int i;

	written = send(sk, map, size, 0);
	if (written < 0)
		perror("Failed to write data");

	printf("send %zd bytes\n", written);

	length = recv(sk, hash, sizeof(hash), 0);
	if (length < 0)
		perror("Failed to read data");

	printf("recv %zd bytes\n", length);

	for (i = 0; i < length; i++)
		printf("%02x", hash[i]);
	printf("  %s\n", pathname);
}

static int create_hash(int sk, const char *pathname)
{
	struct stat st;
	char *map;
	int fd;

	fd = open(pathname, O_RDONLY);
	if (fd < 0)
		return -1;

	if (fstat(fd, &st) < 0) {
		close(fd);
		return -1;
	}

	map = mmap(0, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (map == NULL || map == MAP_FAILED) {
		close(fd);
		return -1;
	}

	build_hash(sk, map, st.st_size, pathname);

	munmap(map, st.st_size);

	close(fd);

	return 0;
}

static int create_socket(void)
{
	struct sockaddr_alg salg = {
		.salg_family = AF_ALG,
		.salg_type = "hash",
		.salg_name = "sha1",
	};
	int sk, nsk;

	sk = socket(PF_ALG, SOCK_SEQPACKET, 0);
	if (sk < 0) {
		perror("Failed to create socket");
		return -1;
	}

	if (bind(sk, (struct sockaddr *) &salg, sizeof(salg)) < 0) {
		perror("Failed to bind socket");
		close(sk);
		return -1;
	}

	nsk = accept(sk, NULL, 0);
	if (nsk < 0) {
		perror("Failed to accept socket");
		close(sk);
		return -1;
	}

	close(sk);

	return nsk;
}

int main(int argc, char *argv[])
{
	int sk;

	if (argc < 2) {
		fprintf(stderr, "Missing argument\n");
		return 1;
	}

	sk = create_socket();
	if (sk < 0)
		return 1;

	create_hash(sk, argv[1]);

	close(sk);

	return 0;
}
