/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2010  BMW Car IT GmbH. All rights reserved.
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

#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#define MAGIC 0xFA00B916

struct connman_stats_data {
	unsigned int rx_packets;
	unsigned int tx_packets;
	unsigned int rx_bytes;
	unsigned int tx_bytes;
	unsigned int rx_errors;
	unsigned int tx_errors;
	unsigned int rx_dropped;
	unsigned int tx_dropped;
	unsigned int time;
};

struct stats_file_header {
	unsigned int magic;
	unsigned int begin;
	unsigned int end;
	unsigned int home;
	unsigned int roaming;
};

struct stats_record {
	time_t ts;
	unsigned int roaming;
	struct connman_stats_data data;
};

struct stats_file {
	int fd;
	char *name;
	char *addr;
	size_t len;

	/* cached values */
	int max_nr;
	int nr;
	struct stats_record *first;
	struct stats_record *last;
	struct stats_record *home_first;
	struct stats_record *roaming_first;
};

static struct stats_file_header *get_hdr(struct stats_file *file)
{
	return (struct stats_file_header *)file->addr;
}

static struct stats_record *get_begin(struct stats_file *file)
{
	unsigned int off = get_hdr(file)->begin;

	return (struct stats_record *)(file->addr + off);
}

static struct stats_record *get_end(struct stats_file *file)
{
	unsigned int off = get_hdr(file)->end;

	return (struct stats_record *)(file->addr + off);
}

static struct stats_record *get_home(struct stats_file *file)
{
	struct stats_file_header *hdr;

	hdr = get_hdr(file);

	if (hdr->home == UINT_MAX)
		return NULL;

	return (struct stats_record *)(file->addr + hdr->home);
}

static struct stats_record *get_roaming(struct stats_file *file)
{
	struct stats_file_header *hdr;

	hdr = get_hdr(file);

	if (hdr->roaming == UINT_MAX)
		return NULL;

	return (struct stats_record *)(file->addr + hdr->roaming);
}

static struct stats_record *get_next(struct stats_file *file,
					struct stats_record *cur)
{
	cur++;

	if (cur > file->last)
		cur = file->first;

	return cur;
}

static int get_index(struct stats_file *file, struct stats_record *rec)
{
	return rec - file->first;
}

static void stats_print_record(struct stats_record *rec)
{
	char buffer[30];

	strftime(buffer, 30, "%d-%m-%Y %T", localtime(&rec->ts));
	printf("%p %s %01d %d %d %d %d %d %d %d %d %d\n", rec, buffer,
		rec->roaming,
		rec->data.rx_packets,
		rec->data.tx_packets,
		rec->data.rx_bytes,
		rec->data.tx_bytes,
		rec->data.rx_errors,
		rec->data.tx_errors,
		rec->data.rx_dropped,
		rec->data.tx_dropped,
		rec->data.time);
}

static void stats_hdr_info(struct stats_file *file)
{
	struct stats_file_header *hdr;
	struct stats_record *begin, *end, *home, *roaming;
	unsigned int home_idx, roaming_idx;

	hdr = get_hdr(file);
	begin = get_begin(file);
	end = get_end(file);

	home = get_home(file);
	if (home == NULL)
		home_idx = UINT_MAX;
	else
		home_idx = get_index(file, home);

	roaming = get_roaming(file);
	if (roaming == NULL)
		roaming_idx = UINT_MAX;
	else
		roaming_idx = get_index(file, roaming);

	printf("Data Structure Sizes\n");
	printf("  sizeof header   %zd/0x%02zx\n",
		sizeof(struct stats_file_header),
		sizeof(struct stats_file_header));
	printf("  sizeof entry    %zd/0%02zx\n\n",
		sizeof(struct stats_record),
		sizeof(struct stats_record));

	printf("File\n");
	printf("  addr            %p\n",  file->addr);
	printf("  len             %zd\n", file->len);

	printf("  max nr entries  %d\n", file->max_nr);
	printf("  nr entries      %d\n\n", file->nr);

	printf("Header\n");
	printf("  magic           0x%08x\n", hdr->magic);
	printf("  begin           [%d] 0x%08x\n",
		get_index(file, begin), hdr->begin);
	printf("  end             [%d] 0x%08x\n",
		get_index(file, end), hdr->end);
	printf("  home            [%d] 0x%08x\n",
		home_idx, hdr->home);
	printf("  roaming         [%d] 0x%08x\n\n",
		roaming_idx, hdr->roaming);


	printf("Pointers\n");
	printf("  hdr             %p\n", hdr);
	printf("  begin           %p\n", begin);
	printf("  end             %p\n", end);
	printf("  home            %p\n", home);
	printf("  romaing         %p\n", roaming);
	printf("  first           %p\n", file->first);
	printf("  last            %p\n\n", file->last);
}

static void stats_print_entries(struct stats_file *file)
{
	struct stats_record *it;
	int i;

	printf("[ idx] ptr ts roaming rx_packets tx_packets rx_bytes "
		"tx_bytes rx_errors tx_errors rx_dropped tx_dropped time\n\n");

	for (i = 0, it = file->first; it <= file->last; it++, i++) {
		printf("[%04d] ", i);
		stats_print_record(it);
	}
}

static void stats_print_rec_diff(struct stats_record *begin,
					struct stats_record *end)
{
	printf("\trx_packets: %d\n",
		end->data.rx_packets - begin->data.rx_packets);
	printf("\ttx_packets: %d\n",
		end->data.tx_packets - begin->data.tx_packets);
	printf("\trx_bytes:   %d\n",
		end->data.rx_bytes - begin->data.rx_bytes);
	printf("\ttx_bytes:   %d\n",
		end->data.tx_bytes - begin->data.tx_bytes);
	printf("\trx_errors:  %d\n",
		end->data.rx_errors - begin->data.rx_errors);
	printf("\ttx_errors:  %d\n",
		end->data.tx_errors - begin->data.tx_errors);
	printf("\trx_dropped: %d\n",
		end->data.rx_dropped - begin->data.rx_dropped);
	printf("\ttx_dropped: %d\n",
		end->data.tx_dropped - begin->data.tx_dropped);
	printf("\ttime:       %d\n",
		end->data.time - begin->data.time);
}

static void stats_print_diff(struct stats_file *file)
{
	struct stats_record *begin, *end;

	begin = get_begin(file);
	begin = get_next(file, begin);
	end = get_end(file);

	printf("\n(begin + 1)\n");
	printf("\t[%04d] ", get_index(file, begin));
	stats_print_record(begin);
	printf("end\n");
	printf("\t[%04d] ", get_index(file, end));
	stats_print_record(end);

	if (file->home_first) {
		printf("\nhome\n");
		stats_print_rec_diff(file->home_first, get_home(file));
	}

	if (file->roaming_first) {
		printf("\roaming\n");
		stats_print_rec_diff(file->roaming_first, get_roaming(file));
	}
}

static void update_max_nr_entries(struct stats_file *file)
{
	file->max_nr = (file->len - sizeof(struct stats_file_header)) /
		sizeof(struct stats_record);
}

static void update_nr_entries(struct stats_file *file)
{
	struct stats_record *begin, *end;
	int nr;

	begin = get_begin(file);
	end = get_end(file);

	nr = get_index(file, end) - get_index(file, begin);

	if (nr < 0)
		nr += file->max_nr;

	file->nr = nr;
}

static void update_first(struct stats_file *file)
{
	file->first = (struct stats_record *)(file->addr +
					sizeof(struct stats_file_header));
}

static void update_last(struct stats_file *file)
{
	struct stats_record *last;

	last = file->first;
	last += file->max_nr - 1;

	file->last = last;
}

static int stats_file_update_cache(struct stats_file *file)
{
	struct stats_record *it;

	update_max_nr_entries(file);
	update_nr_entries(file);
	update_first(file);
	update_last(file);

	for (it = file->first; it <= file->last &&
		     (file->home_first == NULL ||
			     file->roaming_first == NULL); it++) {
		if (file->home_first == NULL && it->roaming == 0)
			file->home_first = it;

		if (file->roaming_first == NULL && it->roaming == 1)
			file->roaming_first = it;
	}
	return 0;
}

static int stats_file_mmap(struct stats_file *file, size_t size)
{
	size_t page_size;

	page_size = sysconf(_SC_PAGESIZE);
	file->len = (size + page_size - 1) & ~(page_size - 1);

	file->addr = mmap(NULL, file->len, PROT_READ,
			MAP_SHARED, file->fd, 0);

	if (file->addr == MAP_FAILED) {
		fprintf(stderr, "mmap error %s for %s\n",
			strerror(errno), file->name);
		return -errno;
	}

	stats_file_update_cache(file);

	return 0;
}

int main(int argc, char *argv[])
{
	struct stats_file _file, *file;
	struct stat stat;
	int err;

	if (argc < 2) {
		printf("Usage: %s [STATS_FILENAME]\n", argv[0]);
		exit(0);
	}

	file = &_file;
	bzero(file, sizeof(struct stats_file));

	file->name = argv[1];

	file->fd = open(file->name, O_RDONLY, 0644);
	if (file->fd == -1) {
		fprintf(stderr, "open error %s for %s\n",
			strerror(errno), file->name);
		exit(1);
	}

	err = fstat(file->fd, &stat);
	if (err < 0) {
		fprintf(stderr, "fstat error %s for %s\n",
			strerror(errno), file->name);
		exit(1);
	}

	err = stats_file_mmap(file, stat.st_size);
	if (err < 0)
		exit(1);

	if (get_hdr(file)->magic != MAGIC) {
		/* not fatal */
		printf("No valid magic found\n");
	}

	stats_hdr_info(file);
	stats_print_entries(file);
	stats_print_diff(file);

	munmap(file->addr, file->len);
	close(file->fd);

	return 0;
}
