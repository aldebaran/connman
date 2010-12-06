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

#include "connman.h"

#define MAGIC 0xFA00B916

/*
 * Statistics counters are stored into a ring buffer which is stored
 * into a file
 *
 * File properties:
 *   The ring buffer is mmap to a file
 *   Initialy only the smallest possible amount of disk space is allocated
 *   The files grow to the configured maximal size
 *   The grows by _SC_PAGESIZE step size
 *   For each service a file is created
 *   Each file has a header where the indexes are stored
 *
 * Entries properties:
 *   Each entry has a timestamp
 *   A flag to mark if the entry is either home (0) or roaming (1) entry
 *   The entries are fixed sized (stats_record)
 *
 * Ring buffer properties:
 *   There are to indexes 'begin', 'end', 'home' and 'roaming'
 *   'begin' points to the oldest entry
 *   'end' points to the newest/current entry
 *   'home' points to the current home entry
 *   'roaming' points to the current roaming entry
 *   If 'begin' == 'end' then the buffer is empty
 *   If 'end' + 1 == 'begin then it's full
 *   The ring buffer is valid in the range (begin, end]
 *   If 'home' has the value UINT_MAX', 'home' is invalid
 *   if 'roaming' has the value UINT_MAX', 'roaming' is invalid
 *   'first' points to the first entry in the ring buffer
 *   'last' points to the last entry in the ring buffer
 */

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
	size_t max_len;

	/* cached values */
	struct stats_record *first;
	struct stats_record *last;
	struct stats_record *home;
	struct stats_record *roaming;
};

GHashTable *stats_hash = NULL;

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

static void set_begin(struct stats_file *file, struct stats_record *begin)
{
	struct stats_file_header *hdr;

	hdr = get_hdr(file);
	hdr->begin = (char *)begin - file->addr;
}

static void set_end(struct stats_file *file, struct stats_record *end)
{
	struct stats_file_header *hdr;

	hdr = get_hdr(file);
	hdr->end = (char *)end - file->addr;
}

static void set_home(struct stats_file *file, struct stats_record *home)
{
	struct stats_file_header *hdr;

	hdr = get_hdr(file);
	hdr->home = (char *)home - file->addr;
}

static void set_roaming(struct stats_file *file, struct stats_record *roaming)
{
	struct stats_file_header *hdr;

	hdr = get_hdr(file);
	hdr->roaming = (char *)roaming - file->addr;
}

static struct stats_record *get_next(struct stats_file *file,
					struct stats_record *cur)
{
	cur++;

	if (cur > file->last)
		cur = file->first;

	return cur;
}

static void stats_free(gpointer user_data)
{
	struct stats_file *file = user_data;

	msync(file->addr, file->len, MS_SYNC);

	munmap(file->addr, file->len);
	file->addr = NULL;

	close(file->fd);
	file->fd = -1;

	g_free(file->name);
	g_free(file);
}

static void update_first(struct stats_file *file)
{
	file->first = (struct stats_record *)
			(file->addr + sizeof(struct stats_file_header));
}

static void update_last(struct stats_file *file)
{
	unsigned int max_entries;

	max_entries = (file->len - sizeof(struct stats_file_header)) /
			sizeof(struct stats_record);
	file->last = file->first + max_entries - 1;
}

static void update_home(struct stats_file *file)
{
	file->home = get_home(file);
}

static void update_roaming(struct stats_file *file)
{
	file->roaming = get_roaming(file);
}

static void stats_file_update_cache(struct stats_file *file)
{
	update_first(file);
	update_last(file);
	update_home(file);
	update_roaming(file);
}

static int stats_file_remap(struct stats_file *file, size_t size)
{
	size_t page_size, new_size;
	void *addr;
	int err;

	page_size = sysconf(_SC_PAGESIZE);
	new_size = (size + page_size - 1) & ~(page_size - 1);

	err = ftruncate(file->fd, new_size);
	if (err < 0) {
		connman_error("ftrunctate error %s for %s",
				strerror(errno), file->name);
		return -errno;
	}

	if (file->addr == NULL) {
		addr = mmap(NULL, new_size, PROT_READ | PROT_WRITE,
				MAP_SHARED, file->fd, 0);
	} else {
		addr = mremap(file->addr, file->len, new_size, MREMAP_MAYMOVE);
	}

	if (addr == MAP_FAILED) {
		connman_error("mmap error %s for %s",
				strerror(errno), file->name);
		return -errno;
	}

	file->addr = addr;
	file->len = new_size;

	stats_file_update_cache(file);

	return 0;
}

static int stats_open(struct connman_service *service,
			struct stats_file *file)
{
	struct stat st;
	int err;
	size_t size;
	struct stats_file_header *hdr;
	connman_bool_t new_file = FALSE;

	file->name = g_strdup_printf("%s/stats/%s.data", STORAGEDIR,
			__connman_service_get_ident(service));

	err = stat(file->name, &st);
	if (err < 0) {
		/* according documentation the only possible error is ENOENT */
		st.st_size = 0;
		new_file = TRUE;
	}

	file->fd = open(file->name, O_RDWR | O_CREAT, 0644);

	if (file->fd < 0) {
		connman_error("open error %s for %s",
				strerror(errno), file->name);
		return -errno;
	}

	file->max_len = STATS_MAX_FILE_SIZE;

	if (st.st_size < sysconf(_SC_PAGESIZE))
		size = sysconf(_SC_PAGESIZE);
	else
		size = st.st_size;

	err = stats_file_remap(file, size);
	if (err < 0)
		return err;

	hdr = get_hdr(file);

	if (hdr->magic != MAGIC ||
			hdr->begin < sizeof(struct stats_file_header) ||
			hdr->end < sizeof(struct stats_file_header) ||
			hdr->home < sizeof(struct stats_file_header) ||
			hdr->roaming < sizeof(struct stats_file_header) ||
			hdr->begin > file->len ||
			hdr->end > file->len) {
		if (new_file == FALSE) {
			/*
			 * A newly created file can't have a correct
			 * header so we only warn if the file already
			 * existed and doesn't have a proper
			 * header.
			 */
			connman_warn("invalid file header for %s", file->name);
		}

		hdr->magic = MAGIC;
		hdr->begin = sizeof(struct stats_file_header);
		hdr->end = sizeof(struct stats_file_header);
		hdr->home = UINT_MAX;
		hdr->roaming = UINT_MAX;

		stats_file_update_cache(file);
	}

	return 0;
}

int __connman_stats_service_register(struct connman_service *service)
{
	struct stats_file *file;
	int err;

	DBG("service %p", service);

	file = g_hash_table_lookup(stats_hash, service);
	if (file == NULL) {
		file = g_try_new0(struct stats_file, 1);
		if (file == NULL)
			return -ENOMEM;

		g_hash_table_insert(stats_hash, service, file);
	} else {
		return -EALREADY;
	}

	err = stats_open(service, file);
	if (err < 0)
		g_hash_table_remove(stats_hash, service);

	return err;
}

void __connman_stats_service_unregister(struct connman_service *service)
{
	DBG("service %p", service);

	g_hash_table_remove(stats_hash, service);
}

int  __connman_stats_update(struct connman_service *service,
				connman_bool_t roaming,
				struct connman_stats_data *data)
{
	struct stats_file *file;
	struct stats_record *next;
	int err;

	file = g_hash_table_lookup(stats_hash, service);
	if (file == NULL)
		return -EEXIST;

	if (file->len < file->max_len &&
			file->last == get_end(file)) {
		DBG("grow file %s", file->name);

		err = stats_file_remap(file, file->len + sysconf(_SC_PAGESIZE));
		if (err < 0)
			return err;
	}

	next = get_next(file, get_end(file));

	if (next == get_begin(file))
		set_begin(file, get_next(file, next));

	next->ts = time(NULL);
	next->roaming = roaming;
	memcpy(&next->data, data, sizeof(struct connman_stats_data));

	if (roaming != TRUE)
		set_home(file, next);
	else
		set_roaming(file, next);

	set_end(file, next);

	return 0;
}

int __connman_stats_get(struct connman_service *service,
				connman_bool_t roaming,
				struct connman_stats_data *data)
{
	struct stats_file *file;
	struct stats_record *rec;

	file = g_hash_table_lookup(stats_hash, service);
	if (file == NULL)
		return -EEXIST;

	if (roaming != TRUE)
		rec = file->home;
	else
		rec = file->roaming;

	if (rec != NULL) {
		memcpy(data, &rec->data,
			sizeof(struct connman_stats_data));
	}

	return 0;
}

int __connman_stats_init(void)
{
	DBG("");

	stats_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal,
							NULL, stats_free);

	return 0;
}

void __connman_stats_cleanup(void)
{
	DBG("");

	g_hash_table_destroy(stats_hash);
	stats_hash = NULL;
}
