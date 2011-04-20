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
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/inotify.h>

#include <glib.h>

#include "connman.h"

#define ETC_LOCALTIME		"/etc/localtime"
#define ETC_SYSCONFIG_CLOCK	"/etc/sysconfig/clock"
#define USR_SHARE_ZONEINFO	"/usr/share/zoneinfo"

static char *read_key_file(const char *pathname, const char *key)
{
	struct stat st;
	char *map, *ptr, *str;
	off_t ptrlen, keylen;
	int fd;

	fd = open(pathname, O_RDONLY);
	if (fd < 0)
		return NULL;

	if (fstat(fd, &st) < 0) {
		close(fd);
		return NULL;
	}

	map = mmap(0, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (map == NULL || map == MAP_FAILED) {
		close(fd);
		return NULL;
	}

	ptr = map;
	ptrlen = st.st_size;
	keylen = strlen(key);

	while (ptrlen > keylen + 1) {
		int cmp = strncmp(ptr, key, keylen);

		if (cmp == 0) {
			if (ptr == map)
				break;

			if (*(ptr - 1) == '\n' && *(ptr + keylen) == '=')
				break;
		}

		ptr = memchr(ptr + 1, key[0], ptrlen - 1);
		if (ptr == NULL)
			break;

		ptrlen = st.st_size - (ptr - map);
	}

	if (ptr != NULL) {
		char *end, *val;

		ptrlen = st.st_size - (ptr - map);

		end = memchr(ptr, '\n', ptrlen);
		if (end != NULL)
			ptrlen = end - ptr;

		val = memchr(ptr, '"', ptrlen);
		if (val != NULL) {
			end = memchr(val + 1, '"', end - val - 1);
			if (end != NULL)
				str = g_strndup(val + 1, end - val - 1);
			else
				str = NULL;
		} else
			str = g_strndup(ptr + keylen + 1, ptrlen - keylen - 1);
	} else
		str = NULL;

	munmap(map, st.st_size);

	close(fd);

	return str;
}

static int compare_file(void *src_map, struct stat *src_st,
						const char *pathname)
{
	struct stat dst_st;
	void *dst_map;
	int fd, result;

	fd = open(pathname, O_RDONLY);
	if (fd < 0)
		return -1;

	if (fstat(fd, &dst_st) < 0) {
		close(fd);
		return -1;
	}

	if (src_st->st_size != dst_st.st_size) {
		close(fd);
		return -1;
	}

	dst_map = mmap(0, dst_st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (dst_map == NULL || dst_map == MAP_FAILED) {
		close(fd);
		return -1;
        }

	result = memcmp(src_map, dst_map, src_st->st_size);

	munmap(dst_map, dst_st.st_size);

	close(fd);

	return result;
}

static char *find_origin(void *src_map, struct stat *src_st,
				const char *basepath, const char *subpath)
{
	DIR *dir;
	struct dirent *d;
	char *str, pathname[PATH_MAX];

	if (subpath == NULL)
		strncpy(pathname, basepath, sizeof(pathname));
	else
		snprintf(pathname, sizeof(pathname),
					"%s/%s", basepath, subpath);

	dir = opendir(pathname);
	if (dir == NULL)
		return NULL;

	while ((d = readdir(dir))) {
		if (strcmp(d->d_name, ".") == 0 ||
				strcmp(d->d_name, "..") == 0 ||
				strcmp(d->d_name, "posix") == 0 ||
				strcmp(d->d_name, "right") == 0)
			continue;

		switch (d->d_type) {
		case DT_REG:
			if (subpath == NULL)
				snprintf(pathname, PATH_MAX,
						"%s/%s", basepath, d->d_name);
			else
				snprintf(pathname, PATH_MAX,
						"%s/%s/%s", basepath,
							subpath, d->d_name);

			if (compare_file(src_map, src_st, pathname) == 0) {
				closedir(dir);
				return g_strdup_printf("%s/%s",
							subpath, d->d_name);
			}
			break;
		case DT_DIR:
			if (subpath == NULL)
				strncpy(pathname, d->d_name, sizeof(pathname));
			else
				snprintf(pathname, sizeof(pathname),
						"%s/%s", subpath, d->d_name);

			str = find_origin(src_map, src_st, basepath, pathname);
			if (str != NULL) {
				closedir(dir);
				return str;
			}
			break;
		}
	}

	closedir(dir);

	return NULL;
}

char *__connman_timezone_lookup(void)
{
	struct stat st;
	void *map;
	int fd;
	char *zone;

	zone = read_key_file(ETC_SYSCONFIG_CLOCK, "ZONE");

	DBG("sysconfig zone %s", zone);

	fd = open(ETC_LOCALTIME, O_RDONLY);
	if (fd < 0) {
		g_free(zone);
		return NULL;
	}

	if (fstat(fd, &st) < 0)
		goto done;

	if (S_ISREG(st.st_mode)) {
		map = mmap(0, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
		if (map == NULL || map == MAP_FAILED) {
			g_free(zone);
			zone = NULL;

			goto done;
		}

		if (zone != NULL) {
			char pathname[PATH_MAX];

			snprintf(pathname, PATH_MAX, "%s/%s",
						USR_SHARE_ZONEINFO, zone);

			if (compare_file(map, &st, pathname) != 0) {
				g_free(zone);
				zone = NULL;
			}
		}

		if (zone == NULL)
			zone = find_origin(map, &st, USR_SHARE_ZONEINFO, NULL);

		munmap(map, st.st_size);
	} else {
		g_free(zone);
		zone = NULL;
	}

done:
	close(fd);

	DBG("localtime zone %s", zone);

	return zone;
}

int __connman_timezone_change(const char *zone)
{
	DBG("zone %s", zone);

	return -EIO;
}

static guint inotify_watch = 0;

static gboolean inotify_data(GIOChannel *channel, GIOCondition cond,
							gpointer user_data)
{
	char buffer[256];
	void *ptr = buffer;
	GIOStatus status;
	gsize bytes_read;

	DBG("");

	if (cond & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		inotify_watch = 0;
		return FALSE;
	}

	status = g_io_channel_read_chars(channel, buffer, sizeof(buffer),
							&bytes_read, NULL);

	switch (status) {
	case G_IO_STATUS_NORMAL:
		break;
	case G_IO_STATUS_AGAIN:
		return TRUE;
	default:
		inotify_watch = 0;
		return FALSE;
	}

	DBG("bytes read %ld", bytes_read);

	while (bytes_read > 0) {
		struct inotify_event *event = ptr;

		if (bytes_read < sizeof(*event))
			break;

		ptr += sizeof(*event);
		bytes_read -= sizeof(*event);

		if (event->len == 0)
			continue;

		if (bytes_read < event->len)
			break;

		ptr += event->len;
		bytes_read -= event->len;

		if (g_strcmp0(event->name, "localtime") == 0)
			__connman_clock_update_timezone();
	}

	return TRUE;
}

int __connman_timezone_init(void)
{
	GIOChannel *channel;
	char *dirname;
	int fd, wd;

	DBG("");

	fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	if (fd < 0)
		return -EIO;

	channel = g_io_channel_unix_new(fd);
	if (channel == NULL) {
		close(fd);
		return -EIO;
	}

	g_io_channel_set_close_on_unref(channel, TRUE);
	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);

	inotify_watch = g_io_add_watch(channel,
				G_IO_IN | G_IO_HUP | G_IO_NVAL | G_IO_ERR,
				inotify_data, NULL);

	g_io_channel_unref(channel);

	dirname = g_path_get_dirname(ETC_LOCALTIME);

	wd = inotify_add_watch(fd, dirname, IN_DONT_FOLLOW |
						IN_MODIFY | IN_MOVED_TO);

	g_free(dirname);

	return 0;
}

void __connman_timezone_cleanup(void)
{
	DBG("");

	if (inotify_watch > 0) {
		g_source_remove(inotify_watch);
		inotify_watch = 0;
	}
}
