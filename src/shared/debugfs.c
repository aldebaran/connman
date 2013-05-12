/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>

#include "src/shared/debugfs.h"

#define STRINGIFY(x) STRINGIFY_ARG(x)
#define STRINGIFY_ARG(x) #x

const char *debugfs_get_path(void)
{
	static char path[PATH_MAX + 1];
	static bool found = false;
	char type[100];
	FILE *fp;

	if (found)
		return path;

	fp = fopen("/proc/mounts", "r");
	if (!fp)
		return NULL;

	while (fscanf(fp, "%*s %" STRINGIFY(PATH_MAX) "s %99s %*s %*d %*d\n",
							path, type) == 2) {
		if (!strcmp(type, "debugfs")) {
			found = true;
			break;
		}
	}

	fclose(fp);

	if (!found)
		return NULL;

	return path;
}
