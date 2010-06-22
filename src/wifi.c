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
#include <string.h>

#include <glib.h>

#include "connman.h"

char *connman_wifi_build_group_name(const unsigned char *ssid,
						unsigned int ssid_len,
							const char *mode,
							const char *security)
{
	GString *str;
	unsigned int i;

	str = g_string_sized_new((ssid_len * 2) + 24);
	if (str == NULL)
		return NULL;

	if (ssid_len > 0 && ssid[0] != '\0') {
		for (i = 0; i < ssid_len; i++)
			g_string_append_printf(str, "%02x", ssid[i]);
	}

	g_string_append_printf(str, "_%s_%s", mode, security);

	return g_string_free(str, FALSE);
}

char **connman_wifi_load_ssid(void)
{
	GKeyFile *key_file;
	const char * profile;
	gchar **groups, *group;
	gsize num_groups;
	char **hex_ssids;
	int i, j;

	profile = __connman_profile_active_ident();

	key_file = __connman_storage_open_profile(profile);
	if (key_file == NULL)
		return NULL;

	groups = g_key_file_get_groups(key_file, &num_groups);
	if (groups == NULL) {
		hex_ssids = NULL;
		goto done;
	}

	hex_ssids = g_try_malloc0(sizeof(*hex_ssids) * num_groups);

	for (i = 0, j = 0; groups[i]; i++) {
		gchar *hex_ssid;
		gboolean favorite;

		group = groups[i];

		favorite = g_key_file_get_boolean(key_file, group,
							"Favorite", NULL);
		if (favorite == FALSE)
			continue;

		hex_ssid = g_key_file_get_string(key_file, group,
							"SSID", NULL);
		if (hex_ssid == NULL)
			continue;

		hex_ssids[j++] = hex_ssid;
	}

done:
	__connman_storage_close_profile(profile, key_file, FALSE);

	return hex_ssids;
}
