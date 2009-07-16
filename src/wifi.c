/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2009  Intel Corporation. All rights reserved.
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
