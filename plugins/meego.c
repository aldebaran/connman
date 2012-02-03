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

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/timeserver.h>
#include <connman/plugin.h>

#define MEEGO_NTP_SERVER "ntp.meego.com"

static int meego_init(void)
{
	return __connman_timeserver_system_append(MEEGO_NTP_SERVER);
}

static void meego_exit(void)
{
	__connman_timeserver_system_remove(MEEGO_NTP_SERVER);
}

CONNMAN_PLUGIN_DEFINE(meego, "MeeGo features plugin", VERSION,
			CONNMAN_PLUGIN_PRIORITY_LOW, meego_init, meego_exit)
