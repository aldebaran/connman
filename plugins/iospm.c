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

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/notifier.h>
#include <connman/log.h>

static void iospm_device_enabled(enum connman_device_type type,
						connman_bool_t enabled)
{
	DBG("type %d enabled %d", type, enabled);
}

static void iospm_offline_mode(connman_bool_t enabled)
{
	DBG("enabled %d", enabled);
}

static struct connman_notifier iospm_notifier = {
	.name		= "iospm",
	.priority	= CONNMAN_NOTIFIER_PRIORITY_DEFAULT,
	.device_enabled	= iospm_device_enabled,
	.offline_mode	= iospm_offline_mode,
};

static int iospm_init(void)
{
	return connman_notifier_register(&iospm_notifier);
}

static void iospm_exit(void)
{
	connman_notifier_unregister(&iospm_notifier);
}

CONNMAN_PLUGIN_DEFINE(ospm, "Intel OSPM notification plugin", VERSION,
		CONNMAN_PLUGIN_PRIORITY_DEFAULT, iospm_init, iospm_exit)
