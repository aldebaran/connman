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

#include <errno.h>
#include <stdlib.h>

#include <glib.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/location.h>
#include <connman/proxy.h>
#include <connman/log.h>

#include "gweb/gweb.h"

#define STATUS_URL  "http://www.connman.net/online/status.html"

struct server_data {
	GWeb *web;
	guint request_id;
};

static void web_debug(const char *str, void *data)
{
	connman_info("%s: %s\n", (const char *) data, str);
}

static gboolean web_result(GWebResult *result, gpointer user_data)
{
	struct connman_location *location = user_data;
	struct server_data *data = connman_location_get_data(location);
	guint16 status;

	if (data->request_id == 0)
		return FALSE;

	status = g_web_result_get_status(result);

	DBG("status %u", status);

	switch (status) {
	case 200:
		connman_location_report_result(location,
					CONNMAN_LOCATION_RESULT_ONLINE);
		break;
	case 302:
		connman_location_report_result(location,
					CONNMAN_LOCATION_RESULT_PORTAL);
		break;
	default:
		connman_location_report_result(location,
					CONNMAN_LOCATION_RESULT_UNKNOWN);
		break;
	}

	data->request_id = 0;

	return FALSE;
}

static void proxy_callback(const char *proxy, void *user_data)
{
	struct connman_location *location = user_data;
	struct server_data *data = connman_location_get_data(location);

	DBG("proxy %s", proxy);

	if (proxy == NULL)
		proxy = getenv("http_proxy");

	g_web_set_proxy(data->web, proxy);

	data->request_id = g_web_request_get(data->web, STATUS_URL,
							web_result, location);
}

static int location_detect(struct connman_location *location)
{
	struct server_data *data;
	enum connman_service_type service_type;
	const char *interface;

	DBG("location %p", location);

	service_type = connman_location_get_type(location);

	switch (service_type) {
	case CONNMAN_SERVICE_TYPE_ETHERNET:
	case CONNMAN_SERVICE_TYPE_WIFI:
	case CONNMAN_SERVICE_TYPE_WIMAX:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		break;
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_VPN:
		return -EOPNOTSUPP;
	}

	interface = connman_location_get_interface(location);
	if (interface == NULL)
		return -EINVAL;

	DBG("interface %s", interface);

	data = g_try_new0(struct server_data, 1);
	if (data == NULL)
		return -ENOMEM;

	connman_location_set_data(location, data);

	data->web = g_web_new(0);
	if (data->web == NULL) {
		g_free(data);
		return -ENOMEM;
	}

	if (getenv("CONNMAN_WEB_DEBUG"))
		g_web_set_debug(data->web, web_debug, "WEB");

	g_web_set_accept(data->web, NULL);
	g_web_set_user_agent(data->web, "ConnMan/%s", VERSION);
	g_web_set_close_connection(data->web, TRUE);

	connman_proxy_lookup(interface, STATUS_URL,
					proxy_callback, location);

	return 0;
}

static int location_finish(struct connman_location *location)
{
	struct server_data *data = connman_location_get_data(location);

	DBG("location %p", location);

	connman_location_set_data(location, NULL);

	if (data->request_id > 0)
		g_web_cancel_request(data->web, data->request_id);

	g_web_unref(data->web);

	g_free(data);

	return 0;
}

static struct connman_location_driver location = {
	.name		= "portal",
	.type		= CONNMAN_SERVICE_TYPE_WIFI,
	.priority	= CONNMAN_LOCATION_PRIORITY_HIGH,
	.detect		= location_detect,
	.finish		= location_finish,
};

static int portal_init(void)
{
	return connman_location_driver_register(&location);
}

static void portal_exit(void)
{
	connman_location_driver_unregister(&location);
}

CONNMAN_PLUGIN_DEFINE(portal, "Portal detection plugin", VERSION,
		CONNMAN_PLUGIN_PRIORITY_DEFAULT, portal_init, portal_exit)
