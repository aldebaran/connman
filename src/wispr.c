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

#include <gweb/gweb.h>

#include "connman.h"

#define STATUS_URL  "http://www.connman.net/online/status.html"

struct connman_wispr_portal_context {
	struct connman_service *service;
	enum connman_ipconfig_type type;

	/* Portal/WISPr common */
	GWeb *web;
	unsigned int token;
	guint request_id;
};

struct connman_wispr_portal {
	struct connman_wispr_portal_context *ipv4_context;
	struct connman_wispr_portal_context *ipv6_context;
};

static GHashTable *wispr_portal_list = NULL;

static void free_connman_wispr_portal_context(struct connman_wispr_portal_context *wp_context)
{
	DBG("");

	if (wp_context == NULL)
		return;

	if (wp_context->token > 0)
		connman_proxy_lookup_cancel(wp_context->token);

	if (wp_context->request_id > 0)
		g_web_cancel_request(wp_context->web, wp_context->request_id);

	g_web_unref(wp_context->web);

	g_free(wp_context);
}

static void free_connman_wispr_portal(gpointer data)
{
	struct connman_wispr_portal *wispr_portal = data;

	DBG("");

	if (wispr_portal == NULL)
		return;

	free_connman_wispr_portal_context(wispr_portal->ipv4_context);
	free_connman_wispr_portal_context(wispr_portal->ipv6_context);

	g_free(wispr_portal);
}

static void web_debug(const char *str, void *data)
{
	connman_info("%s: %s\n", (const char *) data, str);
}

static void wispr_portal_error(struct connman_wispr_portal_context *wp_context)
{
	DBG("Failed to proceed wispr/portal web request");
}

static void portal_manage_status(GWebResult *result,
			struct connman_wispr_portal_context *wp_context)
{
	const char *str = NULL;

	DBG("");

	/* We currently don't do anything with this info */
	if (g_web_result_get_header(result, "X-ConnMan-Client-IP",
				&str) == TRUE)
		connman_info("Client-IP: %s", str);

	if (g_web_result_get_header(result, "X-ConnMan-Client-Country",
				&str) == TRUE)
		connman_info("Client-Country: %s", str);

	if (g_web_result_get_header(result, "X-ConnMan-Client-Region",
				&str) == TRUE)
		connman_info("Client-Region: %s", str);

	__connman_service_ipconfig_indicate_state(wp_context->service,
						CONNMAN_SERVICE_STATE_ONLINE,
						wp_context->type);
}

static gboolean wispr_portal_web_result(GWebResult *result, gpointer user_data)
{
	struct connman_wispr_portal_context *wp_context = user_data;
	const char *redirect = NULL;
	const char *str = NULL;
	guint16 status;

	DBG("");

	if (wp_context->request_id == 0)
		return FALSE;

	status = g_web_result_get_status(result);

	DBG("status: %03u", status);

	switch (status) {
	case 200:
		if (g_web_result_get_header(result, "X-ConnMan-Status",
								&str) == TRUE)
			portal_manage_status(result, wp_context);

		break;
	case 302:
		if (g_web_result_get_header(result, "Location",
						&redirect) == FALSE)
			break;

		DBG("Redirect URL: %s", redirect);

		goto done;
	case 404:
		wispr_portal_error(wp_context);

		break;
	default:
		break;
	}

	wp_context->request_id = 0;
done:
	return FALSE;
}

static void wispr_portal_request_portal(struct connman_wispr_portal_context *wp_context)
{
	DBG("");

	wp_context->request_id = g_web_request_get(wp_context->web,
			STATUS_URL, wispr_portal_web_result, wp_context);

	if (wp_context->request_id == 0)
		wispr_portal_error(wp_context);
}

static void proxy_callback(const char *proxy, void *user_data)
{
	struct connman_wispr_portal_context *wp_context = user_data;

	DBG("proxy %s", proxy);

	wp_context->token = 0;

	if (proxy == NULL)
		proxy = getenv("http_proxy");

	if (getenv("CONNMAN_WEB_DEBUG"))
		g_web_set_debug(wp_context->web, web_debug, "WEB");

	if (proxy != NULL && g_strcmp0(proxy, "DIRECT") != 0)
		g_web_set_proxy(wp_context->web, proxy);

	g_web_set_accept(wp_context->web, NULL);
	g_web_set_user_agent(wp_context->web, "ConnMan/%s", VERSION);
	g_web_set_close_connection(wp_context->web, TRUE);

	wispr_portal_request_portal(wp_context);
}

static int wispr_portal_detect(struct connman_wispr_portal_context *wp_context)
{
	enum connman_service_type service_type;
	char *interface = NULL;
	int err = 0;

	DBG("wispr/portal context %p", wp_context);
	DBG("service %p", wp_context->service);

	service_type = connman_service_get_type(wp_context->service);

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
	case CONNMAN_SERVICE_TYPE_GADGET:
		return -EOPNOTSUPP;
	}

	interface = connman_service_get_interface(wp_context->service);
	if (interface == NULL)
		return -EINVAL;

	DBG("interface %s", interface);

	wp_context->web = g_web_new(0);
	if (wp_context->web == NULL) {
		err = -ENOMEM;
		goto done;
	}

	if (wp_context->type == CONNMAN_IPCONFIG_TYPE_IPV4)
		g_web_set_address_family(wp_context->web, AF_INET);
	else
		g_web_set_address_family(wp_context->web, AF_INET6);

	wp_context->token = connman_proxy_lookup(interface,
					STATUS_URL, wp_context->service,
					proxy_callback, wp_context);
	if (wp_context->token == 0)
		err = -EINVAL;

done:
	g_free(interface);
	return err;
}

int __connman_wispr_start(struct connman_service *service,
					enum connman_ipconfig_type type)
{
	struct connman_wispr_portal_context *wp_context = NULL;
	struct connman_wispr_portal *wispr_portal = NULL;
	int index;

	DBG("service %p", service);

	if (wispr_portal_list == NULL)
		return -EINVAL;

	index = __connman_service_get_index(service);
	if (index < 0)
		return -EINVAL;

	wispr_portal = g_hash_table_lookup(wispr_portal_list,
					GINT_TO_POINTER(index));
	if (wispr_portal == NULL) {
		wispr_portal = g_try_new0(struct connman_wispr_portal, 1);
		if (wispr_portal == NULL)
			return -ENOMEM;

		g_hash_table_replace(wispr_portal_list,
					GINT_TO_POINTER(index), wispr_portal);
	}

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		wp_context = wispr_portal->ipv4_context;
	else if (type == CONNMAN_IPCONFIG_TYPE_IPV6)
		wp_context = wispr_portal->ipv6_context;
	else
		return -EINVAL;

	if (wp_context == NULL) {
		wp_context = g_try_new0(struct connman_wispr_portal_context, 1);
		if (wp_context == NULL)
			return -ENOMEM;

		wp_context->service = service;
		wp_context->type = type;

		if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
			wispr_portal->ipv4_context = wp_context;
		else
			wispr_portal->ipv6_context = wp_context;

		return wispr_portal_detect(wp_context);
	}

	return 0;
}

void __connman_wispr_stop(struct connman_service *service)
{
	int index;

	DBG("service %p", service);

	if (wispr_portal_list == NULL)
		return;

	index = __connman_service_get_index(service);
	if (index < 0)
		return;

	g_hash_table_remove(wispr_portal_list, GINT_TO_POINTER(index));
}

int __connman_wispr_init(void)
{
	DBG("");

	wispr_portal_list = g_hash_table_new_full(g_direct_hash,
						g_direct_equal, NULL,
						free_connman_wispr_portal);

	return 0;
}

void __connman_wispr_cleanup(void)
{
	DBG("");

	g_hash_table_destroy(wispr_portal_list);
	wispr_portal_list = NULL;
}
