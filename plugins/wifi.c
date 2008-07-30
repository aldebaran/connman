/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2008  Intel Corporation. All rights reserved.
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

#include <string.h>

#include <connman/plugin.h>
#include <connman/driver.h>
#include <connman/log.h>

#include "supplicant.h"

struct wifi_data {
	GStaticMutex mutex;
	GSList *list;
};

static struct connman_element *find_element(struct wifi_data *data,
						const char *identifier)
{
	GSList *list;

	for (list = data->list; list; list = list->next) {
		struct connman_element *element = list->data;

		if (element->network.identifier == NULL)
			continue;

		if (g_str_equal(element->network.identifier,
							identifier) == TRUE)
			return element;
	}

	return NULL;
}

static void scan_result(struct connman_element *parent,
					struct supplicant_network *network)
{
	struct wifi_data *data = connman_element_get_data(parent);
	struct connman_element *element;
	gchar *temp;
	int i;

	DBG("network %p identifier %s", network, network->identifier);

	if (data == NULL)
		return;

	if (network->identifier == NULL)
		return;

	if (network->identifier[0] == '\0')
		return;

	temp = g_strdup(network->identifier);

	for (i = 0; i < strlen(temp); i++) {
		if (temp[i] == ' ' || temp[i] == '.')
			temp[i] = '_';
		temp[i] = g_ascii_tolower(temp[i]);
	}

	g_static_mutex_lock(&data->mutex);

	element = find_element(data, temp);
	if (element == NULL) {
		element = connman_element_create();

		element->type = CONNMAN_ELEMENT_TYPE_NETWORK;
		element->name = temp;

		element->network.identifier = g_strdup(temp);

		data->list = g_slist_append(data->list, element);

		connman_element_register(element, parent);
	} else
		g_free(temp);

	g_static_mutex_unlock(&data->mutex);
}

static struct supplicant_callback wifi_callback = {
	.scan_result	= scan_result,
};

static int wifi_probe(struct connman_element *element)
{
	struct wifi_data *data;
	int err;

	DBG("element %p name %s", element, element->name);

	data = g_try_new0(struct wifi_data, 1);
	if (data == NULL)
		return -ENOMEM;

	g_static_mutex_init(&data->mutex);

	connman_element_set_data(element, data);

	err = __supplicant_start(element, &wifi_callback);
	if (err < 0)
		return err;

	__supplicant_scan(element);

	return 0;
}

static void wifi_remove(struct connman_element *element)
{
	struct wifi_data *data = connman_element_get_data(element);
	GSList *list;

	DBG("element %p name %s", element, element->name);

	__supplicant_stop(element);

	connman_element_set_data(element, NULL);

	if (data == NULL)
		return;

	g_static_mutex_lock(&data->mutex);

	for (list = data->list; list; list = list->next) {
		struct connman_element *network = list->data;

		connman_element_unregister(network);
		connman_element_unref(network);
	}

	g_slist_free(data->list);

	g_static_mutex_unlock(&data->mutex);

	g_free(data);
}

static struct connman_driver wifi_driver = {
	.name		= "wifi",
	.type		= CONNMAN_ELEMENT_TYPE_DEVICE,
	.subtype	= CONNMAN_ELEMENT_SUBTYPE_WIFI,
	.probe		= wifi_probe,
	.remove		= wifi_remove,
};

static int wifi_init(void)
{
	return connman_driver_register(&wifi_driver);
}

static void wifi_exit(void)
{
	connman_driver_unregister(&wifi_driver);
}

CONNMAN_PLUGIN_DEFINE("WiFi", "WiFi interface plugin", VERSION,
							wifi_init, wifi_exit)
