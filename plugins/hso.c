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

#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <glib.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/device.h>
#include <connman/resolver.h>
#include <connman/log.h>

#include "modem.h"

struct hso_data {
	int index;
	struct modem_data *modem;
};

static void owandata_callback(const char *buf, void *user_data)
{
	//struct hso_data *data = user_data;
	char *str, ip[16], nm[16], ns1[16], ns2[16], ns3[16], ns4[16], val[20];
	int err, num;

	str = g_strrstr(buf, "_OWANDATA");
	if (str == NULL || strstr(buf, "ERROR") != NULL)
		return;

	err = sscanf(str, "_OWANDATA: %d, %[^,], %[^,], "
					"%[^,], %[^,], %[^,], %[^,], %s",
				&num, ip, nm, ns1, ns2, ns3, ns4, val);

	if (err != 8) {
		DBG("parsed %d arguments", err);
		return;
	}

	DBG("ip %s dns %s %s val %s", ip, ns1, ns2, val);

	//connman_resolver_append(data->iface, NULL, ns1);
	//connman_resolver_append(data->iface, NULL, ns2);
}

static void owancall_callback(const char *buf, void *user_data)
{
	struct hso_data *data = user_data;

	DBG("");

	if (g_strrstr(buf, "_OWANCALL: 1, 3") != NULL) {
		DBG("%s", buf);
		//modem_command(modem, owancall_callback, data,
		//			"_OWANCALL", "%d,%d,%d", 1, 1, 1);
	}

	if (g_strrstr(buf, "_OWANCALL: 1, 1") != NULL) {
		DBG("%s", buf);
		modem_command(data->modem, owandata_callback, data,
						"_OWANDATA", "%d", 1);
	}

	if (g_strrstr(buf, "\r\nOK\r\n") != NULL) {
		modem_command(data->modem, owandata_callback, data,
						"_OWANDATA", "%d", 1);
	}
}

static int network_probe(struct connman_network *network)
{
	DBG("network %p", network);

	return 0;
}

static void network_remove(struct connman_network *network)
{
	DBG("network %p", network);
}

static int network_connect(struct connman_network *network)
{
	DBG("network %p", network);

	return 0;
}

static int network_disconnect(struct connman_network *network)
{
	DBG("network %p", network);

	return 0;
}

static struct connman_network_driver network_driver = {
	.name		= "hso-network",
	.type		= CONNMAN_NETWORK_TYPE_HSO,
	.probe		= network_probe,
	.remove		= network_remove,
	.connect	= network_connect,
	.disconnect	= network_disconnect,
};

static int hso_probe(struct connman_device *device)
{
	struct hso_data *data;

	DBG("device %p", device);

	data = g_try_new0(struct hso_data, 1);
	if (data == NULL)
		return -ENOMEM;

	data->index = connman_device_get_index(device);

	data->modem = modem_create("/dev/ttyHS0");
	if (data->modem == NULL) {
		g_free(data);
		return -EIO;
	}

	connman_device_set_data(device, data);

	modem_add_callback(data->modem, "_OWANCALL",
						owancall_callback, data);

	return 0;
}

static void hso_remove(struct connman_device *device)
{
	struct hso_data *data = connman_device_get_data(device);

	DBG("device %p", device);

	connman_device_set_data(device, NULL);

	modem_destroy(data->modem);

	g_free(data);
}

static int hso_enable(struct connman_device *device)
{
	struct hso_data *data = connman_device_get_data(device);
	struct connman_network *network;
	int err;

	DBG("device %p", device);

	err = modem_open(data->modem);
	if (err < 0)
		return err;

	connman_device_set_powered(device, TRUE);

	modem_command(data->modem, NULL, NULL, "Z", NULL);
	modem_command(data->modem, NULL, NULL, "I", NULL);

	modem_command(data->modem, owancall_callback, data,
					"_OWANCALL", "%d,%d,%d", 1, 1, 1);

	network = connman_network_create("internet", CONNMAN_NETWORK_TYPE_HSO);
	connman_device_add_network(device, network);

	return 0;
}

static int hso_disable(struct connman_device *device)
{
	struct hso_data *data = connman_device_get_data(device);
	//const char *iface = connman_device_get_interface(device);

	DBG("device %p", device);

	//connman_resolver_remove_all(iface);

	modem_command(data->modem, owancall_callback, data,
					"_OWANCALL", "%d,%d,%d", 1, 0, 0);

	connman_device_set_powered(device, FALSE);

	modem_close(data->modem);

	return 0;
}

static struct connman_device_driver hso_driver = {
	.name		= "hso",
	.type		= CONNMAN_DEVICE_TYPE_HSO,
	.probe		= hso_probe,
	.remove		= hso_remove,
	.enable		= hso_enable,
	.disable	= hso_disable,
};

static int hso_init(void)
{
	int err;

	err = connman_network_driver_register(&network_driver);
	if (err < 0)
		return err;

	err = connman_device_driver_register(&hso_driver);
	if (err < 0) {
		connman_network_driver_unregister(&network_driver);
		return err;
	}

	return 0;
}

static void hso_exit(void)
{
	connman_device_driver_unregister(&hso_driver);
	connman_network_driver_register(&network_driver);
}

CONNMAN_PLUGIN_DEFINE(hso, "Option HSO device plugin", VERSION,
		CONNMAN_PLUGIN_PRIORITY_DEFAULT, hso_init, hso_exit)
