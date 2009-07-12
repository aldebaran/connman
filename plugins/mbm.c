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
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <termios.h>
#include <net/if.h>

#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP	0x10000
#endif

#include <glib.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/device.h>
#include <connman/inet.h>
#include <connman/rtnl.h>
#include <connman/log.h>

#include <gatchat.h>

static const char *cfun_prefix[] = { "+CFUN:", NULL };

struct mbm_data {
	GAtChat *chat;
	unsigned flags;
	unsigned int watch;
	struct connman_network *network;
};

static void notify_callback(GAtResult *result, gpointer user_data)
{
	GAtResultIter iter;

	g_at_result_iter_init(&iter, result);

	if (g_at_result_iter_next(&iter, NULL) == TRUE)
		printf("%s\n", g_at_result_iter_raw_line(&iter));

	printf("==> %s\n", g_at_result_final_response(result));
}

static void generic_callback(gboolean ok, GAtResult *result,
						gpointer user_data)
{
	GAtResultIter iter;

	g_at_result_iter_init(&iter, result);

	if (g_at_result_iter_next(&iter, NULL) == TRUE)
		printf("%s\n", g_at_result_iter_raw_line(&iter));

	printf("==> %s (%d)\n", g_at_result_final_response(result), ok);
}

static void cfun_callback(gboolean ok, GAtResult *result,
						gpointer user_data)
{
	struct connman_device *device = user_data;
	struct mbm_data *data = connman_device_get_data(device);
	GAtResultIter iter;
	int status;

	if (ok == FALSE)
		return;

	g_at_result_iter_init(&iter, result);

	if (g_at_result_iter_next(&iter, "+CFUN:") == FALSE)
		return;

	g_at_result_iter_next_number(&iter, &status);

	if (status == 1) {
		connman_device_set_powered(device, TRUE);

		data->network = connman_network_create("internet",
						CONNMAN_NETWORK_TYPE_MBM);
		if (data->network != NULL) {
			int index;

			index = connman_device_get_index(device);
			connman_network_set_index(data->network, index);

			connman_network_set_protocol(data->network,
						CONNMAN_NETWORK_PROTOCOL_IP);

			connman_network_set_group(data->network, "gsm");

			connman_device_add_network(device, data->network);
		}
	} else {
		connman_device_set_powered(device, FALSE);

		data->network = NULL;
	}
}

static int network_probe(struct connman_network *network)
{
	struct connman_device *device = connman_network_get_device(network);
	struct mbm_data *data;

	DBG("network %p", network);

	data = connman_device_get_data(device);
	connman_network_set_data(network, data);

	g_at_chat_send(data->chat, "AT+CGDCONT=1,\"IP\",\"internet.com\"",
					NULL, generic_callback, NULL, NULL);

	g_at_chat_send(data->chat, "AT*ENAP?", NULL,
					generic_callback, NULL, NULL);

	return 0;
}

static void network_remove(struct connman_network *network)
{
	DBG("network %p", network);

	connman_network_set_data(network, NULL);
}

static int network_connect(struct connman_network *network)
{
	struct mbm_data *data = connman_network_get_data(network);

	DBG("network %p", network);

	g_at_chat_send(data->chat, "AT*ENAP=1,1", NULL,
					generic_callback, NULL, NULL);

	return 0;
}

static int network_disconnect(struct connman_network *network)
{
	struct mbm_data *data = connman_network_get_data(network);

	DBG("network %p", network);

	g_at_chat_send(data->chat, "AT*ENAP=0", NULL,
					generic_callback, NULL, NULL);

	return 0;
}

static struct connman_network_driver network_driver = {
	.name		= "mbm",
	.type		= CONNMAN_NETWORK_TYPE_MBM,
	.probe		= network_probe,
	.remove		= network_remove,
	.connect	= network_connect,
	.disconnect	= network_disconnect,
};

static void mbm_newlink(unsigned flags, unsigned change, void *user_data)
{
	struct connman_device *device = user_data;
	struct mbm_data *data = connman_device_get_data(device);

	if (data->network == NULL)
		goto done;

	DBG("device %p flags %d change %d", device, flags, change);

	if ((data->flags & IFF_LOWER_UP) != (flags & IFF_LOWER_UP)) {
		if (flags & IFF_LOWER_UP) {
			printf("==> connected\n");
			connman_network_set_connected(data->network, TRUE);
		} else {
			printf("==> disconnected\n");
			connman_network_set_connected(data->network, FALSE);
		}
	}

done:
	data->flags = flags;
}

static int mbm_probe(struct connman_device *device)
{
	struct mbm_data *data;
	int index;

	DBG("device %p", device);

	data = g_try_new0(struct mbm_data, 1);
	if (data == NULL)
		return -ENOMEM;

	connman_device_set_data(device, data);

	index = connman_device_get_index(device);

	data->watch = connman_rtnl_add_newlink_watch(index,
						mbm_newlink, device);

	connman_rtnl_send_getlink();

	return 0;
}

static void mbm_remove(struct connman_device *device)
{
	struct mbm_data *data = connman_device_get_data(device);

	DBG("device %p", device);

	connman_device_set_data(device, NULL);

	connman_rtnl_remove_watch(data->watch);

	g_free(data);
}

static int mbm_enable(struct connman_device *device)
{
	struct mbm_data *data = connman_device_get_data(device);
	GIOChannel *channel;
	struct termios ti;
	int fd, index;

	DBG("device %p", device);

	fd = open("/dev/ttyACM2", O_RDWR | O_NOCTTY);
	if (fd < 0)
		return -ENODEV;

	tcflush(fd, TCIOFLUSH);

	/* Switch TTY to raw mode */
	memset(&ti, 0, sizeof(ti));
	cfmakeraw(&ti);

	tcsetattr(fd, TCSANOW, &ti);

	channel = g_io_channel_unix_new(fd);
	if (channel == NULL) {
		close(fd);
		return -ENOMEM;
	}

	data->chat = g_at_chat_new(channel, 0);
	if (data->chat == NULL)
		return -EIO;

	g_io_channel_unref(channel);

	g_at_chat_register(data->chat, "*EMRDY:", notify_callback,
							FALSE, NULL, NULL);
	g_at_chat_register(data->chat, "*EMWI:", notify_callback,
							FALSE, NULL, NULL);
	g_at_chat_register(data->chat, "+PACSP", notify_callback,
							FALSE, NULL, NULL);

	index = connman_device_get_index(device);
	connman_inet_ifup(index);

	g_at_chat_send(data->chat, "AT&F E0 V1 X4 &C1 +CMEE=1", NULL,
					generic_callback, NULL, NULL);

	g_at_chat_send(data->chat, "AT+CFUN?", cfun_prefix,
					cfun_callback, device, NULL);
	g_at_chat_send(data->chat, "AT+CFUN=1", NULL,
					cfun_callback, device, NULL);

	return -EINPROGRESS;
}

static int mbm_disable(struct connman_device *device)
{
	struct mbm_data *data = connman_device_get_data(device);
	int index;

	DBG("device %p", device);

	g_at_chat_send(data->chat, "AT+CFUN=4", NULL,
					cfun_callback, NULL, NULL);

	index = connman_device_get_index(device);
	connman_inet_ifdown(index);

	g_at_chat_unref(data->chat);
	data->chat = NULL;

	return -EINPROGRESS;
}

static struct connman_device_driver mbm_driver = {
	.name		= "mbm",
	.type		= CONNMAN_DEVICE_TYPE_MBM,
	.probe		= mbm_probe,
	.remove		= mbm_remove,
	.enable		= mbm_enable,
	.disable	= mbm_disable,
};

static int mbm_init(void)
{
	int err;

	err = connman_network_driver_register(&network_driver);
	if (err < 0)
		return err;

	err = connman_device_driver_register(&mbm_driver);
	if (err < 0) {
		connman_network_driver_unregister(&network_driver);
		return err;
	}

	return 0;
}

static void mbm_exit(void)
{
	connman_device_driver_unregister(&mbm_driver);
	connman_network_driver_register(&network_driver);
}

CONNMAN_PLUGIN_DEFINE(mbm, "Ericsson MBM device plugin", VERSION,
		CONNMAN_PLUGIN_PRIORITY_DEFAULT, mbm_init, mbm_exit)
