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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
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
#include <gattty.h>

static const char *cfun_prefix[] = { "+CFUN:", NULL };
static const char *cind_prefix[] = { "+CIND:", NULL };
static const char *cops_prefix[] = { "+COPS:", NULL };
static const char *creg_prefix[] = { "+CREG:", NULL };
static const char *cgreg_prefix[] = { "+CGREG:", NULL };

struct mbm_data {
	GAtChat *chat;
	unsigned flags;
	unsigned int watch;
	struct connman_network *network;
	char *imsi;
	unsigned int cimi_counter;
	unsigned int creg_status;
};

static void mbm_debug(const char *str, void *user_data)
{
	connman_info("%s", str);
}

static void emrdy_notifier(GAtResult *result, gpointer user_data)
{
}

static void erinfo_notifier(GAtResult *result, gpointer user_data)
{
	GAtResultIter iter;
	int mode, gsm, umts;

	g_at_result_iter_init(&iter, result);

	if (g_at_result_iter_next(&iter, "*ERINFO:") == FALSE)
		return;

	g_at_result_iter_next_number(&iter, &mode);
	g_at_result_iter_next_number(&iter, &gsm);
	g_at_result_iter_next_number(&iter, &umts);

	connman_info("network capability: GSM %d UMTS %d", gsm, umts);
}

static void erinfo_callback(gboolean ok, GAtResult *result,
						gpointer user_data)
{
	if (ok == FALSE)
		return;

	erinfo_notifier(result, user_data);
}

static void cgdcont_callback(gboolean ok, GAtResult *result,
						gpointer user_data)
{
	GAtResultIter iter;

	g_at_result_iter_init(&iter, result);
}

static void cgreg_query(gboolean ok, GAtResult *result,
						gpointer user_data)
{
	struct mbm_data *data = user_data;
	GAtResultIter iter;
	int status, mode;

	if (data->network == NULL)
		return;

	g_at_result_iter_init(&iter, result);

	if (g_at_result_iter_next(&iter, "+CGREG:") == FALSE)
		return;

	g_at_result_iter_skip_next(&iter);
	g_at_result_iter_next_number(&iter, &status);
	g_at_result_iter_skip_next(&iter);
	g_at_result_iter_skip_next(&iter);
	g_at_result_iter_next_number(&iter, &mode);

	connman_network_set_uint8(data->network, "Cellular.Mode", mode);
	connman_network_set_group(data->network, data->imsi);
}

static void enap_query(gboolean ok, GAtResult *result,
						gpointer user_data)
{
	GAtResultIter iter;

	g_at_result_iter_init(&iter, result);
}

static void enap_enable(gboolean ok, GAtResult *result,
						gpointer user_data)
{
	struct mbm_data *data = user_data;
	GAtResultIter iter;

	g_at_result_iter_init(&iter, result);

	g_at_chat_send(data->chat, "AT+CGREG?", cgreg_prefix,
						cgreg_query, data, NULL);
}

static void enap_disable(gboolean ok, GAtResult *result,
						gpointer user_data)
{
	GAtResultIter iter;

	g_at_result_iter_init(&iter, result);
}

static void cind_callback(gboolean ok, GAtResult *result,
						gpointer user_data)
{
	struct connman_device *device = user_data;
	struct mbm_data *data = connman_device_get_data(device);
	GAtResultIter iter;
	int dummy, strength;

	if (ok == FALSE)
		return;

	if (data->network == NULL)
		return;

	g_at_result_iter_init(&iter, result);

	if (g_at_result_iter_next(&iter, "+CIND:") == FALSE)
		return;

	g_at_result_iter_next_number(&iter, &dummy);
	g_at_result_iter_next_number(&iter, &strength);

	connman_network_set_strength(data->network, strength * 20);
	connman_network_set_group(data->network, data->imsi);
}

static void network_callback(gboolean ok, GAtResult *result,
						gpointer user_data)
{
	struct connman_device *device = user_data;
	struct mbm_data *data = connman_device_get_data(device);
	GAtResultIter iter;
	char *name, *mccmnc;
	const char *oper;
	int mode, format, tech;

	if (ok == FALSE)
		return;

	g_at_result_iter_init(&iter, result);

	if (g_at_result_iter_next(&iter, "+COPS:") == FALSE)
		return;

	g_at_result_iter_next_number(&iter, &mode);
	g_at_result_iter_next_number(&iter, &format);
	g_at_result_iter_next_string(&iter, &oper);
	mccmnc = g_strdup(oper);
	g_at_result_iter_next_number(&iter, &tech);

	if (g_at_result_iter_next(&iter, "+COPS:") == FALSE)
		return;

	g_at_result_iter_next_number(&iter, &mode);
	g_at_result_iter_next_number(&iter, &format);
	g_at_result_iter_next_string(&iter, &oper);
	name = g_strdup(oper);
	g_at_result_iter_next_number(&iter, &tech);

	data->network = connman_network_create(mccmnc,
						CONNMAN_NETWORK_TYPE_MBM);
	if (data->network != NULL) {
		char *mcc, *mnc;
		int index;

		index = connman_device_get_index(device);
		connman_network_set_index(data->network, index);

		connman_network_set_protocol(data->network,
						CONNMAN_NETWORK_PROTOCOL_IP);

		mcc = g_strndup(mccmnc, 3);
		connman_network_set_string(data->network, "Cellular.MCC", mcc);
		g_free(mcc);

		mnc = g_strdup(mccmnc + 3);
		connman_network_set_string(data->network, "Cellular.MNC", mnc);
		g_free(mnc);

		connman_network_set_name(data->network, name);
		connman_network_set_group(data->network, data->imsi);

		connman_device_add_network(device, data->network);
	}

	g_free(name);
	g_free(mccmnc);

	g_at_chat_send(data->chat, "AT+CIND?", cind_prefix,
						cind_callback, device, NULL);
}

static void network_ready(struct connman_device *device)
{
	struct mbm_data *data = connman_device_get_data(device);

	g_at_chat_send(data->chat, "AT*E2NAP=1", NULL, NULL, NULL, NULL);
	g_at_chat_send(data->chat, "AT*ERINFO=1", NULL, NULL, NULL, NULL);

	g_at_chat_send(data->chat, "AT+COPS=3,2;+COPS?;+COPS=3,0;+COPS?",
				cops_prefix, network_callback, device, NULL);

	g_at_chat_send(data->chat, "AT*ERINFO?", NULL, erinfo_callback,
								device, NULL);
}

static gboolean lost_network(int old, int new)
{
	if (old != 1 && old != 5)
		return FALSE;

	if (new == 1 || new == 5)
		return FALSE;

	return TRUE;
}

static gboolean get_network(int old, int new)
{
	if (old == 1 || old == 5)
		return FALSE;

	if (new != 1 && new != 5)
		return FALSE;

	return TRUE;
}

static void cleanup_network(struct connman_device *device)
{
	struct mbm_data *data = connman_device_get_data(device);
	const char *identifier;

	DBG("");

	if (data->network == NULL)
		return;

	connman_network_set_connected(data->network, FALSE);

	identifier = connman_network_get_identifier(data->network);

	connman_device_remove_network(device, identifier);

	data->network = NULL;
}

static void update_roaming(struct connman_device *device, int status)
{
	struct mbm_data *data = connman_device_get_data(device);

	if (data->network == NULL)
		return;

	if (status != 1 && status != 5)
		return;

	if (status == 1)
		connman_network_set_roaming(data->network, FALSE);
	else
		connman_network_set_roaming(data->network, TRUE);

	connman_network_set_group(data->network, data->imsi);
}

static void creg_update(struct connman_device *device, int status)
{
	struct mbm_data *data = connman_device_get_data(device);
	int old_status = data->creg_status;

	DBG("old_status %d status %d", old_status, status);

	data->creg_status = status;

	if (lost_network(old_status, status) == TRUE) {
		cleanup_network(device);
		return;
	}

	if (get_network(old_status, status) == TRUE)
		network_ready(device);

	update_roaming(device, status);
}

static void creg_query(gboolean ok, GAtResult *result,
						gpointer user_data)
{
	struct connman_device *device = user_data;
	GAtResultIter iter;
	int status;

	if (ok == FALSE)
		return;

	g_at_result_iter_init(&iter, result);

	if (g_at_result_iter_next(&iter, "+CREG:") == FALSE)
		return;

	g_at_result_iter_skip_next(&iter);
	g_at_result_iter_next_number(&iter, &status);

	creg_update(device, status);
}

static void cops_callback(gboolean ok, GAtResult *result,
						gpointer user_data)
{
	struct connman_device *device = user_data;
	struct mbm_data *data = connman_device_get_data(device);

	if (ok == FALSE)
		return;

	g_at_chat_send(data->chat, "AT+CREG?", creg_prefix,
						creg_query, device, NULL);
}

static void register_network(struct connman_device *device)
{
	struct mbm_data *data = connman_device_get_data(device);

	g_at_chat_send(data->chat, "AT+CREG=1",
						NULL, NULL, NULL, NULL);
	g_at_chat_send(data->chat, "AT+CGREG=2",
						NULL, NULL, NULL, NULL);
	g_at_chat_send(data->chat, "AT+CMER=3,0,0,1",
						NULL, NULL, NULL, NULL);

	g_at_chat_send(data->chat, "AT+COPS=0", cops_prefix,
						cops_callback, device, NULL);
}

static void e2nap_notifier(GAtResult *result, gpointer user_data)
{
	struct connman_device *device = user_data;
	struct mbm_data *data = connman_device_get_data(device);
	GAtResultIter iter;
	int state;

	g_at_result_iter_init(&iter, result);

	if (g_at_result_iter_next(&iter, "*E2NAP:") == FALSE)
		return;

	g_at_result_iter_next_number(&iter, &state);

	connman_info("network connection: state %d", state);

	g_at_chat_send(data->chat, "AT+CIND?", cind_prefix,
						cind_callback, device, NULL);
}

static void pacsp0_notifier(GAtResult *result, gpointer user_data)
{
}

static void ciev_notifier(GAtResult *result, gpointer user_data)
{
	struct connman_device *device = user_data;
	struct mbm_data *data = connman_device_get_data(device);
	GAtResultIter iter;
	int index, strength;

	if (data->network == NULL)
		return;

	g_at_result_iter_init(&iter, result);

	if (g_at_result_iter_next(&iter, "+CIEV:") == FALSE)
		return;

	g_at_result_iter_next_number(&iter, &index);
	if (index != 2)
		return;

	g_at_result_iter_next_number(&iter, &strength);

	connman_network_set_strength(data->network, strength * 20);
	connman_network_set_group(data->network, data->imsi);
}

static void creg_notifier(GAtResult *result, gpointer user_data)
{
	struct connman_device *device = user_data;
	GAtResultIter iter;
	int status;

	g_at_result_iter_init(&iter, result);

	if (g_at_result_iter_next(&iter, "+CREG:") == FALSE)
		return;

	g_at_result_iter_next_number(&iter, &status);

	creg_update(device, status);
}

static void cgreg_notifier(GAtResult *result, gpointer user_data)
{
	struct connman_device *device = user_data;
	struct mbm_data *data = connman_device_get_data(device);
	GAtResultIter iter;
	int status, mode;

	if (data->network == NULL)
		return;

	g_at_result_iter_init(&iter, result);

	if (g_at_result_iter_next(&iter, "+CGREG:") == FALSE)
		return;

	g_at_result_iter_next_number(&iter, &status);
	g_at_result_iter_skip_next(&iter);
	g_at_result_iter_skip_next(&iter);
	g_at_result_iter_next_number(&iter, &mode);

	connman_network_set_uint8(data->network, "Cellular.Mode", mode);
	connman_network_set_group(data->network, data->imsi);
}

static void cimi_callback(gboolean ok, GAtResult *result, gpointer user_data);

static gboolean cimi_timeout(gpointer user_data)
{
	struct connman_device *device = user_data;
	struct mbm_data *data = connman_device_get_data(device);

	data->cimi_counter++;

	if (data->cimi_counter > 5) {
		connman_device_set_powered(device, FALSE);
		return FALSE;
	}

	g_at_chat_send(data->chat, "AT+CIMI", NULL, cimi_callback,
							device, NULL);

	return FALSE;
}

static void cimi_callback(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct connman_device *device = user_data;
	struct mbm_data *data = connman_device_get_data(device);
	GAtResultIter iter;
	const char *imsi;
	int i;

	if (ok == FALSE) {
		g_timeout_add_seconds(1, cimi_timeout, device);
		return;
	}

	g_at_result_iter_init(&iter, result);

	for (i = 0; i < g_at_result_num_response_lines(result); i++)
		g_at_result_iter_next(&iter, NULL);

	imsi = g_at_result_iter_raw_line(&iter);

	data->imsi = g_strdup(imsi);

	register_network(device);
}

static void cfun_enable(gboolean ok, GAtResult *result,
						gpointer user_data)
{
	struct connman_device *device = user_data;
	struct mbm_data *data = connman_device_get_data(device);

	if (ok == FALSE) {
		connman_device_set_powered(device, FALSE);
		return;
	}

	connman_device_set_powered(device, TRUE);

	g_at_chat_send(data->chat, "AT+CIMI", NULL, cimi_callback,
							device, NULL);
}

static void cfun_disable(gboolean ok, GAtResult *result,
						gpointer user_data)
{
	struct connman_device *device = user_data;
	struct mbm_data *data = connman_device_get_data(device);

	connman_device_set_powered(device, FALSE);

	if (data->chat != NULL) {
		g_at_chat_unref(data->chat);
		data->chat = NULL;
	}
}

static void cfun_query(gboolean ok, GAtResult *result,
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

		g_at_chat_send(data->chat, "AT+CIMI", NULL, cimi_callback,
								device, NULL);
	} else {
		g_at_chat_send(data->chat, "AT+CFUN=1", cfun_prefix,
						cfun_enable, device, NULL);
	}
}

static int network_probe(struct connman_network *network)
{
	struct connman_device *device = connman_network_get_device(network);
	struct mbm_data *data;

	DBG("network %p", network);

	data = connman_device_get_data(device);
	connman_network_set_data(network, data);

	g_at_chat_send(data->chat, "AT*ENAP?", NULL,
					enap_query, device, NULL);

	return 0;
}

static void network_remove(struct connman_network *network)
{
	struct connman_device *device = connman_network_get_device(network);
	struct mbm_data *data;

	DBG("network %p", network);

	data = connman_device_get_data(device);
	data->network = NULL;

	connman_network_set_data(network, NULL);
}

static int network_connect(struct connman_network *network)
{
	struct mbm_data *data = connman_network_get_data(network);
	const char *apn;
	char *cmd;

	DBG("network %p", network);

	apn = connman_network_get_string(network, "Cellular.APN");
	if (apn == NULL)
		return -EINVAL;

	cmd = g_strdup_printf("AT+CGDCONT=1,\"IP\",\"%s\"", apn);
	g_at_chat_send(data->chat, cmd, NULL, cgdcont_callback, NULL, NULL);
	g_free(cmd);

	g_at_chat_send(data->chat, "AT*ENAP=1,1", NULL,
					enap_enable, data, NULL);

	return 0;
}

static int network_disconnect(struct connman_network *network)
{
	struct mbm_data *data = connman_network_get_data(network);

	DBG("network %p", network);

	g_at_chat_send(data->chat, "AT*ENAP=0", NULL,
					enap_disable, data, NULL);

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
			connman_network_set_method(data->network,
					CONNMAN_IPCONFIG_METHOD_DHCP);
			connman_network_set_connected(data->network, TRUE);
		} else {
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

	return 0;
}

static void mbm_remove(struct connman_device *device)
{
	struct mbm_data *data = connman_device_get_data(device);

	DBG("device %p", device);

	connman_device_set_data(device, NULL);

	connman_rtnl_remove_watch(data->watch);

	if (data->chat != NULL) {
		g_at_chat_unref(data->chat);
		data->chat = NULL;
	}

	g_free(data->imsi);
	g_free(data);
}

static int mbm_enable(struct connman_device *device)
{
	struct mbm_data *data = connman_device_get_data(device);
	GAtSyntax *syntax;
	GIOChannel *channel;
	const char *devnode;
	int index;

	DBG("device %p", device);

	devnode = connman_device_get_control(device);
	if (devnode == NULL)
		return -EIO;

	channel = g_at_tty_open(devnode, NULL);
	if (channel == NULL)
		return -EIO;

	syntax = g_at_syntax_new_gsmv1();
	data->chat = g_at_chat_new(channel, syntax);
	g_at_syntax_unref(syntax);

	g_io_channel_unref(channel);

	if (data->chat == NULL)
		return -EIO;

	if (getenv("MBM_DEBUG"))
		g_at_chat_set_debug(data->chat, mbm_debug, NULL);

	g_at_chat_register(data->chat, "*EMRDY:", emrdy_notifier,
							FALSE, device, NULL);
	g_at_chat_register(data->chat, "*ERINFO:", erinfo_notifier,
							FALSE, device, NULL);
	g_at_chat_register(data->chat, "*E2NAP:", e2nap_notifier,
							FALSE, device, NULL);
	g_at_chat_register(data->chat, "+PACSP0", pacsp0_notifier,
							FALSE, device, NULL);
	g_at_chat_register(data->chat, "+CIEV:", ciev_notifier,
							FALSE, device, NULL);

	g_at_chat_register(data->chat, "+CREG:", creg_notifier,
							FALSE, device, NULL);
	g_at_chat_register(data->chat, "+CGREG:", cgreg_notifier,
							FALSE, device, NULL);

	index = connman_device_get_index(device);
	connman_inet_ifup(index);

	g_at_chat_send(data->chat, "AT&F E0 V1 X4 &C1 +CMEE=1", NULL,
							NULL, NULL, NULL);

	g_at_chat_send(data->chat, "AT*EMRDY?", NULL, NULL, NULL, NULL);

	g_at_chat_send(data->chat, "AT+CFUN?", cfun_prefix,
						cfun_query, device, NULL);

	return -EINPROGRESS;
}

static int mbm_disable(struct connman_device *device)
{
	struct mbm_data *data = connman_device_get_data(device);
	int index;

	DBG("device %p", device);

	g_at_chat_send(data->chat, "AT+CMER=0", NULL, NULL, NULL, NULL);
	g_at_chat_send(data->chat, "AT+CREG=0", NULL, NULL, NULL, NULL);
	g_at_chat_send(data->chat, "AT+CGREG=0", NULL, NULL, NULL, NULL);

	g_at_chat_send(data->chat, "AT+CFUN=4", cfun_prefix,
						cfun_disable, device, NULL);

	index = connman_device_get_index(device);
	connman_inet_ifdown(index);

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
