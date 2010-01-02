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
#include <errno.h>
#include <string.h>

#include <glib.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/device.h>
#include <connman/inet.h>
#include <connman/log.h>

#include <WiMaxAPI.h>
#include <WiMaxAPIEx.h>

#include "iwmx.h"

/*
 * Connman plugin interface
 *
 * This part deals with the connman internals
 */

/* WiMAX network driver probe/remove, nops */
static int iwmx_cm_network_probe(struct connman_network *nw)
{
	return 0;
}

static void iwmx_cm_network_remove(struct connman_network *nw)
{
}

/*
 * Called by connman when it wants us to tell the device to connect to
 * the network @network_el; the device is @network_el->parent.
 *
 * We do a synchronous call to start the connection; the logic
 * attached to the status change callback will update the connman
 * internals once the change happens.
 */
static int iwmx_cm_network_connect(struct connman_network *nw)
{
	int result;
	struct wmxsdk *wmxsdk;
	const char *station_name = connman_network_get_identifier(nw);

	wmxsdk = connman_device_get_data(connman_network_get_device(nw));
	result = iwmx_sdk_connect(wmxsdk, nw);
	DBG("(nw %p [%s] wmxsdk %p) = %d\n", nw, station_name, wmxsdk, result);
	return result;
}

/*
 * Called by connman to have the device @nw->parent
 * disconnected from @nw.
 *
 * We do a synchronous call to start the disconnection; the logic
 * attached to the status change callback will update the connman
 * internals once the change happens.
 */
static int iwmx_cm_network_disconnect(struct connman_network *nw)
{
	int result;
	struct wmxsdk *wmxsdk;
	const char *station_name = connman_network_get_identifier(nw);

	wmxsdk = connman_device_get_data(connman_network_get_device(nw));
	result = iwmx_sdk_disconnect(wmxsdk);
	DBG("(nw %p [%s] wmxsdk %p) = %d\n", nw, station_name, wmxsdk, result);
	return 0;
}

/*
 * "Driver" for the networks detected by a device.
 */
static struct connman_network_driver iwmx_cm_network_driver = {
	.name		= "iwmx",
	.type		= CONNMAN_NETWORK_TYPE_WIMAX,
	.probe		= iwmx_cm_network_probe,
	.remove		= iwmx_cm_network_remove,
	.connect	= iwmx_cm_network_connect,
	.disconnect	= iwmx_cm_network_disconnect,
};

/*
 * A (maybe) new network is available, create/update its data
 *
 * If the network is new, we create and register a new element; if it
 * is not, we reuse the one in the list.
 *
 * NOTE:
 *   wmxsdk->network_mutex has to be locked
 */
struct connman_network *__iwmx_cm_network_available(
			struct wmxsdk *wmxsdk, const char *station_name,
			const char *station_type,
			const void *sdk_nspname, size_t sdk_nspname_size,
								int strength)
{
	struct connman_network *nw = NULL;
	struct connman_device *dev = wmxsdk->dev;
	char group[3 * strlen(station_name) + 1];
	unsigned cnt;

	nw = connman_device_get_network(dev, station_name);
	if (nw == NULL) {
		DBG("new network %s", station_name);
		nw = connman_network_create(station_name,
					    CONNMAN_NETWORK_TYPE_WIMAX);
		connman_network_set_index(nw, connman_device_get_index(dev));
		connman_network_set_protocol(nw, CONNMAN_NETWORK_PROTOCOL_IP);
		connman_network_set_name(nw, station_name);
		connman_network_set_blob(nw, "WiMAX.NSP.name",
					 sdk_nspname, sdk_nspname_size);
		/* FIXME: add roaming info? */
		/* Set the group name -- this has to be a unique
		 * [a-zA-Z0-9_] string common to all the networks that
		 * are actually the same provider. In WiMAX each
		 * network from the CAPI is a single provider, so we
		 * just set this as the network name, encoded in
		 * hex. */
		for (cnt = 0; station_name[cnt] != 0; cnt++)
			sprintf(group + 3 * cnt, "%02x", station_name[cnt]);
		group[3 * cnt + 1] = 0;
		connman_network_set_group(nw, station_name);
		if (connman_device_add_network(dev, nw) < 0) {
			connman_network_unref(nw);
			goto error_add;
		}
	} else
		DBG("updating network %s nw %p\n", station_name, nw);
	connman_network_set_available(nw, TRUE);
	connman_network_set_strength(nw, strength);
	connman_network_set_string(nw, "WiMAX Network Type", station_type);
error_add:
	return nw;
}

/*
 * A new network is available [locking version]
 *
 * See __iwmx_cm_network_available() for docs
 */
struct connman_network *iwmx_cm_network_available(
			struct wmxsdk *wmxsdk, const char *station_name,
			const char *station_type,
			const void *sdk_nspname, size_t sdk_nspname_size,
								int strength)
{
	struct connman_network *nw;

	g_static_mutex_lock(&wmxsdk->network_mutex);
	nw = __iwmx_cm_network_available(wmxsdk, station_name, station_type,
					sdk_nspname, sdk_nspname_size,
					strength);
	g_static_mutex_unlock(&wmxsdk->network_mutex);
	return nw;
}

/*
 * The device has been enabled, make sure connman knows
 */
static void iwmx_cm_dev_enabled(struct wmxsdk *wmxsdk)
{
	struct connman_device *dev = wmxsdk->dev;
	connman_inet_ifup(connman_device_get_index(dev));
	connman_device_set_powered(dev, TRUE);
}

/*
 * The device has been disabled, make sure connman is aware of it.
 */
static void iwmx_cm_dev_disabled(struct wmxsdk *wmxsdk)
{
	struct connman_device *dev = wmxsdk->dev;
	connman_inet_ifdown(connman_device_get_index(dev));
	connman_device_set_powered(dev, FALSE);
}

/*
 * The device has been (externally to connman) connnected to a
 * network, make sure connman knows.
 *
 * When the device is connected to a network, this function is called
 * to change connman's internal state to reflect the fact.
 *
 * If the change came from an external entity, that means that our
 * connect code wasn't called. Our connect code sets
 * @wmxsdk->connecting_nw to the network we were connecting
 * to. If it is unset, it means an external entity forced the device
 * to connect. In that case, we need to find out which network it was
 * connected to, and create/lookup a @nw for it.
 *
 * Once the nw is set, then we are done.
 */
static void iwmx_cm_dev_connected(struct wmxsdk *wmxsdk)
{
	struct connman_network *nw;

	g_mutex_lock(wmxsdk->connect_mutex);
	nw = wmxsdk->connecting_nw;
	if (nw == NULL) {
		nw = __iwmx_sdk_get_connected_network(wmxsdk);
		if (nw == NULL) {
			connman_error("wmxsdk: can't find connected network\n");
			goto error_nw_find;
		}
	}
	wmxsdk->nw = connman_network_ref(nw);
	wmxsdk->connecting_nw = NULL;
	connman_network_set_method(network, CONNMAN_IPCONFIG_METHOD_DHCP);
	connman_network_set_connected(nw, TRUE);
	DBG("connected to network %s\n",
	    connman_network_get_identifier(nw));
error_nw_find:
	g_mutex_unlock(wmxsdk->connect_mutex);
}

/*
 * The device has been (externally to connman) disconnnected, make
 * sure connman knows
 *
 * We need to reverse the steps done in iwmx_cm_dev_connected().
 * If the event was caused by an external entity and we had no record
 * of being connected to a network...well, bad luck. We'll just
 * pretend it happened ok.
 */
static void __iwmx_cm_dev_disconnected(struct wmxsdk *wmxsdk)
{
	struct connman_network *nw = wmxsdk->nw;

	if (nw != NULL) {
		DBG("disconnected from network %s\n",
					connman_network_get_identifier(nw));
		connman_network_set_connected(nw, FALSE);
		connman_network_unref(nw);
		wmxsdk->nw = NULL;
	} else
		DBG("disconnected from unknown network\n");
}

/*
 * The device has been disconnnected, make sure connman knows
 *
 * See __iwmx_cm_dev_disconnect() for more information.
 */
static void iwmx_cm_dev_disconnected(struct wmxsdk *wmxsdk)
{
	g_mutex_lock(wmxsdk->connect_mutex);
	__iwmx_cm_dev_disconnected(wmxsdk);
	g_mutex_unlock(wmxsdk->connect_mutex);
}

/*
 * Handle a change in state
 *
 * This is were most of the action happens. When the device changes
 * state, this will catch it (through the state change callback or an
 * explicit call) and call iwmx_cm_dev_*ed() to indicate to connman what
 * happened.
 *
 * Finally, cache the new device status.
 */
void __iwmx_cm_state_change(struct wmxsdk *wmxsdk,
					WIMAX_API_DEVICE_STATUS __new_status)
{
	WIMAX_API_DEVICE_STATUS __old_status = wmxsdk->status;
	WIMAX_API_DEVICE_STATUS old_status;
	WIMAX_API_DEVICE_STATUS new_status;

	/*
	 * Simplify state transition computations.
	 *
	 * For practical effects, some states are the same
	 */

#if HAVE_IWMXSDK_STATUS_IDLE
	/* Conection_Idle is the same as Data_Connected */
	if (__old_status == WIMAX_API_DEVICE_STATUS_Connection_Idle)
		old_status = WIMAX_API_DEVICE_STATUS_Data_Connected;
	else
		old_status = __old_status;
	if (__new_status == WIMAX_API_DEVICE_STATUS_Connection_Idle)
		new_status = WIMAX_API_DEVICE_STATUS_Data_Connected;
	else
		new_status = __new_status;
#endif /* #if HAVE_IWMXSDK_STATUS_IDLE */
	/* Radio off: all are just RF_OFF_SW (the highest) */
	switch (__old_status) {
	case WIMAX_API_DEVICE_STATUS_RF_OFF_HW_SW:
	case WIMAX_API_DEVICE_STATUS_RF_OFF_HW:
	case WIMAX_API_DEVICE_STATUS_RF_OFF_SW:
		old_status = WIMAX_API_DEVICE_STATUS_RF_OFF_SW;
		break;
	default:
		old_status = __old_status;
		break;
	}

	switch (__new_status) {
	case WIMAX_API_DEVICE_STATUS_RF_OFF_HW_SW:
	case WIMAX_API_DEVICE_STATUS_RF_OFF_HW:
	case WIMAX_API_DEVICE_STATUS_RF_OFF_SW:
		new_status = WIMAX_API_DEVICE_STATUS_RF_OFF_SW;
		break;
	default:
		new_status = __new_status;
		break;
	}

	/* If no real state change, do nothing */
	if (old_status == new_status) {
		DBG("no state changed\n");
		return;
	} else
		DBG("state change from %d (%d: %s) to %d (%d: %s)\n",
		    old_status, __old_status,
		    iwmx_sdk_dev_status_to_str(__old_status),
		    new_status, __new_status,
		    iwmx_sdk_dev_status_to_str(__new_status));

	/* Cleanup old state */
	switch (old_status) {
	case WIMAX_API_DEVICE_STATUS_UnInitialized:
		/* This means the plugin is starting but the device is
		 * in some state already, so we need to update our
		 * internal knowledge of it. */
		if (new_status > WIMAX_API_DEVICE_STATUS_RF_OFF_SW)
			iwmx_cm_dev_enabled(wmxsdk);
		break;
	case WIMAX_API_DEVICE_STATUS_RF_OFF_SW:
		/* This means the radio is being turned on, so enable
		 * the device ( unless going to uninitialized). */
		if (new_status != WIMAX_API_DEVICE_STATUS_RF_OFF_SW)
			iwmx_cm_dev_enabled(wmxsdk);
		break;
	case WIMAX_API_DEVICE_STATUS_Ready:
		break;
	case WIMAX_API_DEVICE_STATUS_Scanning:
		break;
	case WIMAX_API_DEVICE_STATUS_Connecting:
		break;
	case WIMAX_API_DEVICE_STATUS_Data_Connected:
		iwmx_cm_dev_disconnected(wmxsdk);
		break;
	default:
		connman_error("wmxsdk: unknown old status %d\n", old_status);
		return;
	};

	/* Implement new state */
	switch (new_status) {
	case WIMAX_API_DEVICE_STATUS_UnInitialized:
		break;
	case WIMAX_API_DEVICE_STATUS_RF_OFF_SW:
		/* This means the radio is being turned off, so
		 * disable the device unless coming from uninitialized. */
		if (old_status != WIMAX_API_DEVICE_STATUS_UnInitialized)
			iwmx_cm_dev_disabled(wmxsdk);
		break;
	case WIMAX_API_DEVICE_STATUS_Ready:
		break;
	case WIMAX_API_DEVICE_STATUS_Scanning:
		break;
	case WIMAX_API_DEVICE_STATUS_Connecting:
		break;
	case WIMAX_API_DEVICE_STATUS_Data_Connected:
		iwmx_cm_dev_connected(wmxsdk);
		break;
	default:
		connman_error("wmxsdk: unknown new status %d\n", old_status);
		return;
	};
	wmxsdk->status = __new_status;
}

/*
 * Implement a device state transition [locking version]
 *
 * See __iwmx_cm_state_change()
 */
void iwmx_cm_state_change(struct wmxsdk *wmxsdk,
				 WIMAX_API_DEVICE_STATUS __new_status)
{
	g_mutex_lock(wmxsdk->status_mutex);
	__iwmx_cm_state_change(wmxsdk, __new_status);
	g_mutex_unlock(wmxsdk->status_mutex);
}

/*
 * Read the cached device status
 */
WIMAX_API_DEVICE_STATUS iwmx_cm_status_get(struct wmxsdk *wmxsdk)
{
	WIMAX_API_DEVICE_STATUS status;

	g_mutex_lock(wmxsdk->status_mutex);
	status = wmxsdk->status;
	g_mutex_unlock(wmxsdk->status_mutex);
	return status;
}

/*
 * Called by connman when a device is enabled by the user
 *
 * We need to turn the radio on; the state change function will poke
 * the internals.
 */
static int iwmx_cm_enable(struct connman_device *dev)
{
	int result;
	struct wmxsdk *wmxsdk = connman_device_get_data(dev);

	connman_inet_ifup(connman_device_get_index(dev));
	result = iwmx_sdk_rf_state_set(wmxsdk, WIMAX_API_RF_ON);
	return result;
}

/*
 * Called by connman when a device is disabled by the user
 *
 * Simple: just make sure the radio is off; the state change function
 * will poke the internals.
 */
static int iwmx_cm_disable(struct connman_device *dev)
{
	int result;
	struct wmxsdk *wmxsdk = connman_device_get_data(dev);

	result = iwmx_sdk_rf_state_set(wmxsdk, WIMAX_API_RF_OFF);
	connman_inet_ifdown(connman_device_get_index(dev));
	return 0;
}

/*
 * Probe deferred call from when the mainloop is idle
 *
 * probe() schedules this to be called from the mainloop when idle to
 * do a device status evaluation. Needed because of an internal race
 * condition in connman. FIXME: deploy into _probe() when fixed.
 */
static gboolean __iwmx_cm_probe_dpc(gpointer _wmxsdk)
{
	int result;
	struct wmxsdk *wmxsdk = _wmxsdk;
	result = iwmx_sdk_get_device_status(wmxsdk);
	if (result < 0)
		connman_error("wmxsdk: can't get status: %d\n", result);
	else
		iwmx_cm_state_change(wmxsdk, result);
	return FALSE;
}

/*
 * Called by connman when a new device pops in
 *
 * We allocate our private structure, register with the WiMAX API,
 * open their device, subscribe to all the callbacks.
 *
 * At the end, we launch a deferred call (to work around current
 * connman issues that need to be fixed in the future) and update the
 * device's status. This allows us to pick up the current status and
 * adapt connman's idea of the device to it.
 */
static int iwmx_cm_probe(struct connman_device *dev)
{
	int result;
	struct wmxsdk *wmxsdk = NULL;

	wmxsdk = connman_device_get_data(dev);
	if (wmxsdk == NULL)
		/* not called from a discovery done by the WiMAX
		 * Network Service, ignore */
		return -ENODEV;

	result = iwmx_sdk_setup(wmxsdk);
	if (result < 0)
		goto error_setup;

	/* There is a race condition in the connman core that doesn't
	 * allow us to call this directly and things to work properly
	 * FIXME FIXME FIXME: merge _dpc call in here when connman is fixed */
	g_idle_add(__iwmx_cm_probe_dpc, wmxsdk);
	return 0;

	iwmx_sdk_remove(wmxsdk);
error_setup:
	return result;
}

/*
 * Called when a device is removed from connman
 *
 * Cleanup all that is done in _probe. Remove callbacks, unregister
 * from the WiMAX API.
 */
static void iwmx_cm_remove(struct connman_device *dev)
{
	struct wmxsdk *wmxsdk = connman_device_get_data(dev);
	iwmx_sdk_remove(wmxsdk);
}

/*
 * Called by connman to ask the device to scan for networks
 *
 * We have set in the WiMAX API the scan result callbacks, so we just
 * start a simple scan (not a wide one).
 *
 * First we obtain the current list of networks and pass it to the
 * callback processor. Then we start an scan cycle.
 */
static int iwmx_cm_scan(struct connman_device *dev)
{
	struct wmxsdk *wmxsdk = connman_device_get_data(dev);
	return iwmx_sdk_scan(wmxsdk);
}

/*
 * Driver for a WiMAX API based device.
 */
static struct connman_device_driver iwmx_cm_device_driver = {
	.name		= "iwmx",
	.type		= CONNMAN_DEVICE_TYPE_WIMAX,
	.probe		= iwmx_cm_probe,
	.remove		= iwmx_cm_remove,
	.enable		= iwmx_cm_enable,
	.disable	= iwmx_cm_disable,
	.scan		= iwmx_cm_scan,
};

static int iwmx_cm_init(void)
{
	int result;

	result = connman_device_driver_register(&iwmx_cm_device_driver);
	if (result < 0)
		goto error_driver_register;
	result = connman_network_driver_register(&iwmx_cm_network_driver);
	if (result < 0)
		goto error_network_driver_register;
	result = iwmx_sdk_api_init();
	if (result < 0)
		goto error_iwmx_sdk_init;
	return 0;

error_iwmx_sdk_init:
	connman_network_driver_unregister(&iwmx_cm_network_driver);
error_network_driver_register:
	connman_device_driver_unregister(&iwmx_cm_device_driver);
error_driver_register:
	return result;
}

static void iwmx_cm_exit(void)
{
	iwmx_sdk_api_exit();
	connman_network_driver_unregister(&iwmx_cm_network_driver);
	connman_device_driver_unregister(&iwmx_cm_device_driver);
}

CONNMAN_PLUGIN_DEFINE(iwmx, "Intel WiMAX SDK / Common API plugin",
			CONNMAN_VERSION, CONNMAN_PLUGIN_PRIORITY_LOW,
						iwmx_cm_init, iwmx_cm_exit);
