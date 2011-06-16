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
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <net/if.h>

#include <glib.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/device.h>
#include <connman/inet.h>
#include <connman/log.h>

#include <WiMaxType.h>
#include <WiMaxAPI.h>
#include <WiMaxAPIEx.h>

#include "iwmx.h"

/* Yes, this is dirty; see above on IWMX_SDK_DEV_MAX*/
static struct wmxsdk *g_iwmx_sdk_devs[IWMX_SDK_DEV_MAX];

static struct wmxsdk *deviceid_to_wmxsdk(WIMAX_API_DEVICE_ID *device_id)
{
	unsigned cnt;
	for (cnt = 0; cnt < IWMX_SDK_DEV_MAX; cnt++) {
		struct wmxsdk *wmxsdk = g_iwmx_sdk_devs[cnt];
		if (wmxsdk &&
		    wmxsdk->device_id.deviceIndex == device_id->deviceIndex)
			return wmxsdk;
	}
	return NULL;
}

static WIMAX_API_DEVICE_ID g_api;


/*
 * FIXME: pulled it it out of some hole
 *
 * the cinr to percentage computation comes from the L3/L4 doc
 *
 * But some other places (L4 code) have a more complex, seemingly
 * logarithmical computation.
 *
 * Oh well...
 *
 */
static int cinr_to_percentage(int cinr)
{
	int strength;
	if (cinr <= -5)
		strength = 0;
	else if (cinr >= 25)
		strength = 100;
	else	/* Calc percentage on the value from -5 to 25 */
		strength = ((100UL * (cinr - -5)) / (25 - -5));
	return strength;
}

/*
 * Convert a WiMAX API status to an string.
 */
const char *iwmx_sdk_dev_status_to_str(WIMAX_API_DEVICE_STATUS status)
{
	switch (status) {
	case WIMAX_API_DEVICE_STATUS_UnInitialized:
		return "Uninitialized";
		break;
	case WIMAX_API_DEVICE_STATUS_RF_OFF_HW_SW:
		return "Device RF Off(both H/W and S/W)";
		break;
	case WIMAX_API_DEVICE_STATUS_RF_OFF_HW:
		return "Device RF Off(via H/W switch)";
	case WIMAX_API_DEVICE_STATUS_RF_OFF_SW:
		return "Device RF Off(via S/W switch)";
	case WIMAX_API_DEVICE_STATUS_Ready:
		return "Device is ready";
	case WIMAX_API_DEVICE_STATUS_Scanning:
		return "Device is scanning";
	case WIMAX_API_DEVICE_STATUS_Connecting:
		return "Connection in progress";
	case WIMAX_API_DEVICE_STATUS_Data_Connected:
		return "Layer 2 connected";
#if HAVE_IWMXSDK_STATUS_IDLE
	case WIMAX_API_DEVICE_STATUS_Connection_Idle:
		return "Idle connection";
#endif /* #if HAVE_IWMXSDK_STATUS_IDLE */
	default:
		return "unknown state";
	}
}

/*
 * Get the device's status from the device
 *
 * Does NOT cache the result
 * Does NOT trigger a state change in connman
 *
 * Returns < 0 errno code on error, status code if ok.
 */
WIMAX_API_DEVICE_STATUS iwmx_sdk_get_device_status(struct wmxsdk *wmxsdk)
{
	WIMAX_API_RET r;
	char errstr[512];
	UINT32 errstr_size = sizeof(errstr);

	WIMAX_API_DEVICE_STATUS dev_status;
	WIMAX_API_CONNECTION_PROGRESS_INFO pi;

	r = GetDeviceStatus(&wmxsdk->device_id, &dev_status, &pi);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&wmxsdk->device_id, r, errstr, &errstr_size);
		connman_error("wmxsdk: Cannot read device state: %d (%s)\n",
			r, errstr);
		dev_status = -EIO;
	}
	return dev_status;
}

/*
 * Get the device's status from the device but return a string describing it
 *
 * Same conditions as iwmx_sdk_get_device_status().
 */
static const char *iwmx_sdk_get_device_status_str(struct wmxsdk *wmxsdk)
{
	const char *result;
	WIMAX_API_DEVICE_STATUS dev_status;

	dev_status = iwmx_sdk_get_device_status(wmxsdk);
	if ((int) dev_status < 0)
		result = "cannot read device state";
	else
		result = iwmx_sdk_dev_status_to_str(dev_status);
	return result;
}

/*
 * Translate a WiMAX network type to a readable name.
 */
static const char *iwmx_sdk_network_type_name(enum _WIMAX_API_NETWORK_TYPE network_type)
{
	static char *network_type_name[] = {
		[WIMAX_API_HOME] = "",
		[WIMAX_API_PARTNER] = " (partner network)",
		[WIMAX_API_ROAMING_PARTNER] = " (roaming partner network)",
		[WIMAX_API_UNKNOWN] = " (unknown network)",
	};
	if (network_type > WIMAX_API_UNKNOWN)
		return "(BUG! UNKNOWN NETWORK_TYPE MODE)";
	else
		return network_type_name[network_type];
}

/*
 * If the device is connected but we don't know about the network,
 * create the knowledge of it.
 *
 * Asks the WiMAX API to report which NSP we are connected to and we
 * create/update a network_el in the device's network list. Then
 * return it.
 *
 * Returns NULL on error.
 *
 * NOTE: wmxsdk->network_mutex has to be taken
 */
struct connman_network *__iwmx_sdk_get_connected_network(struct wmxsdk *wmxsdk)
{
	struct connman_network *nw;

	WIMAX_API_CONNECTED_NSP_INFO nsp_info;
	WIMAX_API_RET r;
	char errstr[512];
	UINT32 errstr_size = sizeof(errstr);

	/* The device is getting connected due to an external (to
	 * connman) event; find which is the nw we are getting
	 * connected to. if we don't have it, add it */
	r = GetConnectedNSP(&wmxsdk->device_id, &nsp_info);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&wmxsdk->device_id, r, errstr, &errstr_size);
		connman_error(
			"wmxsdk: Cannot get connected NSP info: %d (%s)\n",
			r, errstr);
		strcpy((char *) nsp_info.NSPName, "unknown");
		nw = iwmx_cm_network_available(
			wmxsdk, "unknown",
			nsp_info.NSPName, strlen((char *) nsp_info.NSPName) + 1,
			cinr_to_percentage(nsp_info.CINR - 10));
	} else {
		nw = iwmx_cm_network_available(
			wmxsdk, (char *) nsp_info.NSPName,
			nsp_info.NSPName, strlen((char *) nsp_info.NSPName) + 1,
			cinr_to_percentage(nsp_info.CINR - 10));
	}
	return nw;
}

/*
 * Callback for a RF State command
 *
 * Called by the WiMAX API when a command sent to change the RF state
 * is completed. This is just a confirmation of what happened with the
 * command.
 *
 * We don't do anything, as when the device changes state, the state
 * change callback is called and that will fiddle with the connman
 * internals.
 */
static void __iwmx_sdk_rf_state_cb(WIMAX_API_DEVICE_ID *device_id,
				   WIMAX_API_RF_STATE rf_state)
{
	DBG("rf_state changed to %d\n", rf_state);
}

/*
 * Turn the radio on or off
 *
 * First it checks that we are in the right state before doing
 * anything; there might be no need to do anything.
 *
 * Issue a command to the WiMAX API, wait for a callback confirming it
 * is done. Sometimes the callback is missed -- in that case, do force
 * a state change evaluation.
 *
 * Frustration note:
 *
 *      Geezoos efing Xist, they make difficult even the most simple
 *      of the operations
 *
 *      This thing is definitely a pain. If the radio is ON already
 *      and you switch it on again...well, there is no way to tell
 *      because you don't get a callback saying it basically
 *      suceeded. But on the other hand, if the thing was in a
 *      different state and action needs to be taken, you have to wait
 *      for a callback to confirm it's done. However, there is also an
 *      state change callback, which is almost the same, so now you
 *      have to handle things in two "unrelated" threads of execution.
 *
 *      How the shpx are you expected to tell the difference? Check
 *      status first? On timeout? Nice gap (eighteen wheeler size) for
 *      race conditions.
 */
int iwmx_sdk_rf_state_set(struct wmxsdk *wmxsdk, WIMAX_API_RF_STATE rf_state)
{
	int result;

	WIMAX_API_RET r;
	char errstr[512];
	UINT32 errstr_size = sizeof(errstr);
	WIMAX_API_DEVICE_STATUS dev_status;

	g_assert(rf_state == WIMAX_API_RF_ON || rf_state == WIMAX_API_RF_OFF);

	/* Guess what the current radio state is; if it is ON
	 * already, don't redo it. */
	dev_status = iwmx_sdk_get_device_status(wmxsdk);
	if ((int) dev_status < 0) {
		result = dev_status;
		goto error_get_status;
	}
	switch (dev_status) {
	case WIMAX_API_DEVICE_STATUS_UnInitialized:
		result = -EINVAL;
		goto error_cant_do;
	case WIMAX_API_DEVICE_STATUS_RF_OFF_HW_SW:
	case WIMAX_API_DEVICE_STATUS_RF_OFF_HW:
		connman_error(
			"wmxsdk: cannot turn on radio: hw switch is off\n");
		result = -EPERM;
		goto error_cant_do;
		break;
	case WIMAX_API_DEVICE_STATUS_RF_OFF_SW:
		if (rf_state == WIMAX_API_RF_OFF) {
			result = 0;
			DBG("radio is already off\n");
			goto out_done;
		}
		break;
	case WIMAX_API_DEVICE_STATUS_Ready:
	case WIMAX_API_DEVICE_STATUS_Scanning:
	case WIMAX_API_DEVICE_STATUS_Connecting:
	case WIMAX_API_DEVICE_STATUS_Data_Connected:
#if HAVE_IWMXSDK_STATUS_IDLE
	case WIMAX_API_DEVICE_STATUS_Connection_Idle:
#endif
		if (rf_state == WIMAX_API_RF_ON) {
			result = 0;
			DBG("radio is already on\n");
			goto out_done;
		}
		break;
	default:
		g_assert(1);
	}
	/* Ok, flip the radio */
	r = CmdControlPowerManagement(&wmxsdk->device_id, rf_state);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&wmxsdk->device_id, r, errstr, &errstr_size);
		connman_error("wmxsdk: Cannot flip radio to %d: %d (%s) "
			      "[device is in state %s]\n",
			      rf_state, r, errstr,
			      iwmx_sdk_get_device_status_str(wmxsdk));
		result = -EIO;
	} else
		result = -EINPROGRESS;
out_done:
error_cant_do:
error_get_status:
	return result;
}

/*
 * Callback for a Connect command
 *
 * Called by the WiMAX API when a command sent to connect is
 * completed. This is just a confirmation of what happened with the
 * command.
 *
 * WE DON'T DO MUCH HERE -- the real meat happens when a state change
 * callback is sent, where we detect we move to connected state (or
 * from disconnecting to something else); the state change callback is
 * called and that will fiddle with the connman internals.
 */
static void __iwmx_sdk_connect_cb(WIMAX_API_DEVICE_ID *device_id,
				  WIMAX_API_NETWORK_CONNECTION_RESP resp)
{
	WIMAX_API_DEVICE_STATUS status;
	struct wmxsdk *wmxsdk = deviceid_to_wmxsdk(device_id);

	status = iwmx_cm_status_get(wmxsdk);
	if (resp == WIMAX_API_CONNECTION_SUCCESS) {
		if (status != WIMAX_API_DEVICE_STATUS_Data_Connected
#if HAVE_IWMXSDK_STATUS_IDLE
		    && status != WIMAX_API_DEVICE_STATUS_Connection_Idle
#endif
			)
			connman_error("wmxsdk: error: connect worked, but state"
				      " didn't change (now it is %d [%s])\n",
				      status,
				      iwmx_sdk_dev_status_to_str(status));
	} else
		connman_error("wmxsdk: failed to connect (status %d: %s)\n",
			      status, iwmx_sdk_dev_status_to_str(status));
}

/*
 * Connect to a network
 *
 * This function starts the connection process to a given network;
 * when the device changes status, the status change callback will
 * tell connman if the network is finally connected or not.
 *
 * One of the reasons it is done like that is to allow external tools
 * to control the device and the plugin just passing the status so
 * connman displays the right info.
 */
int iwmx_sdk_connect(struct wmxsdk *wmxsdk, struct connman_network *nw)
{
	int result;

	WIMAX_API_RET r;
	char errstr[512];
	UINT32 errstr_size = sizeof(errstr);
	WIMAX_API_DEVICE_STATUS dev_status;
	const char *station_name = connman_network_get_identifier(nw);
	const void *sdk_nspname;
	unsigned int sdk_nspname_size;

	g_mutex_lock(wmxsdk->connect_mutex);
	/* Guess what the current radio state is; if it is ON
	 * already, don't redo it. */
	dev_status = iwmx_cm_status_get(wmxsdk);
	if ((int) dev_status < 0) {
		result = dev_status;
		goto error_get_status;
	}
	switch (dev_status) {
	case WIMAX_API_DEVICE_STATUS_UnInitialized:
		connman_error("wmxsdk: SW BUG? HW is uninitialized\n");
		result = -EINVAL;
		goto error_cant_do;
	case WIMAX_API_DEVICE_STATUS_RF_OFF_HW_SW:
	case WIMAX_API_DEVICE_STATUS_RF_OFF_HW:
	case WIMAX_API_DEVICE_STATUS_RF_OFF_SW:
		connman_error("wmxsdk: Cannot connect: radio is off\n");
		result = -EPERM;
		goto error_cant_do;
	case WIMAX_API_DEVICE_STATUS_Ready:
	case WIMAX_API_DEVICE_STATUS_Scanning:
		break;
	case WIMAX_API_DEVICE_STATUS_Connecting:
		DBG("Connect already pending, waiting for it\n");
		result = -EINPROGRESS;
		goto error_cant_do;
	case WIMAX_API_DEVICE_STATUS_Data_Connected:
#if HAVE_IWMXSDK_STATUS_IDLE
	case WIMAX_API_DEVICE_STATUS_Connection_Idle:
#endif
		connman_error("wmxsdk: BUG? need to disconnect?\n");
		result = -EINVAL;
		goto error_cant_do;
	default:
		g_assert(1);
	}

	/* Ok, do the connection, wait for a callback */
	wmxsdk->connecting_nw = connman_network_ref(nw);
	sdk_nspname = connman_network_get_blob(nw, "WiMAX.NSP.name",
							&sdk_nspname_size);
	g_assert(sdk_nspname != NULL);
	r = CmdConnectToNetwork(&wmxsdk->device_id, (void *) sdk_nspname, 0, 0);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&wmxsdk->device_id, r, errstr, &errstr_size);
		connman_error("wmxsdk: Cannot connect to network %s: %d (%s)"
			      " - device is in state '%s'\n",
			      station_name, r, errstr,
			      iwmx_sdk_get_device_status_str(wmxsdk));
		result = -EIO;
		connman_network_unref(nw);
		wmxsdk->connecting_nw = NULL;
	} else
		result = -EINPROGRESS;
error_cant_do:
error_get_status:
	g_mutex_unlock(wmxsdk->connect_mutex);
	return result;
}

/*
 * Callback for a Disconnect command
 *
 * Called by the WiMAX API when a command sent to connect is
 * completed. This is just a confirmation of what happened with the
 * command.
 *
 * When the device changes state, the state change callback is called
 * and that will fiddle with the connman internals.
 *
 * We just update the result of the command and wake up anybody who is
 * waiting for this conditional variable.
 */
static void __iwmx_sdk_disconnect_cb(WIMAX_API_DEVICE_ID *device_id,
				     WIMAX_API_NETWORK_CONNECTION_RESP resp)
{
	struct wmxsdk *wmxsdk = deviceid_to_wmxsdk(device_id);
	WIMAX_API_DEVICE_STATUS status;

	status = iwmx_cm_status_get(wmxsdk);
	if (resp == WIMAX_API_CONNECTION_SUCCESS) {
		if (status == WIMAX_API_DEVICE_STATUS_Data_Connected
#if HAVE_IWMXSDK_STATUS_IDLE
		    || status == WIMAX_API_DEVICE_STATUS_Connection_Idle
#endif
			)
			connman_error("wmxsdk: error: disconnect worked, "
				      "but state didn't change (now it is "
				      "%d [%s])\n", status,
				      iwmx_sdk_dev_status_to_str(status));
	} else
		connman_error("wmxsdk: failed to disconnect (status %d: %s)\n",
			      status, iwmx_sdk_dev_status_to_str(status));
}

/*
 * Disconnect from a network
 *
 * This function tells the device to disconnect; the state change
 * callback will take care of inform connman's internals.
 */
int iwmx_sdk_disconnect(struct wmxsdk *wmxsdk)
{
	int result;

	WIMAX_API_RET r;
	char errstr[512];
	UINT32 errstr_size = sizeof(errstr);
	WIMAX_API_DEVICE_STATUS dev_status;

	g_mutex_lock(wmxsdk->connect_mutex);
	/* Guess what the current radio state is; if it is ON
	 * already, don't redo it. */
	dev_status = iwmx_sdk_get_device_status(wmxsdk);
	if ((int) dev_status < 0) {
		result = dev_status;
		goto error_get_status;
	}
	switch (dev_status) {
	case WIMAX_API_DEVICE_STATUS_UnInitialized:
		connman_error("wmxsdk: SW BUG? HW is uninitialized\n");
		result = -EINVAL;
		goto error_cant_do;
	case WIMAX_API_DEVICE_STATUS_RF_OFF_HW_SW:
	case WIMAX_API_DEVICE_STATUS_RF_OFF_HW:
	case WIMAX_API_DEVICE_STATUS_RF_OFF_SW:
		DBG("Cannot disconnect, radio is off; ignoring\n");
		result = 0;
		goto error_cant_do;
	case WIMAX_API_DEVICE_STATUS_Ready:
	case WIMAX_API_DEVICE_STATUS_Scanning:
		DBG("Cannot disconnect, already disconnected; ignoring\n");
		result = 0;
		goto error_cant_do;
	case WIMAX_API_DEVICE_STATUS_Connecting:
	case WIMAX_API_DEVICE_STATUS_Data_Connected:
#if HAVE_IWMXSDK_STATUS_IDLE
	case WIMAX_API_DEVICE_STATUS_Connection_Idle:
#endif
		break;
	default:
		g_assert(1);
	}
	/* Ok, flip the radio */
	r = CmdDisconnectFromNetwork(&wmxsdk->device_id);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&wmxsdk->device_id, r, errstr, &errstr_size);
		connman_error("wmxsdk: Cannot disconnect from network: "
			      "%d (%s)\n", r, errstr);
		result = -EIO;
	} else
		result = -EINPROGRESS;
error_cant_do:
error_get_status:
	g_mutex_unlock(wmxsdk->connect_mutex);
	return result;
}

/*
 * Callback for state change messages
 *
 * Just pass them to the state transition handler
 */
static void __iwmx_sdk_state_change_cb(WIMAX_API_DEVICE_ID *device_id,
					WIMAX_API_DEVICE_STATUS status,
					WIMAX_API_STATUS_REASON reason,
					WIMAX_API_CONNECTION_PROGRESS_INFO pi)
{
	struct wmxsdk *wmxsdk = deviceid_to_wmxsdk(device_id);
	iwmx_cm_state_change(wmxsdk, status);
}

/*
 * Called by _iwmx_sdk_*scan_cb() when [wide or preferred] scan results
 * are available.
 *
 * From here we update the connman core idea of which networks are
 * available.
 */
static void __iwmx_sdk_scan_common_cb(WIMAX_API_DEVICE_ID *device_id,
				      WIMAX_API_NSP_INFO_EX *nsp_list,
				      UINT32 nsp_list_size)
{
	struct wmxsdk *wmxsdk = deviceid_to_wmxsdk(device_id);
	unsigned itr;
	char station_name[256];

	g_static_mutex_lock(&wmxsdk->network_mutex);
	for (itr = 0; itr < nsp_list_size; itr++) {
		int strength;
		WIMAX_API_NSP_INFO_EX *nsp_info = &nsp_list[itr];
		snprintf(station_name, sizeof(station_name),
			 "%s", (char *)nsp_info->NSPName);
		/* CAPI is reporing link quality as zero -- if it is
		 * zero, check if it is a bug by computing it based on
		 * CINR. If it is different, use the computed one. */
		strength = nsp_info->linkQuality;
		if (strength == 0) {	/* huh */
			int linkq_expected =
				cinr_to_percentage(nsp_info->CINR - 10);
			if (linkq_expected != strength)
				strength = linkq_expected;
		}

		__iwmx_cm_network_available(
			wmxsdk, station_name,
			nsp_info->NSPName,
			strlen((char *) nsp_info->NSPName) + 1,
			strength);
	}
	g_static_mutex_unlock(&wmxsdk->network_mutex);
}

/*
 * Called by the WiMAX API when we get a wide scan result
 *
 * We treat them same as wide, so we just call that.
 */
static void __iwmx_sdk_wide_scan_cb(WIMAX_API_DEVICE_ID *device_id,
				    WIMAX_API_NSP_INFO_EX *nsp_list,
				    UINT32 nsp_list_size)
{
	__iwmx_sdk_scan_common_cb(device_id, nsp_list, nsp_list_size);
}

/*
 * Called by the WiMAX API when we get a normal (non wide) scan result
 *
 * We treat them same as wide, so we just call that.
 */
static void __iwmx_sdk_scan_cb(WIMAX_API_DEVICE_ID *device_id,
				WIMAX_API_NSP_INFO_EX *nsp_list,
				UINT32 nsp_list_size, UINT32 searchProgress)
{
	__iwmx_sdk_scan_common_cb(device_id, nsp_list, nsp_list_size);
}

/*
 * Called to ask the device to scan for networks
 *
 * We don't really scan as the WiMAX SDK daemon scans in the
 * background for us. We just get the results. See iwmx_sdk_setup().
 */
int iwmx_sdk_scan(struct wmxsdk *wmxsdk)
{
	int result;

	UINT32 nsp_list_length = 10;
	WIMAX_API_NSP_INFO_EX nsp_list[10];	/* FIXME: up to 32? */

	WIMAX_API_RET r;
	char errstr[512];
	UINT32 errstr_size = sizeof(errstr);

	r = GetNetworkListEx(&wmxsdk->device_id, nsp_list, &nsp_list_length);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&wmxsdk->device_id, r, errstr, &errstr_size);
		connman_error("wmxsdk: Cannot get network list: %d (%s)\n",
			      r, errstr);
		result = -EIO;
		goto error_scan;
	}

	if (nsp_list_length == 0)
		DBG("no networks\n");
	else
		__iwmx_sdk_scan_common_cb(&wmxsdk->device_id, nsp_list,
					nsp_list_length);
	result = 0;
error_scan:
	return result;
}

/*
 * Initialize the WiMAX API, register with it, setup callbacks
 *
 * Called through
 *
 * iwmx_sdk_dev_add
 *   connman_inet_create_device
 *      connman_register
 *         iwmx_cm_probe()
 */
int iwmx_sdk_setup(struct wmxsdk *wmxsdk)
{
	int result;

	WIMAX_API_RET r;

	char errstr[512];
	UINT32 errstr_size = sizeof(errstr);

	result = -ENFILE;

	/* device_id initialized by iwmx_sdk_dev_add */

	r = WiMaxDeviceOpen(&wmxsdk->device_id);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&wmxsdk->device_id, r, errstr, &errstr_size);
		connman_error("wmxsdk: Cannot open device: %d (%s)\n",
			      r, errstr);
		goto error_wimaxdeviceopen;
	}

	/*
	 * We scan in auto mode (in the background)
	 *
	 * Otherwise is messy -- if we have connman triggering a scan
	 * when we call iwmx_cm_scan() -> iwmx_sdk_scan(), most of the
	 * times that causes a race condition when the UI asks for a
	 * scan right before displaying the network menu. As there is
	 * no way to cancel an ongoing scan before connecting, we are
	 * stuck. So we do auto bg and have iwmx_sdk_scan() just return
	 * the current network list.
	 */
	r = SetConnectionMode(&wmxsdk->device_id,
			      WIMAX_API_CONNECTION_AUTO_SCAN_MANUAL_CONNECT);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&wmxsdk->device_id, r, errstr, &errstr_size);
		connman_error("wmxsdk: Cannot set connectin mode to manual: "
			      "%d (%s)\n", r, errstr);
		goto error_connection_mode;
	}

	r = SubscribeControlPowerManagement(&wmxsdk->device_id,
					    __iwmx_sdk_rf_state_cb);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&wmxsdk->device_id, r, errstr, &errstr_size);
		connman_error("wmxsdk: Cannot subscribe to radio change "
			      "events: %u (%s)\n", r, errstr);
		result = -EIO;
		goto error_subscribe_rf_state;
	}

	r = SubscribeDeviceStatusChange(&wmxsdk->device_id,
					__iwmx_sdk_state_change_cb);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&wmxsdk->device_id, r, errstr, &errstr_size);
		connman_error("wmxsdk: Cannot subscribe to state chaneg events:"
			      "%d (%s)\n", r, errstr);
		goto error_subscribe_state_change;
	}

	r = SubscribeNetworkSearchWideScanEx(&wmxsdk->device_id,
					     __iwmx_sdk_wide_scan_cb);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&wmxsdk->device_id, r, errstr, &errstr_size);
		connman_error("wmxsdk: Cannot subscribe to wide scan events: "
			      "%d (%s)\n", r, errstr);
		goto error_subscribe_wide_scan;
	}
	r = SubscribeNetworkSearchEx(&wmxsdk->device_id, __iwmx_sdk_scan_cb);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&wmxsdk->device_id, r, errstr, &errstr_size);
		connman_error("wmxsdk: Cannot subscribe to scan events: "
			      "%d (%s)\n", r, errstr);
		goto error_subscribe_scan;
	}

	r = SubscribeConnectToNetwork(&wmxsdk->device_id,
				      __iwmx_sdk_connect_cb);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&wmxsdk->device_id, r, errstr, &errstr_size);
		connman_error("wmxsdk: Cannot subscribe to connect events: "
			      "%d (%s)\n", r, errstr);
		goto error_subscribe_connect;
	}

	r = SubscribeDisconnectToNetwork(&wmxsdk->device_id,
					 __iwmx_sdk_disconnect_cb);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&wmxsdk->device_id, r, errstr, &errstr_size);
		connman_error("wmxsdk: Cannot subscribe to disconnect events: "
			      "%d (%s)\n", r, errstr);
		goto error_subscribe_disconnect;
	}
	result = 0;
out:
	return result;

	UnsubscribeDisconnectToNetwork(&wmxsdk->device_id);
error_subscribe_disconnect:
	UnsubscribeConnectToNetwork(&wmxsdk->device_id);
error_subscribe_connect:
	UnsubscribeNetworkSearchEx(&wmxsdk->device_id);
error_subscribe_scan:
	UnsubscribeNetworkSearchWideScanEx(&wmxsdk->device_id);
error_subscribe_wide_scan:
	UnsubscribeDeviceStatusChange(&wmxsdk->device_id);
error_subscribe_state_change:
	UnsubscribeControlPowerManagement(&wmxsdk->device_id);
error_subscribe_rf_state:
error_connection_mode:
	WiMaxDeviceClose(&wmxsdk->device_id);
error_wimaxdeviceopen:
	goto out;
}

/*
 * Called when a device is removed from connman
 *
 * Cleanup all that is done in iwmx_sdk_setup(). Remove callbacks,
 * unregister from the WiMAX API.
 */
void iwmx_sdk_remove(struct wmxsdk *wmxsdk)
{
	UnsubscribeDisconnectToNetwork(&wmxsdk->device_id);
	UnsubscribeConnectToNetwork(&wmxsdk->device_id);
	UnsubscribeNetworkSearchEx(&wmxsdk->device_id);
	UnsubscribeNetworkSearchWideScanEx(&wmxsdk->device_id);
	UnsubscribeDeviceStatusChange(&wmxsdk->device_id);
	UnsubscribeControlPowerManagement(&wmxsdk->device_id);
	WiMaxDeviceClose(&wmxsdk->device_id);
}

static void iwmx_sdk_dev_add(unsigned idx, unsigned api_idx, const char *name)
{
	int result, ifindex;
	struct wmxsdk *wmxsdk;
	const char *s;

	if (idx >= IWMX_SDK_DEV_MAX) {
		connman_error("BUG! idx (%u) >= IWMX_SDK_DEV_MAX (%u)\n",
			      idx, IWMX_SDK_DEV_MAX);
		goto error_bug;
	}
	if (g_iwmx_sdk_devs[idx] != NULL) {
		connman_error("BUG! device index %u already enumerated?\n",
			      idx);
		goto error_bug;
	}

	wmxsdk = malloc(sizeof(*wmxsdk));
	if (wmxsdk == NULL) {
		connman_error("Can't allocate %zu bytes\n",
			      sizeof(*wmxsdk));
		goto error_bug;
	}

	memset(wmxsdk, 0, sizeof(*wmxsdk));
	wmxsdk_init(wmxsdk);
	/*
	 * This depends on a hack in the WiMAX Network Service; it has
	 * to return, as part of the device name, a string "if:IFNAME"
	 * where the OS's device name is stored.
	 */
	s = strstr(name, "if:");
	if (s == NULL
	    || sscanf(s, "if:%15[^ \f\n\r\t\v]", wmxsdk->ifname) != 1) {
		connman_error("Cannot extract network interface name off '%s'",
			      name);
		goto error_noifname;
	}
	DBG("network interface name: '%s'", wmxsdk->ifname);

	ifindex = if_nametoindex(wmxsdk->ifname);
	if (ifindex <= 0) {
		result = -ENFILE;
		connman_error("wxmsdk: %s: cannot find interface index\n",
			      wmxsdk->ifname);
		goto error_noifname;
	}

	wmxsdk->dev = connman_inet_create_device(ifindex);
	if (wmxsdk->dev == NULL) {
		connman_error("wmxsdk: %s: failed to create connman_device\n",
			      name);
		goto error_create;
	}
	strncpy(wmxsdk->name, name, sizeof(wmxsdk->name));
	connman_device_set_data(wmxsdk->dev, wmxsdk);

	wmxsdk->device_id.privilege = WIMAX_API_PRIVILEGE_READ_WRITE;
	wmxsdk->device_id.deviceIndex = api_idx;

	result = connman_device_register(wmxsdk->dev);
	if (result < 0) {
		connman_error("wmxsdk: %s: failed to register: %d\n",
			      wmxsdk->ifname, result);
		goto error_dev_add;
	}
	g_iwmx_sdk_devs[idx] = wmxsdk;
	return;

error_dev_add:
	wmxsdk->name[0] = 0;
	connman_device_unref(wmxsdk->dev);
	wmxsdk->dev = NULL;
error_noifname:
error_create:
error_bug:
	return;
}

static void iwmx_sdk_dev_rm(unsigned idx)
{
	struct wmxsdk *wmxsdk;

	if (idx >= IWMX_SDK_DEV_MAX) {
		connman_error("BUG! idx (%u) >= IWMX_SDK_DEV_MAX (%u)\n",
			      idx, IWMX_SDK_DEV_MAX);
		goto error_bug;
	}
	wmxsdk = g_iwmx_sdk_devs[idx];
	if (wmxsdk->dev == NULL) {
		DBG("device index %u not enumerated? ignoring\n", idx);
		goto error_bug;
	}

	connman_device_unregister(wmxsdk->dev);
	wmxsdk->name[0] = 0;
	connman_device_unref(wmxsdk->dev);
	memset(wmxsdk, 0, sizeof(*wmxsdk));
	g_iwmx_sdk_devs[idx] = NULL;
	free(wmxsdk);
error_bug:
	return;
}

static void iwmx_sdk_addremove_cb(WIMAX_API_DEVICE_ID *devid,
				  BOOL presence)
{
	unsigned int cnt;
	WIMAX_API_RET r;
	WIMAX_API_HW_DEVICE_ID device_id_list[5];
	UINT32 device_id_list_size = ARRAY_SIZE(device_id_list);

	char errstr[512];
	UINT32 errstr_size = sizeof(errstr);

	DBG("cb: handle %u index #%u is %d\n", devid->sdkHandle,
	    devid->deviceIndex, presence);

	r = GetListDevice(devid, device_id_list, &device_id_list_size);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(devid, r, errstr, &errstr_size);
		connman_error("wmxsdk: Cannot obtain list "
			      "of devices: %d (%s)\n", r, errstr);
		return;
	}

	if (device_id_list_size == 0)
		DBG("No WiMAX devices reported\n");
	else
		for (cnt = 0; cnt < device_id_list_size; cnt++) {
			WIMAX_API_HW_DEVICE_ID *dev =
				device_id_list + cnt;
			DBG("#%u index #%u device %s\n",
			    cnt, dev->deviceIndex, dev->deviceName);
		}
	if (device_id_list_size < devid->deviceIndex) {
		connman_error("wmxsdk: changed device (%u) not in the list? "
			      "(%u items)\n",
			      devid->deviceIndex, device_id_list_size);
		return;
	}

	if (presence) {
		WIMAX_API_HW_DEVICE_ID *dev =
			device_id_list + devid->deviceIndex;
		iwmx_sdk_dev_add(devid->deviceIndex, dev->deviceIndex,
			       dev->deviceName);
	} else {
		iwmx_sdk_dev_rm(devid->deviceIndex);
	}
}

/*
 * Initialize the WiMAX API, register with it, setup callbacks for
 * device coming up / dissapearing
 */
int iwmx_sdk_api_init(void)
{
	int result;
	unsigned int cnt;
	WIMAX_API_RET r;
	char errstr[512];
	UINT32 errstr_size = sizeof(errstr);

	WIMAX_API_HW_DEVICE_ID device_id_list[5];
	UINT32 device_id_list_size = ARRAY_SIZE(device_id_list);

	memset(&g_api, 0, sizeof(g_api));
	g_api.privilege = WIMAX_API_PRIVILEGE_READ_WRITE;

	result = -EIO;
	r = WiMaxAPIOpen(&g_api);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&g_api, r, errstr, &errstr_size);
		connman_error("wmxsdk: WiMaxAPIOpen failed with %d (%s)\n",
			      r, errstr);
		goto error_wimaxapiopen;
	}

	r = SubscribeDeviceInsertRemove(&g_api, iwmx_sdk_addremove_cb);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&g_api, r, errstr, &errstr_size);
		connman_error("wmxsdk: insert/remove subscribe failed with "
			      "%d (%s)\n", r, errstr);
		goto error_close;
	}

	r = GetListDevice(&g_api, device_id_list, &device_id_list_size);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&g_api, r, errstr, &errstr_size);
		connman_error("wmxsdk: Cannot obtain list "
			      "of devices: %d (%s)\n", r, errstr);
		goto error_close;
	}
	if (device_id_list_size < g_api.deviceIndex) {
		connman_error("wmxsdk: changed device (%u) not in the list? "
			      "(%u items)\n",
			      g_api.deviceIndex, device_id_list_size);
	}

	if (device_id_list_size == 0)
		DBG("No WiMAX devices reported\n");
	else
		for (cnt = 0; cnt < device_id_list_size; cnt++) {
			WIMAX_API_HW_DEVICE_ID *dev =
				device_id_list + cnt;
			DBG("#%u index #%u device %s\n",
			    cnt, dev->deviceIndex, dev->deviceName);
			iwmx_sdk_dev_add(cnt, dev->deviceIndex,
					 dev->deviceName);
		}
	return 0;

error_close:
	WiMaxAPIClose(&g_api);
error_wimaxapiopen:
	return result;
}

void iwmx_sdk_api_exit(void)
{
	WIMAX_API_RET r;

	char errstr[512];
	UINT32 errstr_size = sizeof(errstr);

	r = WiMaxAPIClose(&g_api);
	if (r != WIMAX_API_RET_SUCCESS) {
		GetErrorString(&g_api, r, errstr, &errstr_size);
		connman_error("wmxsdk: WiMaxAPIClose failed with %d (%s)\n",
			      r, errstr);
	}
	return;
}
