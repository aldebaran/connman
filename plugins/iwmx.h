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

/* Fix source compat brakage from 1.4 to 1.5...*/
#ifndef HAVE_WIMAX_API_DEVICE_ID
typedef struct WIMAX_API_DEVICE_ID WIMAX_API_DEVICE_ID;
#endif

#ifndef HAVE_WIMAX_API_CONNECTED_NSP_INFO
typedef struct WIMAX_API_CONNECTED_NSP_INFO WIMAX_API_CONNECTED_NSP_INFO;
#endif

#ifndef HAVE_WIMAX_API_NSP_INFO_EX
typedef struct WIMAX_API_NSP_INFO_EX WIMAX_API_NSP_INFO_EX;
#endif

#ifndef HAVE_WIMAX_API_HW_DEVICE_ID
typedef struct WIMAX_API_HW_DEVICE_ID WIMAX_API_HW_DEVICE_ID;
#endif


/*
 *
 * The plugin is broken in two main parts: the glue to connman
 * (iwmx_cm_*() functions) and the glue to the libiWmxSdk (iwmx_sdk_*()
 * functions). They connect using a well defined interface.
 *
 * The plugin is state based and operates reactively to state
 * transtitions on the WiMAX device or to user requests, even from
 * external control tools that are not aware of connman.
 *
 * When the user requests connman to do something, it goes into a call
 * implemented by the 'struct connman_driver iwmx_cm_driver' (or
 * iwmx_cm_network_driver) that will instruct libiWmxSDK to change the
 * device's state.
 *
 * When the device changes state, a state change callback is sent back
 * by libiWmxSDK, which gets fed to iwmx_cm_state_change(), which
 * evaluates the state change and updates connman's internal state in
 * response.
 *
 * This allows the device to be also controlled by external tools
 * without driving connman out of state.
 *
 * Device's state changes can be caused through:
 *
 *  - connman (by user request)
 *
 *  - any other external utility (eg: WmxSDK's wimaxcu)
 *
 *  - external stimuli: network connection broken when going out of
 *    range
 *
 * Functions named __*() normally indicate that require locking. See
 * their doc header.
 *
 * ENUMERATION
 *
 * When we receive a normal probe request [iwmx_cm_probe()] from
 * connman, we ignore it (we can tell based on the connman device
 * having NULL data).
 *
 * The plugin has registered with the WiMAX Network Service and it
 * will listen to its device add/rm messages [iwmx_sdk_addremove_cb()]
 * and use that to create a  device [iwmx_sdk_dev_add()] which will be
 * registered with connman. [iwmx_cm_dev_add()]. Then connman will
 * enumerate the device, call again iwmx_cm_probe() and at this time,
 * we'll recognize it, pass through iwmx_sdk_setup() and complete the
 * probe process.
 *
 * If the daemon dies, in theory the plugin will realize and remove
 * the WiMAX device.
 */

struct wmxsdk {
	WIMAX_API_DEVICE_ID device_id;
	struct connman_device *dev;

	GStaticMutex network_mutex;

	WIMAX_API_DEVICE_STATUS status;
	GMutex *status_mutex;

	/*
	 * nw points to the network we are connected to. connecting_nw
	 * points to the network we have requested to connect.
	 */
	GMutex *connect_mutex;
	struct connman_network *connecting_nw, *nw;

	char name[100];
	char ifname[16];
};

/* Initialize a [zeroed] struct wmxsdk */
static inline void wmxsdk_init(struct wmxsdk *wmxsdk)
{
	g_static_mutex_init(&wmxsdk->network_mutex);

	wmxsdk->status = WIMAX_API_DEVICE_STATUS_UnInitialized;
	wmxsdk->status_mutex = g_mutex_new();
	g_assert(wmxsdk->status_mutex);

	wmxsdk->connect_mutex = g_mutex_new();
	g_assert(wmxsdk->connect_mutex);
}

/* Misc utilities */
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))
#define container_of(pointer, type, member)				\
({									\
	type *object = NULL;						\
	size_t offset = (void *) &object->member - (void *) object;	\
	(type *) ((void *) pointer - offset);				\
})

/* Misc values */
enum {
	/**
	 * Time we wait for callbacks: 5s
	 *
	 * I know, it is huge, but L4 and the device sometimes take
	 * some time, especially when there is crypto involved.
	 */
	IWMX_SDK_L4_TIMEOUT_US = 5 * 1000 * 1000,

	/*
	 * WARNING!!!!!
	 *
	 * ONLY ONE DEVICE SUPPORTED
	 *
	 * - on removal, there is no way to know which device was
	 *   removed (the removed device is removed from the list and
	 *   the callback doesn't have any more information than the
	 *   index in the list that getlistdevice would return -- racy
	 *   as hell).
	 *
	 * - on insertion, there is not enough information provided.
	 */
	IWMX_SDK_DEV_MAX = 1,
};

struct connman_network *__iwmx_cm_network_available(
			struct wmxsdk *wmxsdk, const char *station_name,
			const char *station_type,
			const void *sdk_nspname, size_t sdk_nspname_size,
								int strength);

struct connman_network *iwmx_cm_network_available(
			struct wmxsdk *wmxsdk, const char *station_name,
			const char *station_type,
			const void *sdk_nspname, size_t sdk_nspname_size,
								int strength);

WIMAX_API_DEVICE_STATUS iwmx_cm_status_get(struct wmxsdk *wmxsdk);
void __iwmx_cm_state_change(struct wmxsdk *wmxsdk,
					WIMAX_API_DEVICE_STATUS __new_status);
void iwmx_cm_state_change(struct wmxsdk *wmxsdk,
					WIMAX_API_DEVICE_STATUS __new_status);

int iwmx_sdk_connect(struct wmxsdk *wmxsdk, struct connman_network *nw);
int iwmx_sdk_disconnect(struct wmxsdk *wmxsdk);
struct connman_network *__iwmx_sdk_get_connected_network(struct wmxsdk *wmxsdk);
const char *iwmx_sdk_dev_status_to_str(WIMAX_API_DEVICE_STATUS status);
int iwmx_sdk_rf_state_set(struct wmxsdk *wmxsdk, WIMAX_API_RF_STATE rf_state);
WIMAX_API_DEVICE_STATUS iwmx_sdk_get_device_status(struct wmxsdk *wmxsdk);
int iwmx_sdk_setup(struct wmxsdk *wmxsdk);
void iwmx_sdk_remove(struct wmxsdk *wmxsdk);
int iwmx_sdk_scan(struct wmxsdk *wmxsdk);
int iwmx_sdk_api_init(void);
void iwmx_sdk_api_exit(void);
