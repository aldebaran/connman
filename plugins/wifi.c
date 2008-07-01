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

#include <dbus/dbus.h>

#include <connman/plugin.h>
#include <connman/driver.h>
#include <connman/log.h>

static DBusConnection *connection;

#define SUPPLICANT_NAME  "fi.epitest.hostap.WPASupplicant"
#define SUPPLICANT_INTF  "fi.epitest.hostap.WPASupplicant"
#define SUPPLICANT_PATH  "/fi/epitest/hostap/WPASupplicant"

enum supplicant_state {
	STATE_INACTIVE,
	STATE_SCANNING,
	STATE_ASSOCIATING,
	STATE_ASSOCIATED,
	STATE_4WAY_HANDSHAKE,
	STATE_GROUP_HANDSHAKE,
	STATE_COMPLETED,
	STATE_DISCONNECTED,
};

struct supplicant_task {
	int ifindex;
	gchar *ifname;
	enum supplicant_state state;
	gchar *path;
	gboolean created;
};

static GStaticMutex task_mutex = G_STATIC_MUTEX_INIT;
static GSList *task_list = NULL;

static struct supplicant_task *find_task_by_index(int index)
{
	GSList *list;

	for (list = task_list; list; list = list->next) {
		struct supplicant_task *task = list->data;

		if (task->ifindex == index)
			return task;
	}

	return NULL;
}

static int get_interface(struct supplicant_task *task)
{
	DBusMessage *message, *reply;
	DBusError error;
	const char *path;

	DBG("task %p", task);

	message = dbus_message_new_method_call(SUPPLICANT_NAME, SUPPLICANT_PATH,
					SUPPLICANT_INTF, "getInterface");
	if (message == NULL)
		return -ENOMEM;

	dbus_message_append_args(message, DBUS_TYPE_STRING, &task->ifname,
							DBUS_TYPE_INVALID);

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(connection,
							message, -1, &error);
	if (reply == NULL) {
		if (dbus_error_is_set(&error) == TRUE) {
			connman_error("%s", error.message);
			dbus_error_free(&error);
		} else
			connman_error("Failed to get interface");
		dbus_message_unref(message);
		return -EIO;
	}

	dbus_message_unref(message);

	dbus_error_init(&error);

	if (dbus_message_get_args(reply, &error, DBUS_TYPE_OBJECT_PATH, &path,
						DBUS_TYPE_INVALID) == FALSE) {
		if (dbus_error_is_set(&error) == TRUE) {
			connman_error("%s", error.message);
			dbus_error_free(&error);
		} else
			connman_error("Wrong arguments for interface");
		dbus_message_unref(reply);
		return -EIO;
	}

	DBG("path %s", path);

	task->path = g_strdup(path);
	task->created = FALSE;

	dbus_message_unref(reply);

	return 0;
}

static int add_interface(struct supplicant_task *task)
{
	DBusMessage *message, *reply;
	DBusError error;
	const char *path;

	DBG("task %p", task);

	message = dbus_message_new_method_call(SUPPLICANT_NAME, SUPPLICANT_PATH,
					SUPPLICANT_INTF, "addInterface");
	if (message == NULL)
		return -ENOMEM;

	dbus_error_init(&error);

	dbus_message_append_args(message, DBUS_TYPE_STRING, &task->ifname,
							DBUS_TYPE_INVALID);

	reply = dbus_connection_send_with_reply_and_block(connection,
							message, -1, &error);
	if (reply == NULL) {
		if (dbus_error_is_set(&error) == TRUE) {
			connman_error("%s", error.message);
			dbus_error_free(&error);
		} else
			connman_error("Failed to add interface");
		dbus_message_unref(message);
		return -EIO;
	}

	dbus_message_unref(message);

	dbus_error_init(&error);

	if (dbus_message_get_args(reply, &error, DBUS_TYPE_OBJECT_PATH, &path,
						DBUS_TYPE_INVALID) == FALSE) {
		if (dbus_error_is_set(&error) == TRUE) {
			connman_error("%s", error.message);
			dbus_error_free(&error);
		} else
			connman_error("Wrong arguments for interface");
		dbus_message_unref(reply);
		return -EIO;
	}

	DBG("path %s", path);

	task->path = g_strdup(path);
	task->created = TRUE;

	dbus_message_unref(reply);

	return 0;
}

static int remove_interface(struct supplicant_task *task)
{
	DBusMessage *message, *reply;
	DBusError error;

	DBG("task %p", task);

	if (task->created == FALSE)
		return -EINVAL;

	message = dbus_message_new_method_call(SUPPLICANT_NAME, SUPPLICANT_PATH,
					SUPPLICANT_INTF, "removeInterface");
	if (message == NULL)
		return -ENOMEM;

	dbus_message_append_args(message, DBUS_TYPE_OBJECT_PATH, &task->path,
							DBUS_TYPE_INVALID);

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(connection,
							message, -1, &error);
	if (reply == NULL) {
		if (dbus_error_is_set(&error) == TRUE) {
			connman_error("%s", error.message);
			dbus_error_free(&error);
		} else
			connman_error("Failed to remove interface");
		dbus_message_unref(message);
		return -EIO;
	}

	dbus_message_unref(message);

	g_free(task->path);
	task->path = NULL;

	dbus_message_unref(reply);

	return 0;
}

static int initiate_scan(struct supplicant_task *task)
{
	DBusMessage *message, *reply;
	DBusError error;

	DBG("task %p", task);

	message = dbus_message_new_method_call(SUPPLICANT_NAME, task->path,
					SUPPLICANT_INTF ".Interface", "scan");
	if (message == NULL)
		return -ENOMEM;

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(connection,
							message, -1, &error);
	if (reply == NULL) {
		if (dbus_error_is_set(&error) == TRUE) {
			connman_error("%s", error.message);
			dbus_error_free(&error);
		} else
			connman_error("Failed to initiate scan");
		dbus_message_unref(message);
		return -EIO;
	}

	dbus_message_unref(message);

	dbus_message_unref(reply);

	return 0;
}

static int wifi_probe(struct connman_element *element)
{
	struct supplicant_task *task;
	int err;

	DBG("element %p name %s", element, element->name);

	task = g_try_new0(struct supplicant_task, 1);
	if (task == NULL)
		return -ENOMEM;

	task->ifindex = element->netdev.index;
	task->ifname = g_strdup(element->netdev.name);

	if (task->ifname == NULL) {
		g_free(task);
		return -ENOMEM;
	}

	task->created = FALSE;
	task->state = STATE_INACTIVE;

	g_static_mutex_lock(&task_mutex);
	task_list = g_slist_append(task_list, task);
	g_static_mutex_unlock(&task_mutex);

	err = get_interface(task);
	if (err < 0) {
		err = add_interface(task);
		if (err < 0) {
			g_free(task);
			return err;
		}
	}

	initiate_scan(task);

	return 0;
}

static void wifi_remove(struct connman_element *element)
{
	struct supplicant_task *task;

	DBG("element %p name %s", element, element->name);

	g_static_mutex_lock(&task_mutex);
	task = find_task_by_index(element->netdev.index);
	g_static_mutex_unlock(&task_mutex);

	if (task == NULL)
		return;

	g_static_mutex_lock(&task_mutex);
	task_list = g_slist_remove(task_list, task);
	g_static_mutex_unlock(&task_mutex);

	remove_interface(task);

	g_free(task->ifname);
	g_free(task);
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
	int err;

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (connection == NULL)
		return -EIO;

	err = connman_driver_register(&wifi_driver);
	if (err < 0) {
		dbus_connection_unref(connection);
		return err;
	}

	return 0;
}

static void wifi_exit(void)
{
	connman_driver_unregister(&wifi_driver);

	dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE("WiFi", "WiFi interface plugin", VERSION,
							wifi_init, wifi_exit)
