/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2012  Intel Corporation. All rights reserved.
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
#include <string.h>

#include <gdbus.h>
#include <connman/agent.h>
#include <connman/setting.h>

#include "connman.h"

static DBusConnection *connection = NULL;
static guint agent_watch = 0;
static gchar *agent_path = NULL;
static gchar *agent_sender = NULL;

struct connman_agent {
	void *user_context;
	void *user_data;
	DBusMessage *msg;
	DBusPendingCall *call;
	int timeout;
	agent_queue_cb callback;
	struct connman_agent_driver *driver;
};

static GList *agent_queue = NULL;
static struct connman_agent *agent_request = NULL;
static GSList *driver_list = NULL;

void connman_agent_get_info(const char **sender, const char **path)
{
	*sender = agent_sender;
	*path = agent_path;
}

static void agent_data_free(struct connman_agent *data)
{
	if (data == NULL)
		return;
	if (data->user_context != NULL) {
		if (data->driver != NULL && data->driver->context_unref != NULL)
			data->driver->context_unref(data->user_context);
	}
	if (data->msg != NULL)
		dbus_message_unref(data->msg);
	if (data->call != NULL)
		dbus_pending_call_cancel(data->call);

	g_free(data);
}

static void agent_receive_message(DBusPendingCall *call, void *user_data);

static int agent_send_next_request(void)
{
	if (agent_request != NULL)
		return -EBUSY;

	if (agent_queue == NULL)
		return 0;

	agent_request = agent_queue->data;
	agent_queue = g_list_remove(agent_queue, agent_request);

	if (dbus_connection_send_with_reply(connection, agent_request->msg,
					&agent_request->call,
					agent_request->timeout)	== FALSE)
		goto fail;

	if (agent_request->call == NULL)
		goto fail;

	if (dbus_pending_call_set_notify(agent_request->call,
			agent_receive_message, agent_request, NULL) == FALSE)
		goto fail;

	dbus_message_unref(agent_request->msg);
	agent_request->msg = NULL;
	return 0;

fail:
	agent_data_free(agent_request);
	agent_request = NULL;
	return -ESRCH;
}

static int agent_send_cancel(struct connman_agent *agent)
{
	DBusMessage *message;

	if (agent_sender == NULL || agent == NULL || agent->driver == NULL)
		return 0;

	message = dbus_message_new_method_call(agent_sender, agent_path,
			agent->driver->interface, "Cancel");
	if (message != NULL) {
		dbus_message_set_no_reply(message, TRUE);
		g_dbus_send_message(connection, message);
		return 0;
	}

	connman_warn("Failed to send Cancel message to agent");
	return -ESRCH;
}

static void agent_receive_message(DBusPendingCall *call, void *user_data)
{
	struct connman_agent *queue_data = user_data;
	DBusMessage *reply;
	int err;

	DBG("waiting for %p received %p", agent_request, queue_data);

	if (agent_request != queue_data) {
		connman_error("Agent callback expected %p got %p",
				agent_request, queue_data);
		return;
	}

	reply = dbus_pending_call_steal_reply(call);
	dbus_pending_call_unref(call);
	queue_data->call = NULL;

	if (dbus_message_is_error(reply,
			"org.freedesktop.DBus.Error.Timeout") == TRUE ||
			dbus_message_is_error(reply,
			"org.freedesktop.DBus.Error.TimedOut") == TRUE) {
		agent_send_cancel(queue_data->user_context);
	}

	queue_data->callback(reply, queue_data->user_data);
	dbus_message_unref(reply);

	agent_data_free(queue_data);
	agent_request = NULL;

	err = agent_send_next_request();
	if (err < 0)
		DBG("send next request failed (%s/%d)", strerror(-err), -err);
}

static struct connman_agent_driver *get_driver(void)
{
	return g_slist_nth_data(driver_list, 0);
}

int connman_agent_queue_message(void *user_context,
				DBusMessage *msg, int timeout,
				agent_queue_cb callback, void *user_data)
{
	struct connman_agent *queue_data;
	struct connman_agent_driver *driver;
	int err;

	if (user_context == NULL || callback == NULL)
		return -EBADMSG;

	queue_data = g_new0(struct connman_agent, 1);
	if (queue_data == NULL)
		return -ENOMEM;

	driver = get_driver();
	DBG("driver %p", driver);

	if (driver != NULL && driver->context_ref != NULL) {
		queue_data->user_context = driver->context_ref(user_context);
		queue_data->driver = driver;
	} else
		queue_data->user_context = user_context;

	queue_data->msg = dbus_message_ref(msg);
	queue_data->timeout = timeout;
	queue_data->callback = callback;
	queue_data->user_data = user_data;
	agent_queue = g_list_append(agent_queue, queue_data);

	err = agent_send_next_request();
	if (err < 0)
		DBG("send next request failed (%s/%d)", strerror(-err), -err);

	return err;
}

void connman_agent_cancel(void *user_context)
{
	GList *item, *next;
	struct connman_agent *queued_req;
	int err;

	DBG("context %p", user_context);

	item = agent_queue;

	while (item != NULL) {
		next = g_list_next(item);
		queued_req = item->data;

		if (queued_req->user_context == user_context ||
							user_context == NULL) {
			agent_data_free(queued_req);
			agent_queue = g_list_delete_link(agent_queue, item);
		}

		item = next;
	}

	if (agent_request == NULL)
		return;

	if (agent_request->user_context != user_context &&
						user_context != NULL)
		return;

	agent_send_cancel(agent_request);

	agent_data_free(agent_request);
	agent_request = NULL;

	err = agent_send_next_request();
	if (err < 0)
		DBG("send next request failed (%s/%d)", strerror(-err), -err);
}

static void agent_free(void)
{
	if (agent_watch > 0)
		g_dbus_remove_watch(connection, agent_watch);

	agent_watch = 0;

	g_free(agent_sender);
	agent_sender = NULL;

	g_free(agent_path);
	agent_path = NULL;

	connman_agent_cancel(NULL);
}

static void agent_disconnect(DBusConnection *conn, void *data)
{
	DBG("data %p", data);
	agent_free();
}

int connman_agent_register(const char *sender, const char *path)
{
	DBG("sender %s path %s", sender, path);
	if (agent_path != NULL)
		return -EEXIST;

	agent_sender = g_strdup(sender);
	agent_path = g_strdup(path);

	agent_watch = g_dbus_add_disconnect_watch(connection, sender,
						agent_disconnect, NULL, NULL);

	return 0;
}

int connman_agent_unregister(const char *sender, const char *path)
{
	DBG("sender %s path %s", sender, path);

	if (agent_path == NULL)
		return -ESRCH;

	if (agent_watch > 0)
		g_dbus_remove_watch(connection, agent_watch);

	agent_free();

	return 0;
}

struct report_error_data {
	void *user_context;
	report_error_cb_t callback;
	void *user_data;
};

static void report_error_reply(DBusMessage *reply, void *user_data)
{
	struct report_error_data *report_error = user_data;
	gboolean retry = FALSE;
	const char *dbus_err;

	if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR) {
		dbus_err = dbus_message_get_error_name(reply);
		if (dbus_err != NULL &&
			strcmp(dbus_err,
				CONNMAN_AGENT_INTERFACE ".Error.Retry") == 0)
			retry = TRUE;
	}

	report_error->callback(report_error->user_context, retry,
			report_error->user_data);
	g_free(report_error);
}

int connman_agent_report_error(void *user_context, const char *path,
				const char *error,
				report_error_cb_t callback, void *user_data)
{
	DBusMessage *message;
	DBusMessageIter iter;
	struct report_error_data *report_error;
	int err;

	if (user_context == NULL || agent_path == NULL || error == NULL ||
							callback == NULL)
		return -ESRCH;

	message = dbus_message_new_method_call(agent_sender, agent_path,
					CONNMAN_AGENT_INTERFACE,
					"ReportError");
	if (message == NULL)
		return -ENOMEM;

	dbus_message_iter_init_append(message, &iter);

	dbus_message_iter_append_basic(&iter,
				DBUS_TYPE_OBJECT_PATH, &path);
	dbus_message_iter_append_basic(&iter,
				DBUS_TYPE_STRING, &error);

	report_error = g_try_new0(struct report_error_data, 1);
	if (report_error == NULL) {
		dbus_message_unref(message);
		return -ENOMEM;
	}

	report_error->user_context = user_context;
	report_error->callback = callback;
	report_error->user_data = user_data;

	err = connman_agent_queue_message(user_context, message,
					connman_timeout_input_request(),
					report_error_reply, report_error);
	if (err < 0 && err != -EBUSY) {
		DBG("error %d sending error request", err);
		g_free(report_error);
		dbus_message_unref(message);
		return -ESRCH;
	}

	dbus_message_unref(message);

	return -EINPROGRESS;
}

static gint compare_priority(gconstpointer a, gconstpointer b)
{
	const struct connman_agent_driver *driver1 = a;
	const struct connman_agent_driver *driver2 = b;

	return driver2->priority - driver1->priority;
}

/**
 * connman_agent_driver_register:
 * @driver: Agent driver definition
 *
 * Register a new agent driver
 *
 * Returns: %0 on success
 */
int connman_agent_driver_register(struct connman_agent_driver *driver)
{
	DBG("Registering driver %p name %s", driver, driver->name);

	driver_list = g_slist_insert_sorted(driver_list, driver,
							compare_priority);

	return 0;
}

/**
 * connman_agent_driver_unregister:
 * @driver: Agent driver definition
 *
 * Remove a previously registered agent driver
 */
void connman_agent_driver_unregister(struct connman_agent_driver *driver)
{
	GSList *list;

	if (driver == NULL)
		return;

	DBG("Unregistering driver %p name %s", driver, driver->name);

	if (agent_sender == NULL && agent_path == NULL)
		goto out;

	for (list = driver_list; list; list = list->next) {
		DBusMessage *message;

		if (driver != list->data)
			continue;

		DBG("Sending release to %s path %s iface %s", agent_sender,
			agent_path, driver->interface);

		message = dbus_message_new_method_call(agent_sender, agent_path,
				driver->interface, "Release");
		if (message != NULL) {
			dbus_message_set_no_reply(message, TRUE);
			g_dbus_send_message(connection, message);
		}

		agent_free();

		/*
		 * ATM agent_free() unsets the agent_sender and agent_path
		 * variables so we can unregister only once.
		 * This needs proper fix later.
		 */
		break;
	}

out:
	driver_list = g_slist_remove(driver_list, driver);
}

static void release_all_agents(void)
{
	connman_agent_driver_unregister(get_driver());
}

int __connman_agent_init(void)
{
	DBG("");

	connection = connman_dbus_get_connection();
	if (connection == NULL)
		return -1;

	return 0;
}

void __connman_agent_cleanup(void)
{
	DBG("");

	if (connection == NULL)
		return;

	if (agent_watch > 0)
		g_dbus_remove_watch(connection, agent_watch);

	release_all_agents();

	dbus_connection_unref(connection);
	connection = NULL;
}
