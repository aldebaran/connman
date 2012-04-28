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

#include <glib.h>

#include <connman/dbus.h>

#include "../src/connman.h"

struct test_session;

struct test_manager {
	char *state;
};

struct test_fix {
	gpointer user_data;

	GMainLoop *main_loop;
	DBusConnection *main_connection;
	guint watch;
	guint manager_watch;

	struct test_manager manager;
	GSourceFunc manager_changed;

	/* session test cases */
	unsigned int max_sessions;
	struct test_session *session;
};

/* utils.c */
typedef void (* util_test_setup_cb) (struct test_fix *fix,
					gconstpointer data);
typedef void (* util_test_teardown_cb) (struct test_fix *fix,
					gconstpointer data);

gboolean util_quit_loop(gpointer fix);
guint util_idle_call(struct test_fix *fix, GSourceFunc func,
			GDestroyNotify notify);
guint util_call(struct test_fix *fix, GSourceFunc func,
		GDestroyNotify notify);
void util_test_add(const char *test_name, GSourceFunc test_func,
			util_test_setup_cb setup_cb,
			util_test_teardown_cb teardown_cb);
void util_setup(struct test_fix *fix, gconstpointer data);
void util_teardown(struct test_fix *fix, gconstpointer data);

void util_session_create(struct test_fix *fix, unsigned int max_sessions);
void util_session_destroy(gpointer fix);
void util_session_init(struct test_session *session);
void util_session_cleanup(struct test_session *session);

typedef void (* notify_cb) (struct test_session *session);

enum connman_session_state {
	CONNMAN_SESSION_STATE_DISCONNECTED   = 0,
	CONNMAN_SESSION_STATE_CONNECTED      = 1,
	CONNMAN_SESSION_STATE_ONLINE         = 2,
};

enum connman_session_type {
	CONNMAN_SESSION_TYPE_ANY      = 0,
	CONNMAN_SESSION_TYPE_LOCAL    = 1,
	CONNMAN_SESSION_TYPE_INTERNET = 2,
};

enum connman_session_roaming_policy {
	CONNMAN_SESSION_ROAMING_POLICY_UNKNOWN		= 0,
	CONNMAN_SESSION_ROAMING_POLICY_DEFAULT		= 1,
	CONNMAN_SESSION_ROAMING_POLICY_ALWAYS		= 2,
	CONNMAN_SESSION_ROAMING_POLICY_FORBIDDEN	= 3,
	CONNMAN_SESSION_ROAMING_POLICY_NATIONAL		= 4,
	CONNMAN_SESSION_ROAMING_POLICY_INTERNATIONAL	= 5,
};

struct test_session_info {
	char *bearer;
	enum connman_session_state state;
	enum connman_session_type type;
	char *name;
	/* ipv4, ipv6 dicts */
	GSList *allowed_bearers;
	connman_bool_t priority;
	connman_bool_t avoid_handover;
	connman_bool_t stay_connected;
	unsigned int periodic_connect;
	unsigned int idle_timeout;
	connman_bool_t ecall;
	enum connman_session_roaming_policy roaming_policy;
	char *interface;
	unsigned int marker;
};

struct test_session {
	gpointer user_data;

	struct test_fix *fix;
	DBusConnection *connection;

	char *session_path;
	char *notify_path;
	notify_cb notify;

	struct test_session_info *info;
};

struct test_bearer_info {
	char *name;
};

/* session-api.c */
void bearer_info_cleanup(gpointer bearer_info, gpointer user_data);

void session_append_settings(DBusMessageIter *dict,
				struct test_session_info *info);
int session_notify_register(struct test_session *session,
				const char *notify_path);
int session_notify_unregister(struct test_session *session,
				const char *notify_path);

DBusMessage *session_connect(DBusConnection *connection,
				struct test_session *session);
DBusMessage *session_disconnect(DBusConnection *connection,
					struct test_session *session);

/* manager-api.c */
DBusMessage *manager_get_services(DBusConnection *connection);
DBusMessage *manager_get_properties(DBusConnection *connection);
DBusMessage *manager_create_session(DBusConnection *connection,
					struct test_session_info *info,
					const char *notifier_path);
DBusMessage *manager_destroy_session(DBusConnection *connection,
					const char *notifier_path);
DBusMessage *manager_set_session_mode(DBusConnection *connection,
					connman_bool_t enable);
int manager_parse_properties(DBusMessage *msg,
				struct test_manager *manager);

/* #define DEBUG */
#ifdef DEBUG
#include <stdio.h>

#define LOG(fmt, arg...) do { \
	fprintf(stdout, "%s:%s() " fmt "\n", \
			__FILE__, __FUNCTION__ , ## arg); \
} while (0)
#else
#define LOG(fmt, arg...)
#endif
