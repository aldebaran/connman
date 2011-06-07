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

#include <glib.h>

#include <connman/dbus.h>

#include "connman.h"

struct test_session;

struct test_fix {
	gpointer user_data;

	GMainLoop *main_loop;
	DBusConnection *main_connection;

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

typedef void (* notify_cb) (struct test_session *session);

struct test_session {
	gpointer user_data;

	struct test_fix *fix;
	DBusConnection *connection;

	notify_cb notify;
};

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
