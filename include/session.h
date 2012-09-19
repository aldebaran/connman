/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2012  BMW Car IT GbmH. All rights reserved.
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

#ifndef __CONNMAN_SESSION_H
#define __CONNMAN_SESSION_H

#include <connman/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CONNMAN_SESSION_POLICY_PRIORITY_LOW      -100
#define CONNMAN_SESSION_POLICY_PRIORITY_DEFAULT     0
#define CONNMAN_SESSION_POLICY_PRIORITY_HIGH      100

struct connman_session;

struct connman_session_policy {
	const char *name;
	int priority;
	int (*get_bool) (struct connman_session *session,
				const char *key, connman_bool_t *val);
	int (*get_string) (struct connman_session *session,
				const char *key, char **val);
};

int connman_session_policy_register(struct connman_session_policy *config);
void connman_session_policy_unregister(struct connman_session_policy *config);

int connman_session_update_bool(struct connman_session *session, const char *key,
				connman_bool_t val);
int connman_session_update_string(struct connman_session *session, const char *key,
					const char *val);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_SESSION_H */
