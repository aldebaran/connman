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

/*
 * The session are identified through the pid is only a temporary solution
 */
struct connman_session_policy {
	const char *name;
	int (*get_bool) (const char *id, const char *key, connman_bool_t *val);
	int (*get_string) (const char *id, const char *key, char **val);
};

int connman_session_policy_register(struct connman_session_policy *config);
void connman_session_policy_unregister(struct connman_session_policy *config);

int connman_session_update_bool(const char *id, const char *key,
				connman_bool_t val);
int connman_session_update_string(const char *id, const char *key,
					const char *val);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_SESSION_H */
