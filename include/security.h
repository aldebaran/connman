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

#ifndef __CONNMAN_SECURITY_H
#define __CONNMAN_SECURITY_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * SECTION:security
 * @title: Security premitives
 * @short_description: Functions for registering security modules
 */

enum connman_security_privilege {
	CONNMAN_SECURITY_PRIVILEGE_PUBLIC  = 0,
	CONNMAN_SECURITY_PRIVILEGE_MODIFY  = 1,
	CONNMAN_SECURITY_PRIVILEGE_SECRET  = 2,
};

#define CONNMAN_SECURITY_PRIORITY_LOW      -100
#define CONNMAN_SECURITY_PRIORITY_DEFAULT     0
#define CONNMAN_SECURITY_PRIORITY_HIGH      100

struct connman_security {
	const char *name;
	int priority;
	int (*authorize_sender) (const char *sender,
				enum connman_security_privilege privilege);
};

int connman_security_register(struct connman_security *security);
void connman_security_unregister(struct connman_security *security);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_SECURITY_H */
