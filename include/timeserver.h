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

#ifndef __CONNMAN_TIMESERVER_H
#define __CONNMAN_TIMESERVER_H

#ifdef __cplusplus
extern "C" {
#endif

#define CONNMAN_TIMESERVER_PRIORITY_LOW      -100
#define CONNMAN_TIMESERVER_PRIORITY_DEFAULT     0
#define CONNMAN_TIMESERVER_PRIORITY_HIGH      100

/**
 * SECTION:timeserver
 * @title: timeserver premitives
 * @short_description: Functions for handling time servers (including NTP)
 */

int connman_timeserver_append(const char *server);
int connman_timeserver_remove(const char *server);
void connman_timeserver_sync(void);

struct connman_timeserver_driver {
	const char *name;
	int priority;
	int (*append) (const char *server);
	int (*remove) (const char *server);
	void (*sync) (void);
};

int connman_timeserver_driver_register(struct connman_timeserver_driver *driver);
void connman_timeserver_driver_unregister(struct connman_timeserver_driver *driver);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_TIMESERVER_H */
