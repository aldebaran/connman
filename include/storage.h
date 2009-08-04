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

#ifndef __CONNMAN_STORAGE_H
#define __CONNMAN_STORAGE_H

#include <connman/profile.h>
#include <connman/service.h>
#include <connman/device.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * SECTION:storage
 * @title: Storage premitives
 * @short_description: Functions for registering storage modules
 */

#define CONNMAN_STORAGE_PRIORITY_LOW      -100
#define CONNMAN_STORAGE_PRIORITY_DEFAULT     0
#define CONNMAN_STORAGE_PRIORITY_HIGH      100

struct connman_storage {
	const char *name;
	int priority;
	int (*profile_init) (void);
	int (*profile_load) (struct connman_profile *profile);
	int (*profile_save) (struct connman_profile *profile);
	enum connman_service_type service_type;
	int (*service_load) (struct connman_service *service);
	int (*service_save) (struct connman_service *service);
	enum connman_device_type device_type;
	int (*device_load) (struct connman_device *device);
	int (*device_save) (struct connman_device *device);
};

int connman_storage_register(struct connman_storage *storage);
void connman_storage_unregister(struct connman_storage *storage);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_STORAGE_H */
