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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>

#include "connman.h"

struct connman_location {
	gint refcount;
	struct connman_service *service;
	enum connman_location_result result;

	struct connman_location_driver *driver;
	void *driver_data;
};

/**
 * connman_location_ref:
 * @location: Location structure
 *
 * Increase reference counter of location
 */
struct connman_location *connman_location_ref(struct connman_location *location)
{
	g_atomic_int_inc(&location->refcount);

	return location;
}

/**
 * connman_location_unref:
 * @location: Location structure
 *
 * Decrease reference counter of location
 */
void connman_location_unref(struct connman_location *location)
{
	if (g_atomic_int_dec_and_test(&location->refcount) == FALSE)
		return;

	if (location->driver) {
		location->driver->finish(location);
		location->driver = NULL;
	}

	g_free(location);
}

/**
 * connman_location_get_type:
 * @location: Location structure
 *
 * Get the service type of location
 */
enum connman_service_type connman_location_get_type(struct connman_location *location)
{
	if (location == NULL)
		return CONNMAN_SERVICE_TYPE_UNKNOWN;

	return connman_service_get_type(location->service);
}

/**
 * connman_location_get_interface:
 * @location: location structure
 *
 * Get network interface of location
 */
char *connman_location_get_interface(struct connman_location *location)
{
	if (location == NULL)
		return NULL;

	return connman_service_get_interface(location->service);
}

struct connman_service *connman_location_get_service(
					struct connman_location *location)
{
	return location->service;
}
/**
 * connman_location_get_data:
 * @location: Location structure
 *
 * Get private location data pointer
 */
void *connman_location_get_data(struct connman_location *location)
{
	return location->driver_data;
}

/**
 * connman_location_set_data:
 * @location: Location structure
 * @data: data pointer
 *
 * Set private location data pointer
 */
void connman_location_set_data(struct connman_location *location, void *data)
{
	location->driver_data = data;
}

static GSList *driver_list = NULL;

static gint compare_priority(gconstpointer a, gconstpointer b)
{
	const struct connman_location_driver *driver1 = a;
	const struct connman_location_driver *driver2 = b;

	return driver2->priority - driver1->priority;
}

/**
 * connman_location_driver_register:
 * @driver: Location driver definition
 *
 * Register a new Location driver
 *
 * Returns: %0 on success
 */
int connman_location_driver_register(struct connman_location_driver *driver)
{
	DBG("driver %p name %s", driver, driver->name);

	driver_list = g_slist_insert_sorted(driver_list, driver,
							compare_priority);

	return 0;
}

/**
 * connman_location_driver_unregister:
 * @driver: Location driver definition
 *
 * Remove a previously registered Location driver
 */
void connman_location_driver_unregister(struct connman_location_driver *driver)
{
	DBG("driver %p name %s", driver, driver->name);

	driver_list = g_slist_remove(driver_list, driver);
}

/**
 * connman_location_report_result:
 * @location: location structure
 * @result: result information
 *
 * Report result of a location detection
 */
void connman_location_report_result(struct connman_location *location,
					enum connman_location_result result)
{
	DBG("location %p result %d", location, result);

	if (location == NULL)
		return;

	if (location->result == result)
		return;

	location->result = result;

	switch (location->result) {
	case CONNMAN_LOCATION_RESULT_UNKNOWN:
		return;
	case CONNMAN_LOCATION_RESULT_PORTAL:
		__connman_service_request_login(location->service);
		break;
	case CONNMAN_LOCATION_RESULT_ONLINE:
		__connman_service_indicate_state(location->service,
						CONNMAN_SERVICE_STATE_ONLINE,
						CONNMAN_IPCONFIG_TYPE_IPV4);
		break;
	}
}

struct connman_location *__connman_location_create(struct connman_service *service)
{
	struct connman_location *location;

	DBG("service %p", service);

	if (service == NULL)
		return NULL;

	location = g_try_new0(struct connman_location, 1);
	if (location == NULL)
		return NULL;

	DBG("location %p", location);

	location->refcount = 1;

	location->service = service;
	location->result = CONNMAN_LOCATION_RESULT_UNKNOWN;

	return location;
}

int __connman_location_detect(struct connman_service *service)
{
	struct connman_location *location;
	GSList *list;

	DBG("service %p", service);

	location = __connman_service_get_location(service);
	if (location == NULL)
		return -EINVAL;

	if (location->driver) {
		location->result = CONNMAN_LOCATION_RESULT_UNKNOWN;
		location->driver->finish(location);

		if (location->driver->detect(location) == 0)
			return 0;

		location->driver = NULL;
	}

	for (list = driver_list; list; list = list->next) {
		struct connman_location_driver *driver = list->data;

		DBG("driver %p name %s", driver, driver->name);

		if (driver->detect(location) == 0) {
			location->driver = driver;
			break;
		}
	}

	if (location->driver == NULL)
		connman_location_report_result(location,
					CONNMAN_LOCATION_RESULT_ONLINE);

	return 0;
}

int __connman_location_finish(struct connman_service *service)
{
	struct connman_location *location;

	DBG("service %p", service);

	location = __connman_service_get_location(service);
	if (location == NULL)
		return -EINVAL;

	location->result = CONNMAN_LOCATION_RESULT_UNKNOWN;

	if (location->driver) {
		location->driver->finish(location);
		location->driver = NULL;
	}

	return 0;
}

int __connman_location_init(void)
{
	DBG("");

	return 0;
}

void __connman_location_cleanup(void)
{
	DBG("");
}
