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

#include <sqlite3.h>

#include "connman.h"

static sqlite3 *db = NULL;

static int create_tables(void)
{
	char *msg;
	int err;

	DBG("");

	err = sqlite3_exec(db, "CREATE TABLE properties ("
					"element TEXT NOT NULL,"
					"name TEXT NOT NULL,"
					"value TEXT NOT NULL,"
					"PRIMARY KEY(element, name))",
							NULL, NULL, &msg);

	if (err != SQLITE_OK) {
		connman_error("SQL error: %s", msg);
		sqlite3_free(msg);
		return -1;
	}

	return 0;
}

int __connman_storage_init(void)
{
	int err;

	DBG("");

#if 0
	if (!sqlite3_threadsafe()) {
		connman_error("SQLite is missing thread support");
		return -1;
	}
#endif

	err = sqlite3_open(STORAGEDIR "/config.db", &db);
	if (err != SQLITE_OK) {
		connman_error("Can't open database: %s", sqlite3_errmsg(db));
		sqlite3_close(db);
		return -1;
	}

	create_tables();

	return 0;
}

void __connman_storage_cleanup(void)
{
	DBG("");

	sqlite3_close(db);
}

int __connman_element_load(struct connman_element *element)
{
	return 0;
}

int __connman_element_store(struct connman_element *element)
{
	char *sql, *msg;

	DBG("");

	if (element->priority > 0) {
		sql = g_strdup_printf("INSERT INTO properties "
						"VALUES ('%s','%s','%d')",
						element->path, "Priority",
							element->priority);

		if (sqlite3_exec(db, sql, NULL, NULL, &msg) != SQLITE_OK) {
			connman_error("SQL error: %s", msg);
			sqlite3_free(msg);
		}
	}

	return 0;
}
