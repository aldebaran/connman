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

typedef struct modem_data modem_t;

struct modem_data;

struct modem_data *modem_create(const char *device);
void modem_destroy(struct modem_data *modem);

int modem_open(struct modem_data *modem);
int modem_close(struct modem_data *modem);

typedef void (* modem_cb_t) (const char *buf, void *user_data);

int modem_add_callback(struct modem_data *modem, const char *command,
					modem_cb_t function, void *user_data);

int modem_command(struct modem_data *modem,
				modem_cb_t callback, void *user_data,
				const char *command, const char *format, ...);
