/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2013  BMW Car IT GmbH.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License version 2.1 as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <stdint.h>
#include <stdbool.h>

typedef void (*nfacct_add_func_t) (unsigned int error, void *user_data);
typedef void (*nfacct_get_func_t) (unsigned int error, const char *name,
					uint64_t packets, uint64_t bytes,
					void *user_data);
typedef void (*nfacct_dump_func_t) (unsigned int error, const char *name,
					uint64_t packets, uint64_t bytes,
					void *user_data);
typedef void (*nfacct_del_func_t) (unsigned int error, void *user_data);

struct nfacct_info;

struct nfacct_info *nfacct_new(void);
void nfacct_destroy(struct nfacct_info *nfacct);

unsigned int nfacct_add(struct nfacct_info *nfacct, const char *name,
				nfacct_add_func_t function,
				void *user_data);
unsigned int nfacct_dump(struct nfacct_info *nfacct, bool zero,
				nfacct_dump_func_t function, void *user_data);
unsigned int nfacct_get(struct nfacct_info *nfacct, const char *name, bool zero,
				nfacct_get_func_t function, void *user_data);
unsigned int nfacct_del(struct nfacct_info *nfacct, const char *name,
				nfacct_del_func_t function, void *user_data);
