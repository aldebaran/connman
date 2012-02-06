/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2012  Intel Corporation. All rights reserved.
 *  Copyright (C) 2012  BMW Car IT GmbH. All rights reserved.
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

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/errno.h>
#include <sys/socket.h>

#include "connman.h"

struct connman_ippool {
	unsigned int refcount;

	int index;
	uint32_t block;

	char *gateway;
	char *broadcast;
	char *start_ip;
	char *end_ip;
	char *subnet_mask;

	ippool_collision_cb_t collision_cb;
	void *user_data;
};

static GHashTable *hash_pool;
static GHashTable *hash_addresses;
static uint32_t last_block;
static uint32_t block_16_bits;
static uint32_t block_20_bits;
static uint32_t block_24_bits;
static uint32_t subnet_mask_24;

struct connman_ippool *
__connman_ippool_ref_debug(struct connman_ippool *pool,
				const char *file, int line, const char *caller)
{
	DBG("%p ref %d by %s:%d:%s()", pool, pool->refcount + 1,
		file, line, caller);

	__sync_fetch_and_add(&pool->refcount, 1);

	return pool;
}

void __connman_ippool_unref_debug(struct connman_ippool *pool,
				const char *file, int line, const char *caller)
{
	if (pool == NULL)
		return;

	DBG("%p ref %d by %s:%d:%s()", pool, pool->refcount - 1,
		file, line, caller);

	if (__sync_fetch_and_sub(&pool->refcount, 1) != 1)
		return;

	g_hash_table_remove(hash_pool, GUINT_TO_POINTER(pool->block));
}

static char *get_ip(uint32_t ip)
{
	struct in_addr addr;

	addr.s_addr = htonl(ip);

	return g_strdup(inet_ntoa(addr));
}

static uint32_t next_block(uint32_t block)
{
	uint32_t next;

	/*
	 * Return the next IP block within the private IP range
	 *
	 * 16-bit block 192.168.0.0 – 192.168.255.255
	 * 20-bit block  172.16.0.0 –  172.31.255.255
	 * 24-bit block    10.0.0.0 –  10.255.255.255
	 */

	next = (block & 0x0000ff00) >> 8;
	next += 1;

	if (next == 255) {
		if ((block & 0xffffff00) == block_16_bits) {
			/*
			 * Reached the end of the 16 bit block, switch
			 * to the 20-bit block.
			 */
			return block_20_bits;
		}

		if ((block & 0xffff0000) >= block_20_bits) {
			next = (block & 0x00ff0000) >> 16;
			if (next >= 16 && next < 32)
				next += 1;

			if (next == 32) {
				/*
				 * Reached the end of the 20 bit
				 * block, switch to the 24-bit block.
				 */
				return block_24_bits;
			}

			return (block & 0xff000000) |
				((next << 16) & 0x00ff0000);
		}

		if ((block & 0xff000000) == block_24_bits) {
			next = (block & 0x00ff0000) >> 16;
			if (next < 255)
				next += 1;

			if (next == 255) {
				/*
				 * Reached the end of the 24 bit
				 * block, switch to the 16-bit block.
				 */
				return block_16_bits;
			}

			return (block & 0xff000000) |
				((next << 16) & 0x00ff0000);
		}
	}

	return (block & 0xffff0000) | ((next << 8) & 0x0000ff00);
}

static uint32_t find_free_block()
{
	struct connman_ippool *pool;
	uint32_t start;
	uint32_t block;
	uint32_t *key;

	if (last_block == 0)
		return block_16_bits;

	/*
	 * Instead starting always from the 16 bit block, we start
	 * from the last assigned block. This is a simple optimimazion
	 * for the case where a lot of blocks have been assigned, e.g.
	 * the first half of the private IP pool is in use and a new
	 * we need to find a new block.
	 *
	 * To only thing we have to make sure is that we terminated if
	 * there is no block left.
	 */
	start = last_block;

	block = next_block(start);
	while (start != block) {
		block = next_block(block);

		key = GUINT_TO_POINTER(block);
		pool = g_hash_table_lookup(hash_pool, key);
		if (pool != NULL)
			continue;

		if (g_hash_table_lookup(hash_addresses, key) != NULL)
			continue;

		return block;
	}

	return 0;
}

void __connman_ippool_newaddr(int index, const char *address,
				unsigned char prefixlen)
{
	struct connman_ippool *pool;
	struct in_addr inp;
	uint32_t block;
	uint32_t *key;
	unsigned int count;

	if (inet_aton(address, &inp) == 0)
		return;

	block = ntohl(inp.s_addr) & 0xffffff00;

	key = GUINT_TO_POINTER(block);
	count = GPOINTER_TO_UINT(g_hash_table_lookup(hash_addresses, key));
	count = count + 1;
	g_hash_table_replace(hash_addresses, key, GUINT_TO_POINTER(count));

	pool = g_hash_table_lookup(hash_pool, key);
	if (pool == NULL)
		return;

	if (pool->index == index)
		return;

	if (pool->collision_cb != NULL)
		pool->collision_cb(pool, pool->user_data);
}

void __connman_ippool_deladdr(int index, const char *address,
				unsigned char prefixlen)
{
	struct in_addr inp;
	uint32_t block;
	uint32_t *key;
	unsigned int count;

	if (inet_aton(address, &inp) == 0)
		return;

	block = ntohl(inp.s_addr) & 0xffffff00;

	key = GUINT_TO_POINTER(block);
	count = GPOINTER_TO_UINT(g_hash_table_lookup(hash_addresses, key));
	count = count - 1;

	if (count == 0)
		g_hash_table_remove(hash_addresses, key);
	else
		g_hash_table_replace(hash_addresses, key, GUINT_TO_POINTER(count));
}

struct connman_ippool *__connman_ippool_create(int index,
					unsigned int start,
					unsigned int range,
					ippool_collision_cb_t collision_cb,
					void *user_data)
{
	struct connman_ippool *pool;
	uint32_t block;

	/*
	 * The range is at max 255 and we don't support overlapping
	 * blocks.
	 */
	if (start + range > 254)
		return NULL;

	block = find_free_block();
	if (block == 0)
		return NULL;

	pool = g_try_new0(struct connman_ippool, 1);
	if (pool == NULL)
		return NULL;

	pool->refcount = 1;
	pool->index = index;
	pool->block = block;
	pool->collision_cb = collision_cb;
	pool->user_data = user_data;

	last_block = block;

	if (range == 0)
		range = 1;

	pool->gateway = get_ip(block + 1);
	pool->broadcast = get_ip(block + 255);
	pool->subnet_mask = get_ip(subnet_mask_24);
	pool->start_ip = get_ip(block + start);
	pool->end_ip = get_ip(block + start + range);

	g_hash_table_insert(hash_pool, GUINT_TO_POINTER(pool->block), pool);

	return pool;
}

const char *__connman_ippool_get_gateway(struct connman_ippool *pool)
{
	return pool->gateway;
}

const char *__connman_ippool_get_broadcast(struct connman_ippool *pool)
{
	return pool->broadcast;
}

const char *__connman_ippool_get_start_ip(struct connman_ippool *pool)
{
	return pool->start_ip;
}

const char *__connman_ippool_get_end_ip(struct connman_ippool *pool)
{
	return pool->end_ip;
}

const char *__connman_ippool_get_subnet_mask(struct connman_ippool *pool)
{
	return pool->subnet_mask;
}

static void pool_free(gpointer data)
{
	struct connman_ippool *pool = data;

	g_free(pool->gateway);
	g_free(pool->broadcast);
	g_free(pool->start_ip);
	g_free(pool->end_ip);
	g_free(pool->subnet_mask);

	g_free(pool);
}

int __connman_ippool_init(void)
{
	DBG("");

	/* We start at 254 by default to avoid common addresses */
	block_16_bits = ntohl(inet_addr("192.168.254.0"));
	block_20_bits = ntohl(inet_addr("172.16.0.0"));
	block_24_bits = ntohl(inet_addr("10.0.0.0"));
	subnet_mask_24 = ntohl(inet_addr("255.255.255.0"));

	hash_pool = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
						pool_free);
	hash_addresses = g_hash_table_new_full(g_direct_hash, g_direct_equal,
						NULL, NULL);

	return 0;
}

void __connman_ippool_cleanup(void)
{
	DBG("");

	g_hash_table_destroy(hash_pool);
	hash_pool = NULL;

	g_hash_table_destroy(hash_addresses);
	hash_addresses = NULL;
}
