/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include <glib.h>

#include "src/shared/sha1.h"

#define SHA1_MAC_LEN 20

static void __hmac_sha1(GChecksum *checksum, const void *key, size_t key_len,
			const void *data, size_t data_len, void *output)
{
	unsigned char ipad[64];
	unsigned char opad[64];
	unsigned char digest[SHA1_MAC_LEN];
	size_t length;
	int i;

	/* if key is longer than 64 bytes reset it to key=SHA1(key) */
	if (key_len > 64) {
		g_checksum_update(checksum, key, key_len);
		length = sizeof(digest);
		g_checksum_get_digest(checksum, digest, &length);

		g_checksum_reset(checksum);

		key = digest;
		key_len = SHA1_MAC_LEN;
	}

	/* start out by storing key in pads */
	memset(ipad, 0, sizeof(ipad));
	memset(opad, 0, sizeof(opad));
	memcpy(ipad, key, key_len);
	memcpy(opad, key, key_len);

	/* XOR key with ipad and opad values */
	for (i = 0; i < 64; i++) {
		ipad[i] ^= 0x36;
		opad[i] ^= 0x5c;
	}

	/* perform inner SHA1 */
	g_checksum_update(checksum, ipad, sizeof(ipad));
	g_checksum_update(checksum, data, data_len);
	length = sizeof(digest);
	g_checksum_get_digest(checksum, digest, &length);

	g_checksum_reset(checksum);

	/* perform outer SHA1 */
	g_checksum_update(checksum, opad, sizeof(opad));
	g_checksum_update(checksum, digest, length);
	length = sizeof(digest);
	g_checksum_get_digest(checksum, output, &length);

	g_checksum_reset(checksum);
}

int hmac_sha1(const void *key, size_t key_len,
                const void *data, size_t data_len, void *output, size_t size)
{
	GChecksum *checksum;

	checksum = g_checksum_new(G_CHECKSUM_SHA1);

	__hmac_sha1(checksum, key, key_len, data, data_len, output);

	g_checksum_free(checksum);

	return 0;
}

static void F(GChecksum *checksum, const char *password, size_t password_len,
				const char *salt, size_t salt_len,
				unsigned int iterations, unsigned int count,
							unsigned char *digest)
{
	unsigned char tmp1[SHA1_MAC_LEN];
	unsigned char tmp2[SHA1_MAC_LEN];
	unsigned char buf[36];
	unsigned int i, j;

	memcpy(buf, salt, salt_len);
	buf[salt_len + 0] = (count >> 24) & 0xff;
	buf[salt_len + 1] = (count >> 16) & 0xff;
	buf[salt_len + 2] = (count >> 8) & 0xff;
	buf[salt_len + 3] = count & 0xff;

	__hmac_sha1(checksum, password, password_len,
					buf, salt_len + 4, tmp1);
	memcpy(digest, tmp1, SHA1_MAC_LEN);

	for (i = 1; i < iterations; i++) {
		__hmac_sha1(checksum, password, password_len,
						tmp1, SHA1_MAC_LEN, tmp2);
		memcpy(tmp1, tmp2, SHA1_MAC_LEN);

		for (j = 0; j < SHA1_MAC_LEN; j++)
			digest[j] ^= tmp2[j];
	}
}

int pbkdf2_sha1(const void *password, size_t password_len,
			const void *salt, size_t salt_len,
			unsigned int iterations, void *output, size_t size)
{
	GChecksum *checksum;
	unsigned char *ptr = output;
	unsigned char digest[SHA1_MAC_LEN];
	unsigned int i;

	checksum = g_checksum_new(G_CHECKSUM_SHA1);

	for (i = 1; size > 0; i++) {
		size_t len;

		F(checksum, password, password_len, salt, salt_len,
						iterations, i, digest);

		len = size > SHA1_MAC_LEN ? SHA1_MAC_LEN : size;
		memcpy(ptr, digest, len);

		ptr += len;
		size -= len;
	}

	g_checksum_free(checksum);

	return 0;
}

int prf_sha1(const void *key, size_t key_len,
		const void *prefix, size_t prefix_len,
		const void *data, size_t data_len, void *output, size_t size)
{
	GChecksum *checksum;
	unsigned char input[1024];
	size_t input_len;
	unsigned int i, offset = 0;

	checksum = g_checksum_new(G_CHECKSUM_SHA1);

	memcpy(input, prefix, prefix_len);
	input[prefix_len] = 0;

	memcpy(input + prefix_len + 1, data, data_len);
	input[prefix_len + 1 + data_len] = 0;

	input_len = prefix_len + 1 + data_len + 1;

	for (i = 0; i < (size + 19) / 20; i++) {
		__hmac_sha1(checksum, key, key_len, input, input_len,
							output + offset);

		offset += 20;
		input[input_len - 1]++;
	}

	g_checksum_free(checksum);

	return 0;
}
