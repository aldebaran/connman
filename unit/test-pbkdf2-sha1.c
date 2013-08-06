/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2012  Intel Corporation. All rights reserved.
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

#include <stdio.h>
#include <string.h>

#include <glib.h>

#include "src/shared/sha1.h"

struct pbkdf2_data {
	const char *password;
	unsigned int password_len;
	const char *salt;
	unsigned int salt_len;
	unsigned int count;
	unsigned int key_len;
	const char *key;
};

static void pbkdf2_test(gconstpointer data)
{
	const struct pbkdf2_data *test = data;
	unsigned int password_len;
	unsigned int salt_len;
	unsigned int key_len;
	unsigned char output[25];
	char key[50];
	unsigned int i;
	int result;

	password_len = test->password_len ? : strlen(test->password);
	salt_len = test->salt_len ? : strlen(test->salt);

	key_len = test->key_len ? : (strlen(test->key) / 2);

	if (g_test_verbose()) {
		g_print("Password = \"%s\" (%d octects)\n",
					test->password, password_len);
		g_print("Salt     = \"%s\" (%d octects)\n",
					test->salt, salt_len);
		g_print("Count    = %d\n", test->count);
		g_print("Key      = %s (%d octects)\n", test->key, key_len);
	}

	result = pbkdf2_sha1(test->password, password_len,
					test->salt, salt_len,
					test->count, output, key_len);

	g_assert(result == 0);

	for (i = 0; i < key_len; i++)
		sprintf(key + (i * 2), "%02x", output[i]);

	if (g_test_verbose())
		g_print("Result   = %s\n", key);

	g_assert(strcmp(test->key, key) == 0);
}

static const struct pbkdf2_data pbkdf2_test_vector_1 = {
	.password	= "password",
	.salt		= "salt",
	.count		= 1,
	.key		= "0c60c80f961f0e71f3a9b524af6012062fe037a6",
	.key_len	= 20,
};

static const struct pbkdf2_data pbkdf2_test_vector_2 = {
	.password	= "password",
	.salt		= "salt",
	.count		= 2,
	.key		= "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957",
	.key_len	= 20,
};

static const struct pbkdf2_data pbkdf2_test_vector_3 = {
	.password	= "password",
	.salt		= "salt",
	.count		= 4096,
	.key		= "4b007901b765489abead49d926f721d065a429c1",
	.key_len	= 20,
};

static const struct pbkdf2_data pbkdf2_test_vector_4 = {
	.password	= "password",
	.salt		= "salt",
	.count		= 16777216,
	.key		= "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984",
	.key_len	= 20,
};

static const struct pbkdf2_data pbkdf2_test_vector_5 = {
	.password	= "passwordPASSWORDpassword",
	.salt		= "saltSALTsaltSALTsaltSALTsaltSALTsalt",
	.count		= 4096,
	.key		= "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038",
	.key_len	= 25,
};

static const struct pbkdf2_data pbkdf2_test_vector_6 = {
	.password	= "pass\0word",
	.password_len	= 9,
	.salt		= "sa\0lt",
	.salt_len	= 5,
	.count		= 4096,
	.key		= "56fa6aa75548099dcc37d7f03425e0c3",
	.key_len	= 16,
};

static const struct pbkdf2_data athena_test_vector_1 = {
	.password	= "password",
	.salt		= "ATHENA.MIT.EDUraeburn",
	.count		= 1,
	.key		= "cdedb5281bb2f801565a1122b2563515",
};

static const struct pbkdf2_data athena_test_vector_2 = {
	.password	= "password",
	.salt		= "ATHENA.MIT.EDUraeburn",
	.count		= 2,
	.key		= "01dbee7f4a9e243e988b62c73cda935d",
};

static const struct pbkdf2_data athena_test_vector_3 = {
	.password	= "password",
	.salt		= "ATHENA.MIT.EDUraeburn",
	.count		= 1200,
	.key		= "5c08eb61fdf71e4e4ec3cf6ba1f5512b",
};

static const struct pbkdf2_data athena_test_vector_4 = {
	.password	= "password",
	.salt		= "\x12\x34\x56\x78\x78\x56\x34\x12",
	.count		= 5,
	.key		= "d1daa78615f287e6a1c8b120d7062a49",
};

static const struct pbkdf2_data athena_test_vector_5 = {
	.password	= "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
			  "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
	.salt		= "pass phrase equals block size",
	.count		= 1200,
	.key		= "139c30c0966bc32ba55fdbf212530ac9",
};

static const struct pbkdf2_data athena_test_vector_6 = {
	.password	= "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
			  "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
	.salt		= "pass phrase exceeds block size",
	.count		= 1200,
	.key		= "9ccad6d468770cd51b10e6a68721be61",
};

static const struct pbkdf2_data athena_test_vector_7 = {
	.password	= "\xf0\x9d\x84\x9e",	/* g-clef (0xf09d849e) */
	.salt		= "EXAMPLE.COMpianist",
	.count		= 50,
	.key		= "6b9cf26d45455a43a5b8bb276a403b39",
};

struct psk_data {
	const char *passphrase;
	const unsigned char *ssid;
	size_t ssid_len;
	const char *network;
	const char *psk;
};

static void psk_test(gconstpointer data)
{
	const struct psk_data *test = data;
	unsigned char ssid[32];
	size_t ssid_len;
	unsigned char output[32];
	char psk[65];
	unsigned int i;
	int result;

	if (!test->network) {
		memcpy(ssid, test->ssid, test->ssid_len);
		ssid_len = test->ssid_len;
	} else {
		ssid_len = strlen(test->network);
		memcpy(ssid, test->network, ssid_len);
	}

	if (g_test_verbose()) {
		g_print("Passphrase  = \"%s\"\n", test->passphrase);
		g_print("SSID        = {");
		for (i = 0; i < ssid_len; i++)
			g_print("%s'%c'", i == 0 ? " " : ", ",
						ssid[i]);
		g_print(" }\n");
		g_print("SSID Length = %zd\n", ssid_len);
		g_print("PSK         = %s\n", test->psk);
	}

	result = pbkdf2_sha1(test->passphrase, strlen(test->passphrase),
						ssid, ssid_len, 4096,
						output, sizeof(output));

	g_assert(result == 0);

	for (i = 0; i < sizeof(output); i++)
		sprintf(psk + (i * 2), "%02x", output[i]);

	if (g_test_verbose())
		g_print("Result      = %s\n", psk);

	g_assert(strcmp(test->psk, psk) == 0);
}

static const unsigned char psk_test_case_1_ssid[] = { 'I', 'E', 'E', 'E' };

static const struct psk_data psk_test_case_1 = {
	.passphrase	= "password",
	.ssid		= psk_test_case_1_ssid,
	.ssid_len	= sizeof(psk_test_case_1_ssid),
	.psk		= "f42c6fc52df0ebef9ebb4b90b38a5f90"
			  "2e83fe1b135a70e23aed762e9710a12e",
};

static const unsigned char psk_test_case_2_ssid[] = { 'T', 'h', 'i', 's',
					'I', 's', 'A', 'S', 'S', 'I', 'D' };

static const struct psk_data psk_test_case_2 = {
	.passphrase	= "ThisIsAPassword",
	.ssid		= psk_test_case_2_ssid,
	.ssid_len	= sizeof(psk_test_case_2_ssid),
	.psk		= "0dc0d6eb90555ed6419756b9a15ec3e3"
			  "209b63df707dd508d14581f8982721af",
};

static const unsigned char psk_test_case_3_ssid[] = {
				'Z', 'Z', 'Z', 'Z', 'Z', 'Z', 'Z', 'Z',
				'Z', 'Z', 'Z', 'Z', 'Z', 'Z', 'Z', 'Z',
				'Z', 'Z', 'Z', 'Z', 'Z', 'Z', 'Z', 'Z',
				'Z', 'Z', 'Z', 'Z', 'Z', 'Z', 'Z', 'Z' };

static const struct psk_data psk_test_case_3 = {
	.passphrase	= "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	.ssid		= psk_test_case_3_ssid,
	.ssid_len	= sizeof(psk_test_case_3_ssid),
	.psk		= "becb93866bb8c3832cb777c2f559807c"
			  "8c59afcb6eae734885001300a981cc62",
};

int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_data_func("/pbkdf2-sha1/PBKDF2 Test vector 1",
					&pbkdf2_test_vector_1, pbkdf2_test);
	g_test_add_data_func("/pbkdf2-sha1/PBKDF2 Test vector 2",
					&pbkdf2_test_vector_2, pbkdf2_test);
	g_test_add_data_func("/pbkdf2-sha1/PBKDF2 Test vector 3",
					&pbkdf2_test_vector_3, pbkdf2_test);
	g_test_add_data_func("/pbkdf2-sha1/PBKDF2 Test vector 4",
					&pbkdf2_test_vector_4, pbkdf2_test);
	g_test_add_data_func("/pbkdf2-sha1/PBKDF2 Test vector 5",
					&pbkdf2_test_vector_5, pbkdf2_test);
	g_test_add_data_func("/pbkdf2-sha1/PBKDF2 Test vector 6",
					&pbkdf2_test_vector_6, pbkdf2_test);

	g_test_add_data_func("/pbkdf2-sha1/ATHENA Test vector 1",
					&athena_test_vector_1, pbkdf2_test);
	g_test_add_data_func("/pbkdf2-sha1/ATHENA Test vector 2",
					&athena_test_vector_2, pbkdf2_test);
	g_test_add_data_func("/pbkdf2-sha1/ATHENA Test vector 3",
					&athena_test_vector_3, pbkdf2_test);
	g_test_add_data_func("/pbkdf2-sha1/ATHENA Test vector 4",
					&athena_test_vector_4, pbkdf2_test);
	g_test_add_data_func("/pbkdf2-sha1/ATHENA Test vector 5",
					&athena_test_vector_5, pbkdf2_test);
	g_test_add_data_func("/pbkdf2-sha1/ATHENA Test vector 6",
					&athena_test_vector_6, pbkdf2_test);
	g_test_add_data_func("/pbkdf2-sha1/ATHENA Test vector 7",
					&athena_test_vector_7, pbkdf2_test);

	g_test_add_data_func("/pbkdf2-sha1/PSK Test case 1",
					&psk_test_case_1, psk_test);
	g_test_add_data_func("/pbkdf2-sha1/PSK Test case 2",
					&psk_test_case_2, psk_test);
	g_test_add_data_func("/pbkdf2-sha1/PSK Test case 3",
					&psk_test_case_3, psk_test);

	return g_test_run();
}
