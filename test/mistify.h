#ifndef TEST_MISTIFY_H
#define TEST_MISTIFY_H

#include "test.h"

static void test_mistify_file()
{
	struct quirky_rng *rng = quirky_rng_alloc();
	char *key = "password";
	char *bad_key = "passwords";
	char *plain_file = "test.dat";
	char *cipher_file = "cipher.dat";
	char *decipher_file = "decipher.dat";
	quirky_rng_init(rng);
	quirky_rng_add_entropy(rng, (uint8_t *)"hs", 2);
	mistify_file(cipher_file, plain_file, (uint8_t *)key, strlen(key), (uint8_t *)key, strlen(key), 16, rng);
	assert(demistify_file(decipher_file, cipher_file, (uint8_t *)key, strlen(key), (uint8_t *)key, strlen(key), 16) == SPELL_SUCCESS);
	assert(demistify_file(decipher_file, cipher_file, (uint8_t *)bad_key, strlen(bad_key), (uint8_t *)key, strlen(key), 16) == SPELL_KEY_ERROR);
	assert(demistify_file(decipher_file, cipher_file, (uint8_t *)key, strlen(key), (uint8_t *)bad_key, strlen(bad_key), 16) == SPELL_KEY_ERROR);
	quirky_rng_free(rng);
}

static void test_mistify()
{
	char buffer[1024];
	char *cipher_key = "secret";
	char *bad_key = "secrets";
	char *plaintext = "hello world!";
	char ciphertext[1024];
	struct quirky_rng *rng = quirky_rng_alloc();
	quirky_rng_init(rng);
	struct mist *mist = mist_alloc();

	mistify(mist, (uint8_t *)ciphertext, 1024, (uint8_t *)plaintext, strlen(plaintext), (uint8_t *)cipher_key, strlen(cipher_key), (uint8_t *)cipher_key, strlen(cipher_key), 16, rng);
	assert(demistify((uint8_t *)buffer, 1024, mist, (uint8_t *)ciphertext, (uint8_t *)cipher_key, strlen(cipher_key), (uint8_t *)cipher_key, strlen(cipher_key), 16) == SPELL_SUCCESS);
	assert(demistify(NULL, 0, mist, (uint8_t *)ciphertext, (uint8_t *)bad_key, strlen(bad_key), (uint8_t *)cipher_key, strlen(cipher_key), 16) == SPELL_KEY_ERROR);
	assert(ueq(strlen(plaintext), buffer, plaintext));
	ciphertext[0] ^= 'a';
	assert(demistify((uint8_t *)buffer, 1024, mist, (uint8_t *)ciphertext, (uint8_t *)cipher_key, strlen(cipher_key), (uint8_t *)cipher_key, strlen(cipher_key), 16) == SPELL_MAC_ERROR);

	uint64_t serial_nbytes = mist_serial_nbytes();
	uint8_t *serial = malloc(serial_nbytes);
	struct mist *demist = mist_alloc();
	mist_serialize(serial, serial_nbytes, mist);
	mist_deserialize(demist, serial, serial_nbytes);

	free(serial);
	mist_free(demist);
	mist_free(mist);
	quirky_rng_free(rng);
}

#endif /* TEST_MISTIFY_H */
