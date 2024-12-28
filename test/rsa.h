#ifndef TEST_RSA_H
#define TEST_RSA_H

#include "test.h"

static void test_rsa()
{
	const char *h = "hello!";
	struct big *message = big_alloc();
	struct big *cipher = big_alloc();
	struct big *decipher = big_alloc();
	big_from_str(message, (uint8_t*)h, strlen(h));

	struct quirky_rng *m = quirky_rng_alloc();
	quirky_rng_init(m);
	struct rsa_public_key *public = rsa_public_key_alloc();
	struct rsa_private_key *private = rsa_private_key_alloc();
	bench_start();
#ifdef DEBUG
	assert(rsa_gen_key(private, 64, m) == SPELL_SUCCESS);
#else /* DEBUG */
	assert(rsa_gen_key(private, 1024, m) == SPELL_SUCCESS);
#endif /* DEBUG */
	bench_end("rsa_keygen (ms): %f\n");
	rsa_publish(public, private);

	bench_start();
	assert(rsa_public_pow(cipher, message, public) == SPELL_SUCCESS);
	bench_end("encrypt (ms): %f\n");

	bench_start();
	assert(rsa_blinded_pow(decipher, cipher, private, m) == SPELL_SUCCESS);
	bench_end("decrypt (ms): %f\n");
	assert(big_eq(message, decipher));

	char buf[1024];
	big_to_str((uint8_t*)buf, 1024, decipher);
	assert(ueq(strlen(h), h, buf));

	uint8_t *serial = NULL, *deserial = NULL;
	uint64_t serial_nbytes;
	struct rsa_public_key *public2 = rsa_public_key_alloc();
	struct rsa_private_key *private2 = rsa_private_key_alloc();

	SPELL_TEST(rsa_private_key_serial_nbytes(&serial_nbytes, private));
	serial = realloc(serial, serial_nbytes);
	deserial = realloc(deserial, serial_nbytes);
	assert(rsa_private_key_serialize(serial, serial_nbytes - 1, private) == SPELL_BUF_WRITE_OVERFLOW);
	SPELL_TEST(rsa_private_key_serialize(serial, serial_nbytes, private));
	SPELL_TEST(rsa_private_key_deserialize(private2, serial, serial_nbytes));
	SPELL_TEST(rsa_private_key_serialize(deserial, serial_nbytes, private2));
	assert(ueq(serial_nbytes, serial, deserial));
	assert(rsa_private_key_deserialize(private2, serial, serial_nbytes - 1) == SPELL_BUF_READ_OVERFLOW);

	SPELL_TEST(rsa_public_key_serial_nbytes(&serial_nbytes, public));
	serial = realloc(serial, serial_nbytes);
	deserial = realloc(deserial, serial_nbytes);
	assert(rsa_public_key_serialize(serial, serial_nbytes - 1, public) == SPELL_BUF_WRITE_OVERFLOW);
	SPELL_TEST(rsa_public_key_serialize(serial, serial_nbytes, public));
	SPELL_TEST(rsa_public_key_deserialize(public2, serial, serial_nbytes));
	SPELL_TEST(rsa_public_key_serialize(deserial, serial_nbytes, public2));
	assert(ueq(serial_nbytes, serial, deserial));
	assert(rsa_public_key_deserialize(public2, serial, serial_nbytes - 1) == SPELL_BUF_READ_OVERFLOW);

	free(serial);
	free(deserial);
	rsa_public_key_free(public);
	rsa_public_key_free(public2);
	rsa_private_key_free(private);
	rsa_private_key_free(private2);
	big_free(decipher);
	big_free(cipher);
	big_free(message);
	quirky_rng_free(m);
}

#endif /* TEST_RSA_H */
