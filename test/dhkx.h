#ifndef TEST_DHKX_H
#define TEST_DHKX_H

#include "test.h"

static void dh_bench()
{
	struct big *private_e, *public;
	private_e = big_alloc();
	public = big_alloc();
	struct dh_param *dh_param = dh_param_alloc();
	struct quirky_rng *rng = quirky_rng_alloc();
	quirky_rng_init(rng);

	bench_start();
#ifdef DEBUG
	dh_param_init(dh_param, 64, rng);
#else /* DEBUG */
	dh_param_init(dh_param, 512, rng);
#endif /* DEBUG */
	bench_end("dh_param: %g ms\n");

	bench_start();
	dh_gen_key(public, private_e, dh_param, rng);
	bench_end("exponent: %g ms\n");

	uint8_t key[1024];
	bench_start();
	dh_finalize_key(key, 1024, private_e, public, dh_param, rng);
	bench_end("secret: %g ms\n");

	dh_param_free(dh_param);
	big_free(public);
	big_free(private_e);
	quirky_rng_free(rng);
}

static void test_dhkx()
{
	char *seed = "hi";
	struct quirky_rng *rng = quirky_rng_alloc();
	struct dh_param *dh_param = dh_param_alloc();
	struct big *a = big_alloc();
	struct big *b = big_alloc();
	struct big *c = big_alloc();
	struct big *A = big_alloc();
	struct big *B = big_alloc();
	struct big *C = big_alloc();

	quirky_rng_init(rng);
	quirky_rng_add_entropy(rng, (uint8_t *)seed, strlen(seed));
	dh_param_init(dh_param, 64, rng);

	dh_gen_key(A, a, dh_param, rng);
	dh_gen_key(B, b, dh_param, rng);
	dh_gen_key(C, c, dh_param, rng);

	uint8_t keyA[1024], keyB[1024], keyC[1024], keyD[1024];
	dh_finalize_key(keyA, 1024, B, a, dh_param, rng);
	dh_finalize_key(keyB, 1024, A, b, dh_param, rng);
	dh_finalize_key(keyC, 1024, B, c, dh_param, rng);
	dh_finalize_key(keyD, 1024, C, b, dh_param, rng);
	assert(ueq(1024, keyA, keyB));
	assert(!ueq(1024, keyA, keyC));
	assert(!ueq(1024, keyA, keyD));

	uint8_t *serial, *deserial;
	uint64_t serial_nbytes;
	struct dh_param *dh_param2 = dh_param_alloc();
	SPELL_TEST(dh_param_serial_nbytes(&serial_nbytes, dh_param));
	serial = malloc(serial_nbytes);
	deserial = malloc(serial_nbytes);
	assert(dh_param_serialize(serial, serial_nbytes - 1, dh_param) == SPELL_BUF_WRITE_OVERFLOW);
	SPELL_TEST(dh_param_serialize(serial, serial_nbytes, dh_param));
	SPELL_TEST(dh_param_deserialize(dh_param2, serial, serial_nbytes));
	SPELL_TEST(dh_param_serialize(deserial, serial_nbytes, dh_param2));
	assert(ueq(serial_nbytes, serial, deserial));
	assert(dh_param_deserialize(dh_param2, serial, serial_nbytes - 1) == SPELL_BUF_READ_OVERFLOW);

	free(serial);
	free(deserial);
	dh_param_free(dh_param2);
	dh_param_free(dh_param);
	big_free(a);
	big_free(A);
	big_free(b);
	big_free(B);
	big_free(c);
	big_free(C);
	quirky_rng_free(rng);
}

#endif /* TEST_DHKX_H */
