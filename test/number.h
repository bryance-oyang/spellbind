#ifndef TEST_NUMBER_H
#define TEST_NUMBER_H

#include "test.h"

void test_big_serialize()
{
	uint64_t nbytes;
	uint64_t b64_nbytes;
	uint8_t buf[1024];
	uint8_t buf64[1024];
	uint8_t buf2[1024];
	struct big *a = big_alloc();
	struct big *b = big_alloc();
	struct big *c = big_alloc();

	big_from_uint(a, 0);
	big_copy(b, a);

	big_serial_nbytes(&nbytes, a);
	big_serialize(buf, 1024, a);
	big_deserialize(c, buf, nbytes);
	assert(big_eq(c, b));

	big_serial_nbytes(&nbytes, a);
	big_serialize(buf, nbytes, a);
	spell_b64_encode_nbytes(&b64_nbytes, nbytes);
	spell_b64_encode(buf64, 1024, buf, nbytes);
	printbin(buf64, b64_nbytes);
	printf("\n");
	spell_b64_decode(buf2, 1024, &b64_nbytes, buf64, b64_nbytes);
	big_deserialize(c, buf2, nbytes);
	assert(big_eq(c, b));

	big_from_uint(a, 1);
	big_copy(b, a);

	big_serial_nbytes(&nbytes, a);
	big_serialize(buf, 1024, a);
	spell_b64_encode_nbytes(&b64_nbytes, nbytes);
	spell_b64_encode(buf64, 1024, buf, nbytes);
	printbin(buf64, b64_nbytes);
	printf("\n");
	spell_b64_decode(buf2, 1024, &b64_nbytes, buf64, b64_nbytes);
	big_deserialize(c, buf2, nbytes);
	assert(big_eq(c, b));

	big_serial_nbytes(&nbytes, a);
	big_serialize(buf, nbytes, a);
	big_deserialize(c, buf, nbytes);
	assert(big_eq(c, b));

	uint8_t s[1024];
	for (uint64_t i = 0; i < 1024; i++) {
		s[i] = i;
	}
	for (uint64_t i = 0; i < 1024; i++) {
		big_from_str(a, s, i);
		big_copy(b, a);

		big_serial_nbytes(&nbytes, a);
		if (nbytes > 1024) {
			assert(big_serialize(buf, 1024, a) == SPELL_BUF_WRITE_OVERFLOW);
			continue;
		}
		assert(big_serialize(buf, 1024, a) == SPELL_SUCCESS);
		assert(spell_b64_encode_nbytes(&b64_nbytes, nbytes) == SPELL_SUCCESS);
		if (b64_nbytes <= 1024) {
			spell_b64_encode(buf64, 1024, buf, nbytes);
			assert(spell_b64_decode(buf2, 1024, &b64_nbytes, buf64, b64_nbytes) == SPELL_SUCCESS);
			big_deserialize(c, buf2, nbytes);
			assert(big_eq(c, b));

			big_serial_nbytes(&nbytes, a);
			big_serialize(buf, nbytes, a);
			spell_b64_encode_nbytes(&b64_nbytes, nbytes);
			spell_b64_encode(buf64, 1024, buf, nbytes);
			spell_b64_decode(buf2, 1024, &b64_nbytes, buf64, b64_nbytes);
			big_deserialize(c, buf2, nbytes);
			assert(big_eq(c, b));
		} else {
			assert(spell_b64_encode(buf64, 1024, buf, nbytes) == SPELL_BUF_WRITE_OVERFLOW);
		}
	}

	big_free(a);
	big_free(b);
	big_free(c);
}

void test_pow()
{
	struct big *a = big_alloc();
	struct big *b = big_alloc();
	struct big *c = big_alloc();
	struct big *m = big_alloc();
	uint64_t C, D;

	for (uint64_t A = 0; A < 10; A++) {
	for (uint64_t B = 0; B < 10; B++) {
	for (uint64_t M = 1; M < 100; M++) {
		big_from_uint(a, A);
		big_from_uint(b, B);
		big_from_uint(m, M);
		z_crt_modpow(c, a, b, m);
		big_to_uint(&C, c);
		D = 1;
		for (uint64_t j = 0; j < B; j++) {
			D *= A;
		}
		assert(C == D % M);
	}}}

	big_free(a);
	big_free(b);
	big_free(c);
	big_free(m);
}

void test_arithmetic()
{
	uint64_t A;
	uint64_t B;
	uint64_t C, D;
	struct big *a = big_alloc();
	struct big *b = big_alloc();
	struct big *c = big_alloc();
	struct big *r = big_alloc();

	for (A = 0; A < 100; A++) {
		for (B = 0; B < 100; B++) {
			big_from_uint(a, A);
			big_from_uint(b, B);

			C = A + B;
			big_add(c, a, b);
			big_to_uint(&D, c);

			assert(C == D);
		}
	}

	for (A = 0; A < 100; A++) {
		for (B = 0; B < A; B++) {
			big_from_uint(a, A);
			big_from_uint(b, B);

			C = A - B;
			big_sub(c, a, b);
			big_to_uint(&D, c);

			assert(C == D);
		}
	}

	struct karatsuba_ctx *ctx = karatsuba_ctx_alloc();
	for (A = 0; A < 100; A++) {
		for (B = 0; B < 100; B++) {
			big_from_uint(a, A);
			big_from_uint(b, B);

			C = A * B;
			big_mul_karatsuba(c, a, b, ctx);
			big_to_uint(&D, c);

			assert(C == D);
		}
	}
	karatsuba_ctx_free(ctx);

	for (A = 0; A < 100; A++) {
		for (B = 1; B < 100; B++) {
			big_from_uint(a, A);
			big_from_uint(b, B);

			C = A / B;
			big_abs_div(c, r, a, b);

			big_to_uint(&D, c);
			assert(C == D);

			big_to_uint(&D, r);
			assert(A % B == D);
		}
	}

	big_free(a);
	big_free(b);
	big_free(c);
	big_free(r);
}

#endif /* TEST_NUMBER_H */
