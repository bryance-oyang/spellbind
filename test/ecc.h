#ifndef TEST_ECC_H
#define TEST_ECC_H

#include "test.h"

static void test_ecc()
{
	uint64_t encoded_nbytes;
	uint64_t plain_nbytes, decoded_nbytes;
	const char *plain;
	uint8_t encoded[1024];
	uint8_t decoded[1024];
	uint8_t scratch[1024];
	struct quirky_rng *rng = quirky_rng_alloc();
	quirky_rng_init(rng);

	int double_bit_error_test = 0;
	const char *plains[] = {"", "1", "123456", "1234567", "12345678", "123456789", "iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii"};
	for (uint64_t j = 0; j < sizeof(plains) / sizeof(plains[0]); j++) {
		plain = plains[j];
		printf("testing %s\n", plain);
		plain_nbytes = strlen(plain);
		SPELL_TEST(ecc_encode_nbytes(&encoded_nbytes, plain_nbytes));
		SPELL_TEST(ecc_encode(encoded, 1024, (uint8_t *)plain, plain_nbytes, scratch, 1024, rng));
		assert(ecc_encode(encoded, encoded_nbytes - 1, (uint8_t *)plain, plain_nbytes, scratch, 1024, rng) == SPELL_BUF_WRITE_OVERFLOW);
		assert(ecc_decode(decoded, 1024, &decoded_nbytes, encoded, encoded_nbytes + 1, scratch, 1024) == SPELL_INVALID_INPUT);
		assert(ecc_decode(decoded, 1024, &decoded_nbytes, encoded, encoded_nbytes - 1, scratch, 1024) == SPELL_INVALID_INPUT);
		if (plain_nbytes > 0) {
			assert(ecc_decode(decoded, plain_nbytes - 1, &decoded_nbytes, encoded, encoded_nbytes, scratch, 1024) == SPELL_BUF_WRITE_OVERFLOW);
		}
		SPELL_TEST(ecc_decode(decoded, 1024, &decoded_nbytes, encoded, encoded_nbytes, scratch, 1024));
		assert(plain_nbytes == decoded_nbytes);
		assert(ueq(plain_nbytes, plain, decoded));

		for (uint64_t i = 0; i < 8 * encoded_nbytes; i++) {
			SPELL_TEST(ecc_encode(encoded, 1024, (uint8_t *)plain, plain_nbytes, scratch, 1024, rng));
			assert(ecc_encode(encoded, encoded_nbytes - 1, (uint8_t *)plain, plain_nbytes, scratch, 1024, rng) == SPELL_BUF_WRITE_OVERFLOW);
			assert(ecc_decode(decoded, 1024, &decoded_nbytes, encoded, encoded_nbytes + 1, scratch, 1024) == SPELL_INVALID_INPUT);
			assert(ecc_decode(decoded, 1024, &decoded_nbytes, encoded, encoded_nbytes - 1, scratch, 1024) == SPELL_INVALID_INPUT);
			if (plain_nbytes > 0) {
				assert(ecc_decode(decoded, plain_nbytes - 1, &decoded_nbytes, encoded, encoded_nbytes, scratch, 1024) == SPELL_BUF_WRITE_OVERFLOW);
			}
			encoded[i / 8] ^= ((uint8_t)1) << (i % 8);
			SPELL_TEST(ecc_decode(decoded, 1024, &decoded_nbytes, encoded, encoded_nbytes, scratch, 1024));
			assert(plain_nbytes == decoded_nbytes);
			assert(ueq(plain_nbytes, plain, decoded));
		}

		if (plain_nbytes > 8) {
			double_bit_error_test++;
			for (uint64_t i = 0; i < encoded_nbytes * 8 - 1; i++) {
				SPELL_TEST(ecc_encode(encoded, 1024, (uint8_t *)plain, plain_nbytes, scratch, 1024, rng));
				assert(ecc_encode(encoded, encoded_nbytes - 1, (uint8_t *)plain, plain_nbytes, scratch, 1024, rng) == SPELL_BUF_WRITE_OVERFLOW);
				assert(ecc_decode(decoded, 1024, &decoded_nbytes, encoded, encoded_nbytes + 1, scratch, 1024) == SPELL_INVALID_INPUT);
				assert(ecc_decode(decoded, 1024, &decoded_nbytes, encoded, encoded_nbytes - 1, scratch, 1024) == SPELL_INVALID_INPUT);
				if (plain_nbytes > 0) {
					assert(ecc_decode(decoded, plain_nbytes - 1, &decoded_nbytes, encoded, encoded_nbytes, scratch, 1024) == SPELL_BUF_WRITE_OVERFLOW);
				}
				encoded[i / 8] ^= ((uint8_t)1) << (i % 8);
				encoded[(i + 1) / 8] ^= ((uint8_t)1) << ((i + 1) % 8);

				SPELL_TEST(ecc_decode(decoded, 1024, &decoded_nbytes, encoded, encoded_nbytes, scratch, 1024));
				assert(plain_nbytes == decoded_nbytes);
				assert(ueq(plain_nbytes, plain, decoded));
			}
		}
	}
	assert(double_bit_error_test > 0);

	quirky_rng_free(rng);
}

#endif /* TEST_ECC_H */
