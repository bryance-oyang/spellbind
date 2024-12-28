/**
 * @file
 * @brief Error correcting code with Hamming(63, 57), but encoding 56 data
 * bits into 64 encoded bits
 *
 * Message lengths are restricted to be < 2^56. Prepends message with its
 * 56-bit length.
 *
 * Every 7 bytes -> 8 encoded bytes thereafter.
 *
 * Then pad until encoded nbytes is divisible by 64 (to make taking transposes
 * easier).
 *
 * Then bit-wise transpose m x 64 -> 64 x m: because the code can only correct
 * for single bit errors among 64-bits, to make it more resistant to sequential
 * bit errors, we transpose the final output using a restricted scratch space
 */

#include "spellbind.h"
#include "util.h"

#define CODE_TABLE_LEN 64

/**
 * Converts bit position index (0-index) into Hamming(63, 57) bit position index
 *
 * First 56 bits are data bits. Then 6 more parity bits.
 *
 * The parity bits shall have resulting position index 1, 10, 100, 1000, etc
 *
 * The data bits shall be numbered sequentially from 1 but need to fit in parity
 * bits.
 *
 * 0-index bit position: code bit position
 * 0: 3
 * 1: 5
 * 2: 6
 * 3: 7
 * 4: 9
 * ...
 *
 * (these aren't actually computed into the code_table)
 * 56: 1  (000001)
 * 57: 2  (000010)
 * 58: 4  (000100)
 * 59: 8  (001000)
 * 60: 16 (010000)
 * 61: 32 (100000)
 */
static inline void gen_code_table(uint32_t *code_table)
{
	uint32_t pow2 = 1;
	uint32_t pos = 1;
	for (uint32_t i = 0; i < 56; i++) {
		while (pos == pow2) {
			pow2 <<= 1;
			pos++;
		}
		code_table[i] = pos++;
	}
}

static inline void encode(uint64_t *code, const uint32_t *code_table, const uint32_t n)
{
	uint32_t parity = 0;
	for (uint32_t i = 0; i < 56; i++) {
		uint32_t bit = ((*code) >> i) & 1;
		parity ^= bit * code_table[i];
	}
	*code |= ((uint64_t)parity) << 56;
	*code |= ((*code) >> ((7 * n) % 32)) << 62;
}

static inline void correct(uint64_t *code, const uint32_t *code_table)
{
	uint32_t parity = 0;
	for (uint32_t i = 0; i < 56; i++) {
		uint32_t bit = ((*code) >> i) & 1;
		parity ^= bit * code_table[i];
	}
	/* include only 6 bits for parity */
	parity ^= ((*code) >> 56) & 63;

	/* parity now contains the code position of the incorrect bit, or 0 if all is good */
	if (parity == 0) {
		return;
	}

	/* correct single bit error */
	volatile uint64_t decoy = 0;
	for (uint32_t i = 0; i < 56; i++) {
		if (parity == code_table[i]) {
			*code ^= ((uint64_t)1) << i;
		} else {
			decoy ^= ((uint64_t)1) << i;
		}
	}
	(void)decoy;
}

static inline uint64_t ecc_unpadded_nbytes(const uint64_t plain_nbytes)
{
	if (plain_nbytes == 0) {
		return sizeof(uint64_t);
	} else {
		return sizeof(uint64_t) + ((plain_nbytes - 1) / 7 + 1) * 8;
	}
}

enum SPELL_RET ecc_encode_nbytes(uint64_t *encoded_nbytes, const uint64_t plain_nbytes)
{
	/* restrict to len < 2^56 */
	if (plain_nbytes >= ((uint64_t)1 << 56)) {
		return SPELL_INT_OVERFLOW;
	}
	*encoded_nbytes = ((ecc_unpadded_nbytes(plain_nbytes) - 1) / 64 + 1) * 64;
	return SPELL_SUCCESS;
}

enum ECC_TRANSPOSE_MODE {
	ECC_TRANSPOSE_ENCODE,
	ECC_TRANSPOSE_DECODE,
};

/**
 * encode: m x 64 -> 64 x m
 * decode: 64 x m -> m x 64
 */
static inline enum SPELL_RET ecc_transpose(const enum ECC_TRANSPOSE_MODE mode,
	uint8_t *restrict out, const uint64_t max_out_nbytes,
	const uint8_t *restrict in, const uint64_t in_nbytes)
{
	if (in_nbytes > max_out_nbytes) {
		return SPELL_BUF_WRITE_OVERFLOW;
	}

	for (uint64_t i = 0; i < in_nbytes; i++) {
		out[i] = 0;
	}

	const uint64_t m = in_nbytes / 8;
	if (mode == ECC_TRANSPOSE_ENCODE) {
		for (uint64_t i = 0; i < m; i++) {
			for (uint64_t j = 0; j < 64; j++) {
				uint64_t p = 64 * i + j;
				uint8_t bit = (in[p / 8] >> (p % 8)) & 1;

				uint64_t q = m * j + i;
				out[q / 8] |= bit << (q % 8);
			}
		}
	} else if (mode == ECC_TRANSPOSE_DECODE) {
		for (uint64_t i = 0; i < 64; i++) {
			for (uint64_t j = 0; j < m; j++) {
				uint64_t p = m * i + j;
				uint8_t bit = (in[p / 8] >> (p % 8)) & 1;

				uint64_t q = 64 * j + i;
				out[q / 8] |= bit << (q % 8);
			}
		}
	} else {
		return SPELL_FAILURE;
	}

	return SPELL_SUCCESS;
}

enum SPELL_RET ecc_encode(uint8_t *encoded, const uint64_t max_encoded_nbytes,
	const uint8_t *plain, const uint64_t plain_nbytes,
	uint8_t *restrict scratch, const uint64_t max_scratch_nbytes,
	struct quirky_rng *rng)
{
	if (max_scratch_nbytes < max_encoded_nbytes) {
		return SPELL_BUF_WRITE_OVERFLOW;
	}

	enum SPELL_RET retval = SPELL_SUCCESS;
	uint64_t encoded_nbytes;

	SPELL(ecc_encode_nbytes(&encoded_nbytes, plain_nbytes), retval, out);
	if (encoded_nbytes > max_encoded_nbytes) {
		retval = SPELL_BUF_WRITE_OVERFLOW;
		goto out;
	}
	const uint64_t unpadded_nbytes = ecc_unpadded_nbytes(plain_nbytes);
	const uint64_t pad_nbytes = encoded_nbytes - unpadded_nbytes;

	uint32_t code_table[CODE_TABLE_LEN];
	gen_code_table(code_table);
	uint64_t buf;

	/* pad */
	quirky_rng_rand_bytes(&scratch[unpadded_nbytes], pad_nbytes, rng);

	/* reverse order looping to allow encoded to be same as plain */
	/* loop -1 to account for first 8 bytes being length */
	uint64_t byte = unpadded_nbytes - 1;
	for (int64_t i = unpadded_nbytes / 8 - 2; i >= 0; i--) {
		buf = 0;
		for (uint64_t j = 0; j < 7 && 7 * i + j < plain_nbytes; j++) {
			buf |= ((uint64_t)plain[7 * i + j]) << (8 * j);
		}

		encode(&buf, code_table, i);

		for (int64_t j = 7; j >= 0; j--) {
			scratch[byte--] = buf >> (8 * j);
		}
	}
	mistify_dance(scratch, encoded_nbytes, plain_nbytes);

	/* write length */
	buf = plain_nbytes;
	encode(&buf, code_table, unpadded_nbytes / 8 - 1);
	for (int64_t i = 7; i >= 0; i--) {
		scratch[byte--] = buf >> (8 * i);
	}

	mistify_dance(scratch, 8, encoded_nbytes);
	SPELL(ecc_transpose(ECC_TRANSPOSE_ENCODE, encoded, max_encoded_nbytes, scratch, encoded_nbytes), retval, out);

out:
	/* erase secrets */
	SPELL_WRITE_ONCE(uint64_t, buf, 0);
	erase_buf(scratch, max_scratch_nbytes);
	return retval;
}

enum SPELL_RET ecc_decode(uint8_t *plain, const uint64_t max_plain_nbytes,
	uint64_t *plain_nbytes, const uint8_t *encoded, const uint64_t encoded_nbytes,
	uint8_t *restrict scratch, const uint64_t max_scratch_nbytes)
{
	if (encoded_nbytes < 64 || encoded_nbytes % 64 != 0) {
		return SPELL_INVALID_INPUT;
	}
	if (max_scratch_nbytes < encoded_nbytes) {
		return SPELL_BUF_WRITE_OVERFLOW;
	}

	enum SPELL_RET retval = SPELL_SUCCESS;
	uint32_t code_table[CODE_TABLE_LEN];
	gen_code_table(code_table);

	SPELL(ecc_transpose(ECC_TRANSPOSE_DECODE, scratch, max_scratch_nbytes, encoded, encoded_nbytes), retval, out);
	mistify_dance(scratch, 8, encoded_nbytes);

	/* extract length */
	uint64_t buf = 0;
	for (uint64_t i = 0; i < 8; i++) {
		buf |= ((uint64_t)scratch[i]) << (8 * i);
	}
	correct(&buf, code_table);
	*plain_nbytes = (buf << 8) >> 8;

	/* check length self-consistency */
	if (*plain_nbytes > max_plain_nbytes) {
		retval = SPELL_BUF_WRITE_OVERFLOW;
		goto out;
	}
	uint64_t needed_encoded_nbytes;
	SPELL(ecc_encode_nbytes(&needed_encoded_nbytes, *plain_nbytes), retval, out);
	if (needed_encoded_nbytes != encoded_nbytes) {
		retval = SPELL_INVALID_INPUT;
		goto out;
	}
	mistify_dance(scratch, encoded_nbytes, *plain_nbytes);

	uint64_t byte = 0;
	/* loop -1 to account for first 8 bytes being length */
	for (uint64_t i = 0; i < encoded_nbytes / 8 - 1; i++) {
		buf = 0;
		for (uint64_t j = 0; j < 8; j++) {
			buf |= ((uint64_t)scratch[8 * (i + 1) + j]) << (8 * j);
		}

		correct(&buf, code_table);

		for (uint64_t j = 0; j < 7 && byte < (*plain_nbytes); j++) {
			plain[byte++] = buf >> (8 * j);
		}
	}

out:
	/* erase secrets */
	SPELL_WRITE_ONCE(uint64_t, buf, 0);
	erase_buf(scratch, max_scratch_nbytes);
	return retval;
}
