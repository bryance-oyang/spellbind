/**
 * @file
 * @brief base64 encoding
 */

#include "spellbind.h"
#include "util.h"

enum SPELL_RET spell_b64_encode_nbytes(uint64_t *b64_nbytes, const uint64_t binary_nbytes)
{
	if (binary_nbytes > UINT64_MAX / 8) {
		*b64_nbytes = 0;
		return SPELL_INT_OVERFLOW;
	}
	if (binary_nbytes == 0) {
		*b64_nbytes = 0;
		return SPELL_SUCCESS;
	}

	uint64_t binary_ntriplet = (binary_nbytes - 1) / 3 + 1;
	*b64_nbytes = binary_ntriplet * 4;
	return SPELL_SUCCESS;
}

enum SPELL_RET spell_b64_decode_max_nbytes(uint64_t *binary_nbytes, const uint64_t b64_nbytes)
{
	if (b64_nbytes % 4 != 0) {
		return SPELL_INVALID_INPUT;
	}
	*binary_nbytes = (b64_nbytes / 4) * 3;
	return SPELL_SUCCESS;
}

#define ENCODE_CHAR6(out, c) do { \
	if ((c) < 26) { \
		(out) = 'A' + ((c) - 0); \
	} else if ((c) < 52) { \
		(out) = 'a' + ((c) - 26); \
	} else if ((c) < 62) { \
		(out) = '0' + ((c) - 52); \
	} else if ((c) == 62) { \
		(out) = '+'; \
	} else if ((c) == 63) { \
		(out) = '/'; \
	} else { \
		(out) = '*'; \
	} \
} while (0)

#define DECODE_CHAR6(out, c) do { \
	if ('A' <= (c) && (c) < 'A' + 26) { \
		(out) = (c) - 'A'; \
	} else if ('a' <= (c) && (c) < 'a' + 26) { \
		(out) = (c) - 'a' + 26; \
	} else if ('0' <= (c) && (c) < '0' + 10) { \
		(out) = (c) - '0' + 52; \
	} else if ((c) == '+') { \
		(out) = 62; \
	} else if ((c) == '/') { \
		(out) = 63; \
	} else { \
		(out) = -1; \
	} \
} while (0)

enum SPELL_RET spell_b64_encode(uint8_t *b64, const uint64_t max_b64_nbytes,
	const uint8_t *binary, const uint64_t binary_nbytes)
{
	if (binary_nbytes == 0) {
		return SPELL_SUCCESS;
	}

	uint64_t b64_nbytes;
	if (spell_b64_encode_nbytes(&b64_nbytes, binary_nbytes) != SPELL_SUCCESS) {
		return SPELL_INT_OVERFLOW;
	}
	if (b64_nbytes > max_b64_nbytes) {
		return SPELL_BUF_WRITE_OVERFLOW;
	}

	uint8_t c;
	uint64_t triplet;
	const uint64_t b64_npad = (3 - (binary_nbytes % 3)) % 3;
	uint64_t b64_byte = b64_nbytes - 1;

	/* reverse encoding to allow b64 and binary to overlap */
	for (int64_t i = b64_nbytes / 4 - 1; i >= 0; i--) {
		triplet = 0;
		for (uint64_t j = 0; j < 3 && 3 * i + j < binary_nbytes; j++) {
			triplet |= ((uint64_t)binary[3 * i + j]) << (8 * (2 - j));
		}

		for (int64_t j = 3; j >= 0; j--) {
			c = (triplet >> (6 * (3 - j))) & 0x3f;
			ENCODE_CHAR6(b64[b64_byte], c);
			b64_byte--;
		}
	}

	/* fix padding at end */
	for (uint64_t i = 0; i < b64_npad; i++) {
		b64[b64_nbytes - i - 1] = '=';
	}

	/* erase secrets */
	SPELL_WRITE_ONCE(uint64_t, triplet, 0);
	SPELL_WRITE_ONCE(uint8_t, c, 0);
	return SPELL_SUCCESS;
}

enum SPELL_RET spell_b64_decode(uint8_t *binary, const uint64_t max_binary_nbytes,
	uint64_t *binary_nbytes, const uint8_t *b64, const uint64_t b64_nbytes)
{
	/* require padded decoding */
	if (b64_nbytes % 4 != 0) {
		return SPELL_INVALID_INPUT;
	}
	if (b64_nbytes == 0) {
		return SPELL_SUCCESS;
	}

	enum SPELL_RET retval = SPELL_SUCCESS;
	int8_t q;
	uint64_t quad;
	uint64_t binary_byte = 0;
	uint64_t npad = 0;

	for (uint64_t i = 0; i < b64_nbytes / 4; i++) {
		quad = 0;
		for (uint64_t j = 0; j < 4; j++) {
			const uint64_t pos = 4 * i + j;

			if (b64[pos] == '=') {
				/* ensure last characters are = and at most 2 */
				npad = b64_nbytes - pos;
				if (npad > 2) {
					retval = SPELL_INVALID_INPUT;
					goto out;
				}
				if (npad == 2 && b64[pos + 1] != '=') {
					retval = SPELL_INVALID_INPUT;
					goto out;
				}
				break;
			}

			DECODE_CHAR6(q, b64[pos]);
			if (q < 0) {
				retval = SPELL_INVALID_INPUT;
				goto out;
			}
			quad |= ((uint64_t)q) << (6 * (3 - j));
		}

		for (uint64_t j = 0; j < 3; j++) {
			if (binary_byte >= max_binary_nbytes) {
				retval = SPELL_BUF_WRITE_OVERFLOW;
				goto out;
			}
			binary[binary_byte++] = quad >> (8 * (2 - j));
		}
	}

	/* determine output length */
	*binary_nbytes = (b64_nbytes / 4) * 3 - npad;

out:
	/* erase secrets */
	SPELL_WRITE_ONCE(uint64_t, quad, 0);
	SPELL_WRITE_ONCE(int8_t, q, 0);
	if (retval != SPELL_SUCCESS) {
		erase_buf(binary, max_binary_nbytes);
	}
	return retval;
}
