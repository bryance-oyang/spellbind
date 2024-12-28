/**
 * @file
 * @brief A Keccak and SHA-3 hash implementation for spellbind
 *
 * High Wizards:
 * 	Guido Bertoni, Joan Daemen, Michaël Peeters, Gilles Van Assche
 *
 * Example usage:
 * 	char *message = "hello, world!";
 * 	sha3_256(output, (uint8_t *)message, strlen(message));
 *
 * References:
 * 	https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
 * 	https://csrc.nist.gov/pubs/fips/202/final
 * 	https://keccak.team/files/Keccak-reference-3.0.pdf
 */

#ifndef SPELLBIND_SHA3_H
#define SPELLBIND_SHA3_H

#include "spellbind.h"
#include <stdlib.h>

#define SPELLBIND_KECCAK_NWORD 25
#define SPELLBIND_KECCAK_Nrc 255
#define SPELLBIND_KECCAK_NROUND_CONST 24

/* see keccak_pad() */
#define SPELLBIND_SHA3_PAD_CONST0 134
#define SPELLBIND_SHA3_PAD_CONST1 6

#define SPELLBIND_SHA3_WORD_NBITS 64

struct keccak_ctx {
	/* swappable internal state pointers */
	uint64_t *A;
	uint64_t *Aresult;

	/* actual memory for A and Aresult */
	uint64_t A0_memory[SPELLBIND_KECCAK_NWORD];
	uint64_t A1_memory[SPELLBIND_KECCAK_NWORD];

	/* precomputed lookup tables */
	int32_t rho_rotate[SPELLBIND_KECCAK_NWORD];
	int32_t rho_anti_rotate[SPELLBIND_KECCAK_NWORD];
	uint64_t round_const[SPELLBIND_KECCAK_NROUND_CONST];

	/* 1'A if bit in word, 0 if not in word */
	uint64_t word_mask;

	/* keccak parameters */
	int32_t b;
	int32_t nround;
	int32_t word_nbits;
	int32_t l;

	/* sponge parameters */
	int32_t rate;
	int32_t capacity;

	/* output parameters */
	int32_t out_nbits;

	/* bit position when absorbing into rate */
	uint64_t rate_bit_pos;
};

static inline void keccak_swapA(struct keccak_ctx *k)
{
	uint64_t *swp = k->A;
	k->A = k->Aresult;
	k->Aresult = swp;
}

static void keccak_init_word_mask(struct keccak_ctx *restrict k)
{
	/* put k->word_nbits ones (1111...) into word_mask */
	if (k->word_nbits == 64) {
		k->word_mask = 0;
		k->word_mask--;
	} else {
		k->word_mask = ((uint64_t)1 << k->word_nbits) - 1;
	}
}

static void keccak_init_rho_const(struct keccak_ctx *restrict k)
{
	for (int32_t i = 0; i < 25; i++) {
		k->rho_rotate[i] = 0;
		k->rho_anti_rotate[i] = 0;
	}

	int32_t x = 1;
	int32_t y = 0;
	for (int32_t t = 0; t < 24; t++) {
		int32_t rotate = ((t + 1) * (t + 2) / 2) % k->word_nbits;
		k->rho_rotate[5 * y + x] = rotate;
		k->rho_anti_rotate[5 * y + x] = (k->word_nbits - rotate) % k->word_nbits;

		int32_t new_x = y;
		int32_t new_y = (2 * x + 3 * y) % 5;
		x = new_x;
		y = new_y;
	}
}

static void keccak_init_round_const(struct keccak_ctx *restrict k)
{
	uint8_t rc[SPELLBIND_KECCAK_Nrc];
	rc[0] = 1;
	for (int32_t t = 1; t < SPELLBIND_KECCAK_Nrc; t++) {
		uint8_t r8 = rc[t - 1] >> 7;
		uint8_t r8_0456 = (r8) | (r8 << 4) | (r8 << 5) | (r8 << 6);
		rc[t] = rc[t - 1] << 1;
		rc[t] ^= r8_0456;
	}

	for (int32_t ir = 0; ir < SPELLBIND_KECCAK_NROUND_CONST; ir++) {
		k->round_const[ir] = 0;
		for (int32_t j = 0; j <= k->l; j++) {
			uint32_t bit_pos = ((uint32_t)1 << j) - 1;
			k->round_const[ir] |= (uint64_t)(rc[(j + 7 * ir) % SPELLBIND_KECCAK_Nrc] & 1) << bit_pos;
		}
	}
}

static enum SPELL_RET keccak_init(struct keccak_ctx *restrict keccak_ctx,
	int32_t b, int32_t nround, int32_t capacity, int32_t out_nbits)
{
	/* ensure segfault if this function doesn't succeed
	and return value is not checked */
	keccak_ctx->A = NULL;
	keccak_ctx->Aresult = NULL;

	if (b <= 0 || nround <= 0 || out_nbits < 0) {
		goto err;
	}
	int valid_input = 0;
	for (int32_t i = 6; i >= 0; i--) {
		if (b == 25 * ((int32_t)1 << i)) {
			valid_input = 1;
			break;
		}
	}
	if (!valid_input) {
		goto err;
	}

	keccak_ctx->b = b;
	keccak_ctx->nround = nround;
	keccak_ctx->capacity = capacity;
	keccak_ctx->rate = keccak_ctx->b - keccak_ctx->capacity;
	keccak_ctx->out_nbits = out_nbits;

	int32_t word_nbits = b / 25;
	keccak_ctx->word_nbits = word_nbits;
	keccak_ctx->l = -1;
	while (word_nbits > 0) {
		keccak_ctx->l++;
		word_nbits >>= 1;
	}

	/* limit number of rounds so round index ir does not become negative */
	if (keccak_ctx->nround > 12 + 2 * keccak_ctx->l) {
		goto err;
	}
	if (keccak_ctx->rate <= 0 || keccak_ctx->capacity < 0) {
		goto err;
	}
	if (keccak_ctx->l < 0 || keccak_ctx->l > 7) {
		goto err;
	}

	keccak_init_word_mask(keccak_ctx);
	keccak_init_rho_const(keccak_ctx);
	keccak_init_round_const(keccak_ctx);

	keccak_ctx->A = keccak_ctx->A0_memory;
	keccak_ctx->Aresult = keccak_ctx->A1_memory;
	return SPELL_SUCCESS;

err:
	return SPELL_INVALID_INPUT;
}

/** erase internal state */
static void keccak_erase_state(struct keccak_ctx *restrict k)
{
	for (int32_t i = 0; i < SPELLBIND_KECCAK_NWORD; i++) {
		SPELL_WRITE_ONCE(uint64_t, k->A0_memory[i], 0);
		SPELL_WRITE_ONCE(uint64_t, k->A1_memory[i], 0);
	}
}

static inline void keccak_theta_rho(struct keccak_ctx *restrict k)
{
	uint64_t c[5], d[5];
	for (int32_t x = 0; x < 5; x++) {
		c[x] = 0;
	}

	/* c is parity along y */
	for (int32_t y = 0; y < 5; y++) {
		for (int32_t x = 0; x < 5; x++) {
			c[x] ^= k->A[5 * y + x];
		}
	}

	const int32_t word_nbits = k->word_nbits;
	if (word_nbits == 64) {
		/* minor optimization: don't need word_mask if entire uint64_t is used */
		for (int32_t x = 0; x < 5; x++) {
			d[x] = c[(x + 4) % 5];
			uint64_t cc = c[(x + 1) % 5];
			/* rotate cc left by 1 */
			d[x] ^= (cc << 1) | (cc >> (8 * sizeof(cc) - 1));
		}
	} else {
		uint64_t word_mask = k->word_mask;
		for (int32_t x = 0; x < 5; x++) {
			d[x] = c[(x + 4) % 5];
			uint64_t cc = c[(x + 1) % 5];
			/* rotate cc left by 1 */
			d[x] ^= ((cc << 1) & word_mask) | (cc >> (word_nbits - 1));
		}
	}

	if (word_nbits == 64) {
		/* minor optimization: don't need word_mask if entire uint64_t is used */
		for (int32_t y = 0; y < 5; y++) {
			for (int32_t x = 0; x < 5; x++) {
				int32_t rot = k->rho_rotate[5 * y + x];
				uint64_t theta = k->A[5 * y + x] ^ d[x];
				/* rotate left by rot */
				k->Aresult[5 * y + x] = (theta << rot)
					| (theta >> ((8 * sizeof(theta) - rot) % (8 * sizeof(theta))));
			}
		}
	} else {
		uint64_t word_mask = k->word_mask;
		for (int32_t y = 0; y < 5; y++) {
			for (int32_t x = 0; x < 5; x++) {
				int32_t rot = k->rho_rotate[5 * y + x];
				int32_t anti_rot = k->rho_anti_rotate[5 * y + x];
				uint64_t theta = k->A[5 * y + x] ^ d[x];
				/* rotate left by rot */
				k->Aresult[5 * y + x] = ((theta << rot) & word_mask)
					| (theta >> anti_rot);
			}
		}
	}

	keccak_swapA(k);
}

static inline void keccak_pi(struct keccak_ctx *restrict k)
{

	for (int32_t y = 0; y < 5; y++) {
		for (int32_t x = 0; x < 5; x++) {
			k->Aresult[5 * y + x] = k->A[5 * x + ((x + 3 * y) % 5)];
		}
	}

	keccak_swapA(k);
}

static inline void keccak_chi(struct keccak_ctx *restrict k)
{
	for (int32_t y = 0; y < 5; y++) {
		for (int32_t x = 0; x < 5; x++) {
			k->Aresult[5 * y + x] = k->A[5 * y + x]
				^ ((~k->A[5 * y + ((x + 1) % 5)])
					& k->A[5 * y + ((x + 2) % 5)]);
		}
	}

	keccak_swapA(k);
}

static inline void keccak_iota(struct keccak_ctx *restrict k, int32_t ir)
{
	k->A[0] ^= k->round_const[ir];
}

static inline void keccak_round(struct keccak_ctx *restrict k, int32_t ir)
{
	keccak_theta_rho(k);
	keccak_pi(k);
	keccak_chi(k);
	keccak_iota(k, ir);
}

static void keccak_permute(struct keccak_ctx *restrict k)
{
	int32_t ir_l = 12 + 2 * k->l - k->nround;
	int32_t ir_u = 12 + 2 * k->l;
	for (int32_t ir = ir_l; ir < ir_u; ir++) {
		keccak_round(k, ir);
	}
}

/**
 * Reset internal state in preparation for absorbing
 */
static void keccak_reset_for_absorb(struct keccak_ctx *restrict keccak_ctx)
{
	/* initialize sponge */
	for (int32_t i = 0; i < SPELLBIND_KECCAK_NWORD; i++) {
		keccak_ctx->A[i] = 0;
	}
	keccak_ctx->rate_bit_pos = 0;
}

/**
 * Absorb message into sponge
 */
static void keccak_absorb_message(struct keccak_ctx *restrict keccak_ctx, const uint8_t *message, uint64_t message_nbytes)
{
	/* truncate on integer overflow */
	if (message_nbytes > UINT64_MAX / 8) {
		message_nbytes = UINT64_MAX / 8;
	}
	const uint64_t message_nbits = 8 * message_nbytes;
	const uint64_t rate_nbytes = keccak_ctx->rate / 8;

	/* absorb input */
	uint64_t byte_pos = keccak_ctx->rate_bit_pos / 8;
	for (uint64_t i = 0; i < message_nbytes; i++) {
		keccak_ctx->A[byte_pos / 8] ^= ((uint64_t)message[i]) << (8 * (byte_pos % 8));

		byte_pos++;
		if (byte_pos == rate_nbytes) {
			byte_pos = 0;
			keccak_permute(keccak_ctx);
		}
	}

	keccak_ctx->rate_bit_pos = (keccak_ctx->rate_bit_pos + message_nbits) % keccak_ctx->rate;
}

/**
 * Apply message padding assuming padding nbits is divisible by 8.
 * There are 2 possibilities: first where we only require one full byte of
 * padding. Second where we need multiple bytes to pad. These correspond to
 * using SPELLBIND_SHA3_PAD_CONST0 or SPELLBIND_SHA3_PAD_CONST1
 *
 * As an example, SHA-3 padding possibilities as bit strings where || denotes
 * concat and * denotes zero or more:
 *
 * message || 01100001
 * message || 01100000 || 00000000* || 00000001
 *
 * Note that bit string is reverse of integer base 2 string so in decimal
 *
 * 01100001 -> 134
 * 01100000 -> 6
 * 00000001 -> 128
 */
static void keccak_pad(struct keccak_ctx *restrict keccak_ctx)
{
	const uint64_t pad_nbytes = (keccak_ctx->rate - keccak_ctx->rate_bit_pos) / 8;

	uint64_t byte_pos = keccak_ctx->rate_bit_pos / 8;
	if (pad_nbytes == 1) {
		keccak_ctx->A[byte_pos / 8] ^= ((uint64_t)SPELLBIND_SHA3_PAD_CONST0) << (8 * (byte_pos % 8));
	} else {
		keccak_ctx->A[byte_pos / 8] ^= ((uint64_t)SPELLBIND_SHA3_PAD_CONST1) << (8 * (byte_pos % 8));
		byte_pos++;

		/* zeros */
		for (uint64_t i = 0; i < pad_nbytes - 2; i++) {
			byte_pos++;
		}

		keccak_ctx->A[byte_pos / 8] ^= (uint64_t)128 << (8 * (byte_pos % 8));
	}
	keccak_permute(keccak_ctx);
}

/**
 * output bytes of hash; output must be prealloced and large enough to
 * hold hash (keccak_ctx->out_nbits)
 */
static void keccak_squeeze_output(uint8_t *output, struct keccak_ctx *keccak_ctx)
{
	const uint64_t bytes_per_chunk = keccak_ctx->rate / 8;
	const uint64_t out_nbytes = keccak_ctx->out_nbits / 8;

	uint64_t byte = 0;
	for (uint64_t i = 0; i < out_nbytes; i++) {
		output[i] = keccak_ctx->A[byte / 8] >> (8 * (byte % 8));

		byte++;
		if (byte == bytes_per_chunk && i != out_nbytes - 1) {
			byte = 0;
			keccak_permute(keccak_ctx);
		}
	}
}

static enum SPELL_RET sha3_224_init(struct keccak_ctx *restrict keccak_ctx)
{
	return keccak_init(keccak_ctx, 1600, 24, 448, 224);
}

static enum SPELL_RET sha3_256_init(struct keccak_ctx *restrict keccak_ctx)
{
	return keccak_init(keccak_ctx, 1600, 24, 512, 256);
}

static enum SPELL_RET sha3_384_init(struct keccak_ctx *restrict keccak_ctx)
{
	return keccak_init(keccak_ctx, 1600, 24, 768, 384);
}

static enum SPELL_RET sha3_512_init(struct keccak_ctx *restrict keccak_ctx)
{
	return keccak_init(keccak_ctx, 1600, 24, 1024, 512);
}

/**
 * Perform SHA-3 on a message, where keccak_ctx is pre-initialized.
 *
 * @param output must be large enough to hold non-null terminated output
 * @param keccak_ctx must be inited with one of the sha3 init functions (eg sha3_256_init())
 * @param message a sequences of bytes = 8 bits
 * @param message_nbytes length of message in bytes. Message is truncated if
 * this is too big.
 *
 * @return 0 on success, -1 on invalid setup of k
 */
static enum SPELL_RET sha3(uint8_t *output, struct keccak_ctx *restrict keccak_ctx,
	const uint8_t *message, uint64_t message_nbytes)
{
	/* invalid parameters, not encountered if keccak_ctx was initialized using a sha3 initializer */
	if (keccak_ctx->b != 1600 || keccak_ctx->nround != 24) {
		goto err;
	}
	if (keccak_ctx->word_nbits != 64 || keccak_ctx->l != 6) {
		goto err;
	}
	if (keccak_ctx->capacity != 448
	 && keccak_ctx->capacity != 512
	 && keccak_ctx->capacity != 768
	 && keccak_ctx->capacity != 1024) {
		goto err;
	}
	if (keccak_ctx->rate != 1600 - 448
	 && keccak_ctx->rate != 1600 - 512
	 && keccak_ctx->rate != 1600 - 768
	 && keccak_ctx->rate != 1600 - 1024) {
		goto err;
	}
	if (keccak_ctx->out_nbits != 224
	 && keccak_ctx->out_nbits != 256
	 && keccak_ctx->out_nbits != 384
	 && keccak_ctx->out_nbits != 512) {
		goto err;
	}

	keccak_reset_for_absorb(keccak_ctx);
	keccak_absorb_message(keccak_ctx, message, message_nbytes);
	keccak_pad(keccak_ctx);
	keccak_squeeze_output(output, keccak_ctx);

	return SPELL_SUCCESS;

err:
	return SPELL_INVALID_INPUT;
}

#endif /* SPELLBIND_SHA3_H */
