/**
 * @file
 * @brief Number theory operations
 *
 * The Chinese Remainder Theorem and Montgomery form are used when applicable
 * to optimize modular arithmetic
 *
 * https://en.wikipedia.org/wiki/Chinese_remainder_theorem
 * https://en.wikipedia.org/wiki/Montgomery_modular_multiplication
 */

#include "spellbind.h"
#include "big.h"
#include "quirky_rng.h"
#include <stdio.h>

/**
 * Euclidean algorithm on inputs a, b
 *
 * gcd(|a|, |b|) = a_coeff * |a| + b_coeff * |b|
 *
 * Outputs can be null pointers
 */
enum SPELL_RET z_euclid_alg(
	struct big *const gcd, struct big *const a_coeff, struct big *const b_coeff,
	const struct big *a, const struct big *b)
{
	enum SPELL_RET retval = SPELL_SUCCESS;
	struct big *q, *scratch, *tmp;
	struct big *r0, *r1, *r2;
	struct big *s0, *s1, *s2;
	struct big *t0, *t1, *t2;
	BIG_ALLOC(q, retval, err_alloc_q);
	BIG_ALLOC(scratch, retval, err_alloc_scratch);
	BIG_ALLOC(r0, retval, err_alloc_r0);
	BIG_ALLOC(r1, retval, err_alloc_r1);
	BIG_ALLOC(r2, retval, err_alloc_r2);
	BIG_ALLOC(s0, retval, err_alloc_s0);
	BIG_ALLOC(s1, retval, err_alloc_s1);
	BIG_ALLOC(s2, retval, err_alloc_s2);
	BIG_ALLOC(t0, retval, err_alloc_t0);
	BIG_ALLOC(t1, retval, err_alloc_t1);
	BIG_ALLOC(t2, retval, err_alloc_t2);

	SPELL(big_copy(r0, a), retval, out);
	SPELL(big_copy(r1, b), retval, out);
	r0->neg = false;
	r1->neg = false;

	if (a_coeff != NULL || b_coeff != NULL) {
		SPELL(big_setone(s0), retval, out);
		SPELL(big_setzero(s1), retval, out);
		SPELL(big_setzero(t0), retval, out);
		SPELL(big_setone(t1), retval, out);
	}

	do {
		/* r0 = q * r1 + r2 */
		if (a_coeff != NULL || b_coeff != NULL) {
			SPELL(big_abs_div(q, r2, r0, r1), retval, out);
		} else {
			SPELL(big_abs_div(NULL, r2, r0, r1), retval, out);
		}

		if (big_eqzero(r2)) {
			break;
		}

		tmp = r0;
		r0 = r1;
		r1 = r2;
		r2 = tmp;

		/* s2 = s0 - q * s1 */
		/* t2 = t0 - q * t1 */
		if (a_coeff != NULL || b_coeff != NULL) {
			SPELL(big_mul_restrict(scratch, q, s1), retval, out);
			SPELL(big_sub(s2, s0, scratch), retval, out);
			SPELL(big_mul_restrict(scratch, q, t1), retval, out);
			SPELL(big_sub(t2, t0, scratch), retval, out);

			tmp = s0;
			s0 = s1;
			s1 = s2;
			s2 = tmp;

			tmp = t0;
			t0 = t1;
			t1 = t2;
			t2 = tmp;
		}
	} while (1);

	if (gcd != NULL) {
		SPELL(big_copy(gcd, r1), retval, out);
	}
	if (a_coeff != NULL) {
		SPELL(big_copy(a_coeff, s1), retval, out);
	}
	if (b_coeff != NULL) {
		SPELL(big_copy(b_coeff, t1), retval, out);
	}

out:
	BIG_FREE(t2, err_alloc_t2);
	BIG_FREE(t1, err_alloc_t1);
	BIG_FREE(t0, err_alloc_t0);
	BIG_FREE(s2, err_alloc_s2);
	BIG_FREE(s1, err_alloc_s1);
	BIG_FREE(s0, err_alloc_s0);
	BIG_FREE(r2, err_alloc_r2);
	BIG_FREE(r1, err_alloc_r1);
	BIG_FREE(r0, err_alloc_r0);
	BIG_FREE(scratch, err_alloc_scratch);
	BIG_FREE(q, err_alloc_q);
	return retval;
}

/** result = a (mod |modulus|) */
enum SPELL_RET z_mod(struct big *result, const struct big *a, const struct big *modulus)
{
	enum SPELL_RET retval = SPELL_SUCCESS;
	bool aneg = a->neg;
	SPELL(big_abs_div(NULL, result, a, modulus), retval, out);
	if (aneg) {
		SPELL(big_abs_sub(result, modulus, result), retval, out);
	}
out:
	return retval;
}

/** result = |b|^-1 (mod |modulus|) or 0 if gcd(b, modulus) != 1 */
enum SPELL_RET z_modinv(struct big *result, const struct big *b, const struct big *modulus)
{
	enum SPELL_RET retval = SPELL_SUCCESS;
	struct big *gcd;
	BIG_ALLOC(gcd, retval, err_gcd);

	SPELL(z_euclid_alg(gcd, NULL, result, modulus, b), retval, out);

	/* set result to 0 if gcd != 1 */
	if (!big_eqone(gcd)) {
		retval = SPELL_NO_MOD_INVERSE;
		goto out;
	}

	SPELL(z_mod(result, result, modulus), retval, out);
out:
	BIG_FREE(gcd, err_gcd);
	return retval;
}

/**
 * precomputed values for Chinese Remainder Theorem
 *
 * modulus = 2^pow2_factor_exp * odd
 *
 * x = a (mod 2^pow2_factor_exp)
 * x = b (mod odd)
 * x = a * pow2_multiplier + b * odd_multiplier
 */
struct crt {
	int64_t pow2_factor_exp;
	struct big *modulus;
	struct big *odd;
	struct big *pow2;
	struct big *odd_multiplier;
	struct big *pow2_multiplier;
};

static struct crt *crt_alloc(void)
{
	struct crt *c = malloc(sizeof(*c));
	if (c == NULL) {
		goto err_c;
	}

	c->modulus = big_alloc();
	if (c->modulus == NULL) {
		goto err_modulus;
	}
	c->odd = big_alloc();
	if (c->odd == NULL) {
		goto err_odd;
	}
	c->pow2 = big_alloc();
	if (c->pow2 == NULL) {
		goto err_pow2;
	}
	c->odd_multiplier = big_alloc();
	if (c->odd_multiplier == NULL) {
		goto err_odd_multiplier;
	}
	c->pow2_multiplier = big_alloc();
	if (c->pow2_multiplier == NULL) {
		goto err_pow2_multiplier;
	}

	return c;

	big_free(c->pow2_multiplier);
err_pow2_multiplier:
	big_free(c->odd_multiplier);
err_odd_multiplier:
	big_free(c->pow2);
err_pow2:
	big_free(c->odd);
err_odd:
	big_free(c->modulus);
err_modulus:
	free(c);
err_c:
	return NULL;
}

static void crt_free(struct crt *c)
{
	big_free(c->pow2_multiplier);
	big_free(c->odd_multiplier);
	big_free(c->pow2);
	big_free(c->odd);
	big_free(c->modulus);
	free(c);
}

#define CRT_ALLOC(c, retval, goto_label) SPELL_ALLOC(crt_alloc, c, retval, goto_label)
#define CRT_FREE(c, goto_label) SPELL_FREE(crt_free, c, goto_label)

static enum SPELL_RET crt_init(struct crt *c, const struct big *modulus)
{
	if (modulus->neg || modulus->len == 0) {
		return SPELL_INVALID_INPUT;
	}

	enum SPELL_RET retval = SPELL_SUCCESS;

	SPELL(big_copy(c->modulus, modulus), retval, out);
	c->modulus->neg = false;

	c->pow2_factor_exp = big_pow2_factor_exp(c->modulus);
	SPELL(big_rshift(c->odd, c->modulus, c->pow2_factor_exp), retval, out);

	SPELL(big_setpow2(c->pow2, c->pow2_factor_exp), retval, out);

	SPELL(z_euclid_alg(NULL, c->pow2_multiplier, c->odd_multiplier, c->odd, c->pow2), retval, out);
	SPELL(big_mul_unrestricted(c->pow2_multiplier, c->pow2_multiplier, c->odd), retval, out);
	SPELL(big_mul_unrestricted(c->odd_multiplier, c->odd_multiplier, c->pow2), retval, out);

out:
	return retval;
}

/**
 * Inverse of crt_combine()
 *
 * mod_odd = a (mod c->odd)
 * mod_pow2 = a (mod 2^c->pow2_factor_exp)
 */
static enum SPELL_RET crt_split(struct big *mod_odd, struct big *mod_pow2, const struct big *a, const struct crt *restrict c)
{
	enum SPELL_RET retval = SPELL_SUCCESS;
	SPELL(z_mod(mod_odd, a, c->odd), retval, out);
	SPELL(z_mod(mod_pow2, a, c->pow2), retval, out);
out:
	return retval;
}

/**
 * Inverse of crt_split()
 *
 * a = mod_odd * c->odd_multiplier + mod_pow2 * c->pow2_multiplier (mod c->modulus)
 *
 * so that
 *
 * mod_odd = a (mod c->odd)
 * mod_pow2 = a (mod 2^c->pow2_factor_exp)
 */
static enum SPELL_RET crt_combine(struct big *a, struct big *mod_odd, const struct big *mod_pow2, const struct crt *restrict c)
{
	enum SPELL_RET retval = SPELL_SUCCESS;
	struct big *restrict part1, *restrict part2;
	BIG_ALLOC(part1, retval, err_part1);
	BIG_ALLOC(part2, retval, err_part2);

	SPELL(big_mul_restrict(part1, mod_odd, c->odd_multiplier), retval, out);
	SPELL(big_mul_restrict(part2, mod_pow2, c->pow2_multiplier), retval, out);
	SPELL(big_add(a, part1, part2), retval, out);
	SPELL(z_mod(a, a, c->modulus), retval, out);
out:
	BIG_FREE(part2, err_part2);
	BIG_FREE(part1, err_part1);
	return retval;
}

/** precomputed values for montgomery modular arithmetic */
struct montgomery {
	/** R = 2^(BIG_XBITS * len) */
	int64_t len;
	struct big *modulus;
	struct big *Rone;
	struct big *Rneg_one;
	struct big *Rsquared;
	struct big *neg_ninv;

	struct big *redc_scratch0;
	struct big *redc_scratch1;

	struct big *toR_scratch;
	struct big *mul_scratch;
	struct big *pow_scratch;
};

/** modulus must be odd */
static struct montgomery *montgomery_alloc(void)
{
	struct montgomery *m = malloc(sizeof(*m));
	if (m == NULL) {
		goto err_m;
	}

	m->modulus = big_alloc();
	if (m->modulus == NULL) {
		goto err_modulus;
	}
	m->Rone = big_alloc();
	if (m->Rone == NULL) {
		goto err_Rone;
	}
	m->Rneg_one = big_alloc();
	if (m->Rneg_one == NULL) {
		goto err_Rneg_one;
	}
	m->Rsquared = big_alloc();
	if (m->Rsquared == NULL) {
		goto err_Rsquared;
	}
	m->neg_ninv = big_alloc();
	if (m->neg_ninv == NULL) {
		goto err_neg_ninv;
	}
	m->redc_scratch0 = big_alloc();
	if (m->redc_scratch0 == NULL) {
		goto err_scratch0;
	}
	m->redc_scratch1 = big_alloc();
	if (m->redc_scratch1 == NULL) {
		goto err_scratch1;
	}
	m->toR_scratch = big_alloc();
	if (m->toR_scratch == NULL) {
		goto err_toR_scratch;
	}
	m->mul_scratch = big_alloc();
	if (m->mul_scratch == NULL) {
		goto err_mul_scratch;
	}
	m->pow_scratch = big_alloc();
	if (m->pow_scratch == NULL) {
		goto err_pow_scratch;
	}

	return m;

	big_free(m->pow_scratch);
err_pow_scratch:
	big_free(m->mul_scratch);
err_mul_scratch:
	big_free(m->toR_scratch);
err_toR_scratch:
	big_free(m->redc_scratch1);
err_scratch1:
	big_free(m->redc_scratch0);
err_scratch0:
	big_free(m->neg_ninv);
err_neg_ninv:
	big_free(m->Rsquared);
err_Rsquared:
	big_free(m->Rneg_one);
err_Rneg_one:
	big_free(m->Rone);
err_Rone:
	big_free(m->modulus);
err_modulus:
	free(m);
err_m:
	return NULL;
}

static void montgomery_free(struct montgomery *m)
{
	big_free(m->pow_scratch);
	big_free(m->mul_scratch);
	big_free(m->toR_scratch);
	big_free(m->redc_scratch1);
	big_free(m->redc_scratch0);
	big_free(m->neg_ninv);
	big_free(m->Rsquared);
	big_free(m->Rneg_one);
	big_free(m->Rone);
	big_free(m->modulus);
	free(m);
}

#define MONTGOMERY_ALLOC(m, retval, goto_label) SPELL_ALLOC(montgomery_alloc, m, retval, goto_label)
#define MONTGOMERY_FREE(m, goto_label) SPELL_FREE(montgomery_free, m, goto_label)

static enum SPELL_RET montgomery_init(struct montgomery *m, const struct big *modulus)
{
	if (big_is_even(modulus)) {
		return SPELL_INVALID_INPUT;
	}

	enum SPELL_RET retval = SPELL_SUCCESS;

	SPELL(big_copy(m->modulus, modulus), retval, out);
	m->modulus->neg = false;
	m->len = m->modulus->len;

	/* R = 2^(len * BIG_XBITS) */
	SPELL(big_setpow2(m->Rone, m->len * BIG_XBITS), retval, out);

	/* neg_ninv = -modulus^-1 (mod R) */
	SPELL(z_euclid_alg(NULL, NULL, m->neg_ninv, m->Rone, m->modulus), retval, out);
	big_negate(m->neg_ninv);
	SPELL(z_mod(m->neg_ninv, m->neg_ninv, m->Rone), retval, out);

	/* R (mod m->modulus) */
	SPELL(big_abs_div(NULL, m->Rone, m->Rone, m->modulus), retval, out);

	/* -R (mod m->modulus) */
	SPELL(big_sub(m->Rneg_one, m->modulus, m->Rone), retval, out);

	/* R^2 (mod m->modulus) */
	SPELL(big_setpow2(m->Rsquared, 2 * m->len * BIG_XBITS), retval, out);
	SPELL(big_abs_div(NULL, m->Rsquared, m->Rsquared, m->modulus), retval, out);

out:
	return retval;
}

/** result = Ra (mod 2^(m->len * BIG_XBITS)) */
static enum SPELL_RET montgomery_modR(struct big *result, const struct big *Ra, const struct montgomery *restrict m)
{
	enum SPELL_RET retval = SPELL_SUCCESS;
	int64_t result_len = uint64_min(m->len, Ra->len);
	SPELL(big_setlen(result, result_len), retval, out);
	result->neg = false;
	for (int64_t i = 0; i < result_len; i++) {
		result->x[i] = Ra->x[i];
	}
	big_fixlenzero(result);
out:
	return retval;
}

/** result = Ra >> (m->len * BIG_XBITS) (mod m->modulus) */
static enum SPELL_RET montgomery_shiftR(struct big *result, const struct big *Ra, const struct montgomery *restrict m)
{
	int64_t result_len = Ra->len - m->len;
	if (result_len <= 0) {
		return big_setzero(result);
	}

	enum SPELL_RET retval = SPELL_SUCCESS;
	SPELL(big_setlen(result, result_len), retval, out);
	result->neg = false;
	for (int64_t i = 0; i < result_len; i++) {
		result->x[i] = Ra->x[i + m->len];
	}
out:
	return retval;
}

/** result = Ra / 2^(m->len * BIG_XBITS) (mod m->modulus) */
static enum SPELL_RET montgomery_redc(struct big *result, const struct big *Ra, const struct montgomery *restrict m)
{
	enum SPELL_RET retval = SPELL_SUCCESS;
	/* redc_scratch1 = (Ra (mod R)) * neg_ninv (mod R) */
	SPELL(montgomery_modR(m->redc_scratch0, Ra, m), retval, out);
	SPELL(big_mul_restrict(m->redc_scratch1, m->redc_scratch0, m->neg_ninv), retval, out);
	SPELL(montgomery_modR(m->redc_scratch1, m->redc_scratch1, m), retval, out);

	/* result = (Ra + redc_scratch1 * modulus) / R */
	SPELL(big_mul_restrict(m->redc_scratch0, m->redc_scratch1, m->modulus), retval, out);
	SPELL(big_abs_add(m->redc_scratch0, m->redc_scratch0, Ra), retval, out);
	SPELL(montgomery_shiftR(result, m->redc_scratch0, m), retval, out);

	if (big_abs_gteq(result, m->modulus)) {
		SPELL(big_sub(result, result, m->modulus), retval, out);
	} else {
		/* anti-timing attack */
		SPELL(big_sub(m->redc_scratch0, result, m->modulus), retval, out);
	}
out:
	return retval;
}

/** convert a to montgomery form */
static enum SPELL_RET montgomery_toR(struct big *Ra, const struct big *a, const struct montgomery *restrict m)
{
	enum SPELL_RET retval = SPELL_SUCCESS;
	SPELL(big_mul_restrict(m->toR_scratch, a, m->Rsquared), retval, out);
	SPELL(montgomery_redc(Ra, m->toR_scratch, m), retval, out);
out:
	return retval;
}

/** montgomery multiplication */
static enum SPELL_RET montgomery_mul(struct big *result, const struct big *Ra, const struct big *Rb, const struct montgomery *restrict m)
{
	enum SPELL_RET retval = SPELL_SUCCESS;
	SPELL(big_mul_restrict(m->mul_scratch, Ra, Rb), retval, out);
	SPELL(montgomery_redc(result, m->mul_scratch, m), retval, out);
out:
	return retval;
}

/** result Ra^exponent (mod m->modulo) */
static enum SPELL_RET montgomery_pow(struct big *result, const struct big *Ra, const struct big *exponent, const struct montgomery *restrict m)
{
	enum SPELL_RET retval = SPELL_SUCCESS;

	SPELL(big_copy(m->pow_scratch, Ra), retval, out);
	SPELL(big_copy(result, m->Rone), retval, out);

	int64_t ebits = big_nbits(exponent);
	for (int64_t i = ebits - 1; i >= 0; i--) {
		const uint64_t bit = (exponent->x[i / BIG_XBITS] >> (i % BIG_XBITS)) & 1;
		if (bit == 0) {
			SPELL(montgomery_mul(m->pow_scratch, result, m->pow_scratch, m), retval, out);
			SPELL(montgomery_mul(result, result, result, m), retval, out);
		} else {
			SPELL(montgomery_mul(result, result, m->pow_scratch, m), retval, out);
			SPELL(montgomery_mul(m->pow_scratch, m->pow_scratch, m->pow_scratch, m), retval, out);
		}
	}
out:
	return retval;
}

/** result = a^|exponent| (mod |modulus|) */
enum SPELL_RET z_crt_modpow(struct big *result, const struct big *a, const struct big *exponent, const struct big *modulus)
{
	if (modulus->len == 0) {
		return SPELL_INVALID_INPUT;
	}

	if (big_is_even(modulus)) {
		/* Chinese Remainder Theorem to split modulus = 2^d * odd */
		enum SPELL_RET retval = SPELL_SUCCESS;
		struct crt *c;
		struct montgomery *m;
		struct big *mod_pow2;
		CRT_ALLOC(c, retval, err_even_c);
		MONTGOMERY_ALLOC(m, retval, err_even_m);
		BIG_ALLOC(mod_pow2, retval, err_even_mod_pow2);

		SPELL(crt_init(c, modulus), retval, out_even);
		SPELL(montgomery_init(m, c->odd), retval, out_even);
		crt_split(result, mod_pow2, a, c);

		/* odd part done with montgomery arithmetic */
		SPELL(montgomery_toR(result, result, m), retval, out_even);
		SPELL(montgomery_pow(result, result, exponent, m), retval, out_even);
		SPELL(montgomery_redc(result, result, m), retval, out_even);

		/* montgomery ladder for even part */
		SPELL(big_setone(m->pow_scratch), retval, out_even);
		int64_t ebits = big_nbits(exponent);
		for (int64_t i = ebits - 1; i >= 0; i--) {
			const uint64_t bit = (exponent->x[i / BIG_XBITS] >> (i % BIG_XBITS)) & 1;
			if (bit == 0) {
				SPELL(big_mul_unrestricted(mod_pow2, m->pow_scratch, mod_pow2), retval, out_even);
				SPELL(big_modpow2(mod_pow2, mod_pow2, c->pow2_factor_exp), retval, out_even);

				SPELL(big_mul_unrestricted(m->pow_scratch, m->pow_scratch, m->pow_scratch), retval, out_even);
				SPELL(big_modpow2(m->pow_scratch, m->pow_scratch, c->pow2_factor_exp), retval, out_even);
			} else {
				SPELL(big_mul_unrestricted(m->pow_scratch, m->pow_scratch, mod_pow2), retval, out_even);
				SPELL(big_modpow2(m->pow_scratch, m->pow_scratch, c->pow2_factor_exp), retval, out_even);

				SPELL(big_mul_unrestricted(mod_pow2, mod_pow2, mod_pow2), retval, out_even);
				SPELL(big_modpow2(mod_pow2, mod_pow2, c->pow2_factor_exp), retval, out_even);
			}
		}

		crt_combine(result, result, m->pow_scratch, c);
out_even:
		BIG_FREE(mod_pow2, err_even_mod_pow2);
		MONTGOMERY_FREE(m, err_even_m);
		CRT_FREE(c, err_even_c);
		return retval;
	} else {
		enum SPELL_RET retval = SPELL_SUCCESS;
		struct montgomery *m;
		MONTGOMERY_ALLOC(m, retval, err_odd_m);
		SPELL(montgomery_init(m, modulus), retval, out_odd);
		SPELL(montgomery_toR(result, a, m), retval, out_odd);
		SPELL(montgomery_pow(result, result, exponent, m), retval, out_odd);
		SPELL(montgomery_redc(result, result, m), retval, out_odd);
out_odd:
		MONTGOMERY_FREE(m, err_odd_m);
		return retval;
	}
}

/** probabilistic prime test */
static enum SPELL_RET z_miller_rabin_montgomery(bool *restrict is_prime, const struct big *restrict odd,
	struct montgomery *restrict m, struct big *restrict d, struct big *restrict Rad,
	const uint32_t nround, struct quirky_rng *rng)
{
	if (odd->neg || big_is_even(odd)) {
		return SPELL_INVALID_INPUT;
	}

	enum SPELL_RET retval = SPELL_SUCCESS;
	SPELL(montgomery_init(m, odd), retval, out);

	/* compute odd - 1 and temporarily store in d */
	SPELL(big_setone(d), retval, out);
	SPELL(big_sub(d, odd, d), retval, out);
	if (big_eqzero(d)) {
		retval = SPELL_INVALID_INPUT;
		goto out;
	}

	/* odd - 1 = 2^s d where d is odd */
	int64_t s = big_pow2_factor_exp(d);
	SPELL(big_rshift(d, d, s), retval, out);

	for (uint32_t r = 0; r < nround; r++) {
		/* choose witness to be around 2^(log_2(odd)/2 - 1) + 1 or 1 if odd == 3*/
		quirky_rng_rand_big(Rad, big_nbits(odd) / 2 - 1, rng);
		Rad->x[0] |= 1;
		SPELL(montgomery_toR(Rad, Rad, m), retval, out);

		/* check Rad^d == 1 or -1 */
		SPELL(montgomery_pow(Rad, Rad, d, m), retval, out);
		if (big_eq(Rad, m->Rone) || big_eq(Rad, m->Rneg_one)) {
			continue;
		}

		/* check Rad^(d * 2^i) == -1 by successive squaring */
		for (int64_t i = 1; i < s; i++) {
			SPELL(montgomery_mul(Rad, Rad, Rad, m), retval, out);
			if (big_eq(Rad, m->Rneg_one)) {
				continue;
			}
			if (big_eq(Rad, m->Rone)) {
				*is_prime = false;
				goto out;
			}
		}

		*is_prime = false;
		goto out;
	}
	*is_prime = true;
out:
	return retval;
}

/** used to speedup big prime finding */
#define Z_NSMALLPRIMES 4096

static void z_find_small_primes(uint64_t *restrict primes)
{
	if (Z_NSMALLPRIMES < 1) {
		return;
	}

	uint64_t nfound = 1;
	primes[0] = 2;
	for (uint64_t n = 3; nfound < Z_NSMALLPRIMES; n += 2) {
		bool is_prime = true;
		for (uint64_t i = 0; i < nfound; i++) {
			if (n % primes[i] == 0) {
				is_prime = false;
				break;
			}
		}
		if (is_prime) {
			primes[nfound++] = n;
		}
	}
}

/** mod_primes[i] = b % primes[i] */
static enum SPELL_RET z_big_mod_small_primes(uint64_t *restrict mod_primes, const struct big *restrict b, const uint64_t *restrict primes)
{
	enum SPELL_RET retval = SPELL_SUCCESS;
	struct big *restrict prime, *restrict remainder;
	BIG_ALLOC(prime, retval, err_prime);
	BIG_ALLOC(remainder, retval, err_remainder);

	for (int64_t i = 0; i < Z_NSMALLPRIMES; i++) {
		SPELL(big_from_uint(prime, primes[i]), retval, out);
		SPELL(big_abs_div(NULL, remainder, b, prime), retval, out);
		big_to_uint(&mod_primes[i], remainder);
	}

out:
	BIG_FREE(remainder, err_remainder);
	BIG_FREE(prime, err_prime);
	return retval;
}

static void z_increment_mod_primes(uint64_t *restrict mod_primes, uint64_t increment, const uint64_t *restrict primes)
{
	for (int64_t i = 0; i < Z_NSMALLPRIMES; i++) {
		mod_primes[i] = (mod_primes[i] + increment) % primes[i];
	}
}

/** number of iterations to thoroughly check prime candidate */
#define MILLER_RABIN_THOROUGH_NITER 20

enum SPELL_RET z_find_prime(struct big *prime, const struct big *start)
{
	/* rng for miller rabin */
	struct quirky_rng rng;
	quirky_rng_init(&rng);

	enum SPELL_RET retval = SPELL_SUCCESS;
	struct big *d, *Rad, *two;
	struct montgomery *m;
	BIG_ALLOC(d, retval, err_d);
	BIG_ALLOC(Rad, retval, err_Rad);
	BIG_ALLOC(two, retval, err_two);
	MONTGOMERY_ALLOC(m, retval, err_m);

	SPELL(big_setpow2(two, 1), retval, out);

	if (big_lt(start, two)) {
		SPELL(big_copy(prime, two), retval, out);
	} else {
		SPELL(big_copy(prime, start), retval, out);
	}

	/* ensure odd */
	prime->x[0] |= 1;

	uint64_t small_primes[Z_NSMALLPRIMES], mod_primes[Z_NSMALLPRIMES];
	z_find_small_primes(small_primes);
	SPELL(z_big_mod_small_primes(mod_primes, prime, small_primes), retval, out);

	bool is_prime;
	for (;;) {
		/* check if divisible by small primes */
		for (int64_t i = 1; i < Z_NSMALLPRIMES; i++) {
			if (mod_primes[i] == 0) {
				goto cont;
			}
		}
		//printf(".");
		//fflush(stdout);

		SPELL(z_miller_rabin_montgomery(&is_prime, prime, m, d, Rad, MILLER_RABIN_THOROUGH_NITER, &rng), retval, out);
		if (is_prime) {
			break;
		}

cont:
		/* prime += 2 */
		SPELL(big_abs_add(prime, prime, two), retval, out);
		z_increment_mod_primes(mod_primes, 2, small_primes);
	}

out:
	//printf("\n");
	MONTGOMERY_FREE(m, err_m);
	BIG_FREE(two, err_two);
	BIG_FREE(Rad, err_Rad);
	BIG_FREE(d, err_d);
	return retval;
}

/* prime = 2 * half + 1 and both prime and half are primes */
enum SPELL_RET z_find_safe_prime(struct big *prime, const struct big *start)
{
	/* rng for miller rabin */
	struct quirky_rng rng;
	quirky_rng_init(&rng);

	enum SPELL_RET retval = SPELL_SUCCESS;
	struct big *d, *Rad, *six, *twelve, *half;
	struct montgomery *m;
	BIG_ALLOC(d, retval, err_d);
	BIG_ALLOC(Rad, retval, err_Rad);
	BIG_ALLOC(six, retval, err_six);
	BIG_ALLOC(twelve, retval, err_twelve);
	BIG_ALLOC(half, retval, err_half);
	MONTGOMERY_ALLOC(m, retval, err_m);

	SPELL(big_from_uint(six, 6), retval, out);
	SPELL(big_from_uint(twelve, 12), retval, out);

	if (big_lt(start, twelve)) {
		SPELL(big_copy(prime, six), retval, out);
	} else {
		SPELL(big_copy(prime, start), retval, out);
	}

	/* safe primes are always == -1 (mod 12) */
	SPELL(z_mod(d, prime, twelve), retval, out);
	SPELL(big_abs_sub(d, twelve, d), retval, out);
	SPELL(big_abs_add(prime, prime, d), retval, out);
	SPELL(big_setone(d), retval, out);
	SPELL(big_abs_sub(prime, prime, d), retval, out);

	/* prime = 2 * half + 1 */
	SPELL(big_rshift(half, prime, 1), retval, out);

	uint64_t small_primes[Z_NSMALLPRIMES], mod_primes[Z_NSMALLPRIMES];
	z_find_small_primes(small_primes);
	SPELL(z_big_mod_small_primes(mod_primes, prime, small_primes), retval, out);

	bool is_prime;
	for (;;) {
		/* check if divisible by small primes */
		for (int64_t i = 1; i < Z_NSMALLPRIMES; i++) {
			/* n is odd and n == 1 (mod q) iff (n - 1) / 2 == 0 (mod q) for odd q > 2 */
			/* so this checks both prime and half for divisibility by small primes */
			if (mod_primes[i] <= 1) {
				goto cont;
			}
		}
		//printf(".");
		//fflush(stdout);

		/* brief check half for prime */
		SPELL(z_miller_rabin_montgomery(&is_prime, half, m, d, Rad, 1, &rng), retval, out);
		if (!is_prime) {
			goto cont;
		}
		//printf("+");
		//fflush(stdout);

		/* half is likely prime already */
		SPELL(z_miller_rabin_montgomery(&is_prime, prime, m, d, Rad, 1, &rng), retval, out);
		if (!is_prime) {
			goto cont;
		}
		//printf("+");
		//fflush(stdout);

		/* thorough half */
		SPELL(z_miller_rabin_montgomery(&is_prime, half, m, d, Rad, MILLER_RABIN_THOROUGH_NITER, &rng), retval, out);
		if (!is_prime) {
			goto cont;
		}

		/* thorough full */
		SPELL(z_miller_rabin_montgomery(&is_prime, prime, m, d, Rad, MILLER_RABIN_THOROUGH_NITER, &rng), retval, out);
		if (is_prime) {
			break;
		}

cont:
		/* half += 6 */
		SPELL(big_abs_add(half, half, six), retval, out);
		/* prime += 12 */
		SPELL(big_abs_add(prime, prime, twelve), retval, out);
		z_increment_mod_primes(mod_primes, 12, small_primes);
	}

out:
	//printf("\n");
	MONTGOMERY_FREE(m, err_m);
	BIG_FREE(half, err_half);
	BIG_FREE(twelve, err_twelve);
	BIG_FREE(six, err_six);
	BIG_FREE(Rad, err_Rad);
	BIG_FREE(d, err_d);
	return retval;
}
