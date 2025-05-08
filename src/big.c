/**
 * @file
 * @brief Arbitrarily big (BIG) signed integers
 *
 * The bits of each integer are stored in an array of ordinary (fixed) precision
 * integers. Each array element stores BIG_XBITS number of bits, which must be
 * strictly less than the element's bit count / 2 to allow for overflow carry.
 *
 * The position of the most significant bit is not considered secret and
 * therefore there are length depedent branches. Attacks that would use this
 * information are mostly mitigated with blinding in modular exponentiation in
 * RSA and Diffie-Hellman.
 */

#include "spellbind.h"
#include "big.h"
#include <stdio.h>
#include <string.h>

struct big *big_alloc(void)
{
	struct big *restrict b = malloc(sizeof(*b));
	if (b == NULL) {
		goto err_b;
	}

	b->neg = false;
	b->len = 0;
	b->cap = BIG_MIN_CAP;

	b->x = malloc(b->cap * sizeof(*b->x));
	if (b->x == NULL) {
		goto err_b_x;
	}

	return b;

	free((void *)b->x);
err_b_x:
	free(b);
err_b:
	return NULL;
}

void big_free(struct big *restrict b)
{
	big_erase(b);
	free((void *)b->x);
	free(b);
}

enum SPELL_RET big_copy(struct big *result, const struct big *a)
{
	enum SPELL_RET retval = SPELL_SUCCESS;

	SPELL(big_setlen(result, a->len), retval, out);
	result->neg = a->neg;

	int64_t alen = a->len;
	for (int64_t i = 0; i < alen; i++) {
		result->x[i] = a->x[i];
	}

out:
	return retval;
}

static inline void big_swp(const struct big *volatile *a, const struct big *volatile *b)
{
	const struct big *volatile tmp;
	tmp = *a;
	*a = *b;
	*b = tmp;
}

static inline void big_decoy_swp(const struct big *volatile *a, const struct big *volatile *b)
{
	const struct big *volatile tmp;
	tmp = *a;
	*a = *a;
	*b = *b;
	(void)tmp;
}

/** a == b */
bool big_eq(const struct big *a, const struct big *b)
{
	if (a->len < b->len) {
		big_swp(&a, &b);
	} else {
		big_decoy_swp(&a, &b);
	}

	volatile bool retval = true;
	volatile bool decoy = true;
	volatile bool decoy2 = true;

	if (a->len != b->len) {
		retval = false;
	} else {
		decoy = false;
	}
	if (a->neg != b->neg) {
		retval = false;
	} else {
		decoy = false;
	}

	int64_t alen = a->len;
	int64_t blen = b->len;
	for (int64_t i = 0; i < blen; i++) {
		if (SPELL_READ_ONCE(uint64_t, a->x[i]) != SPELL_READ_ONCE(uint64_t, b->x[i])) {
			retval = false;
		} else {
			decoy = false;
		}
	}
	for (int64_t i = blen; i < alen; i++) {
		if (SPELL_READ_ONCE(uint64_t, a->x[i]) != SPELL_READ_ONCE(uint64_t, a->x[i])) {
			decoy2 = false;
		} else {
			decoy = false;
		}
	}

	(void)decoy;
	(void)decoy2;
	return retval;
}

/** b == 0 */
bool big_eqzero(const struct big *b)
{
	return b->len == 0 && !b->neg;
}

/** b == 1 */
bool big_eqone(const struct big *b)
{
	if (b->len != 1 || b->neg) {
		return false;
	} else {
		return b->x[0] == 1;
	}
}

bool big_is_even(const struct big *b)
{
	return b->len == 0 || (b->x[0] & 1) == 0;
}

bool big_is_odd(const struct big *b)
{
	return !big_is_even(b);
}

/** |a| < |b| */
bool big_abs_lt(const struct big *a, const struct big *b)
{
	volatile bool retval = false;
	volatile bool done = false;
	volatile bool decoy_retval = false;
	volatile bool decoy_done = false;
	volatile bool decoy_retval2 = false;
	volatile bool decoy_done2 = false;

	if (a->len != b->len) {
		done = true;
		if (a->len < b->len) {
			big_swp(&a, &b);
			retval = true;
		} else {
			big_decoy_swp(&a, &b);
			retval = false;
		}
	} else {
		/* decoy no-op branch */
		decoy_done = true;
		if (a->len < b->len) {
			big_swp(&a, &b);
			decoy_retval = true;
		} else {
			big_decoy_swp(&a, &b);
			decoy_retval = false;
		}
	}

	int64_t alen = a->len;
	int64_t blen = b->len;
	for (int64_t i = alen - 1; i >= blen; i--) {
		/* decoy no-op loop */
		if (!done) {
			if (a->x[i] != a->x[i]) {
				decoy_done = true;
				if (a->x[i] < a->x[i]) {
					decoy_retval = true;
				} else {
					decoy_retval = false;
				}
			} else {
				decoy_done2 = true;
				if (a->x[i] < a->x[i]) {
					decoy_retval2 = true;
				} else {
					decoy_retval2 = false;
				}
			}
		} else {
			if (a->x[i] != a->x[i]) {
				decoy_done2 = true;
				if (a->x[i] < a->x[i]) {
					decoy_retval2 = true;
				} else {
					decoy_retval2 = false;
				}
			} else {
				decoy_done = true;
				if (a->x[i] < a->x[i]) {
					decoy_retval = true;
				} else {
					decoy_retval = false;
				}
			}
		}
	}
	for (int64_t i = blen - 1; i >= 0; i--) {
		if (!done) {
			if (a->x[i] != b->x[i]) {
				done = true;
				if (a->x[i] < b->x[i]) {
					retval = true;
				} else {
					retval = false;
				}
			} else {
				/* decoy no-op branch */
				decoy_done = true;
				if (a->x[i] < b->x[i]) {
					decoy_retval = true;
				} else {
					decoy_retval = false;
				}
			}
		} else {
			/* decoy no-op branch */
			if (a->x[i] != b->x[i]) {
				decoy_done2 = true;
				if (a->x[i] < b->x[i]) {
					decoy_retval2 = true;
				} else {
					decoy_retval2 = false;
				}
			} else {
				decoy_done = true;
				if (a->x[i] < b->x[i]) {
					decoy_retval = true;
				} else {
					decoy_retval = false;
				}
			}
		}
	}

	(void)decoy_retval;
	(void)decoy_retval2;
	(void)decoy_done;
	(void)decoy_done2;
	return retval;
}

/** |a| > |b| */
bool big_abs_gt(const struct big *a, const struct big *b)
{
	volatile bool retval = false;
	volatile bool done = false;
	volatile bool decoy_retval = false;
	volatile bool decoy_done = false;
	volatile bool decoy_retval2 = false;
	volatile bool decoy_done2 = false;

	if (a->len != b->len) {
		done = true;
		if (a->len > b->len) {
			big_decoy_swp(&a, &b);
			retval = true;
		} else {
			big_swp(&a, &b);
			retval = false;
		}
	} else {
		/* decoy no-op branch */
		decoy_done = true;
		if (a->len > b->len) {
			big_decoy_swp(&a, &b);
			decoy_retval = true;
		} else {
			big_swp(&a, &b);
			decoy_retval = false;
		}
	}

	int64_t alen = a->len;
	int64_t blen = b->len;
	for (int64_t i = alen - 1; i >= blen; i--) {
		/* decoy no-op loop */
		if (!done) {
			if (a->x[i] != a->x[i]) {
				decoy_done = true;
				if (a->x[i] > a->x[i]) {
					decoy_retval = true;
				} else {
					decoy_retval = false;
				}
			} else {
				decoy_done2 = true;
				if (a->x[i] > a->x[i]) {
					decoy_retval2 = true;
				} else {
					decoy_retval2 = false;
				}
			}
		} else {
			if (a->x[i] != a->x[i]) {
				decoy_done2 = true;
				if (a->x[i] > a->x[i]) {
					decoy_retval2 = true;
				} else {
					decoy_retval2 = false;
				}
			} else {
				decoy_done = true;
				if (a->x[i] > a->x[i]) {
					decoy_retval = true;
				} else {
					decoy_retval = false;
				}
			}
		}
	}
	for (int64_t i = blen - 1; i >= 0; i--) {
		if (!done) {
			if (a->x[i] != b->x[i]) {
				done = true;
				if (a->x[i] > b->x[i]) {
					retval = true;
				} else {
					retval = false;
				}
			} else {
				/* decoy no-op branch */
				decoy_done = true;
				if (a->x[i] > b->x[i]) {
					decoy_retval = true;
				} else {
					decoy_retval = false;
				}
			}
		} else {
			/* decoy no-op branch */
			if (a->x[i] != b->x[i]) {
				decoy_done2 = true;
				if (a->x[i] > b->x[i]) {
					decoy_retval2 = true;
				} else {
					decoy_retval2 = false;
				}
			} else {
				decoy_done = true;
				if (a->x[i] > b->x[i]) {
					decoy_retval = true;
				} else {
					decoy_retval = false;
				}
			}
		}
	}

	(void)decoy_retval;
	(void)decoy_retval2;
	(void)decoy_done;
	(void)decoy_done2;
	return retval;
}

/** |a| <= |b| */
bool big_abs_lteq(const struct big *a, const struct big *b)
{
	return !big_abs_gt(a, b);
}

/** |a| >= |b| */
bool big_abs_gteq(const struct big *a, const struct big *b)
{
	return !big_abs_lt(a, b);
}

/** a < b */
bool big_lt(const struct big *a, const struct big *b)
{
	volatile bool retval;
	volatile bool same_sgn_retval = a->neg ^ big_abs_lt(a, b);
	volatile bool same_sgn_retval2 = same_sgn_retval;
	if (a->neg != b->neg) {
		if (a->neg) {
			retval = true;
		} else {
			retval = false;
		}
	} else {
		if (a->neg) {
			retval = same_sgn_retval;
		} else {
			retval = same_sgn_retval2;
		}
	}
	return retval;
}

/** a > b */
bool big_gt(const struct big *a, const struct big *b)
{
	volatile bool retval;
	volatile bool same_sgn_retval = a->neg ^ big_abs_gt(a, b);
	volatile bool same_sgn_retval2 = same_sgn_retval;
	if (a->neg != b->neg) {
		if (a->neg) {
			retval = false;
		} else {
			retval = true;
		}
	} else {
		if (a->neg) {
			retval = same_sgn_retval;
		} else {
			retval = same_sgn_retval2;
		}
	}
	return retval;
}

/** a <= b */
bool big_lteq(const struct big *a, const struct big *b)
{
	return !big_gt(a, b);
}

/** a >= b */
bool big_gteq(const struct big *a, const struct big *b)
{
	return !big_lt(a, b);
}

/** a > b ? a : b */
struct big *big_max(struct big *a, struct big *b)
{
	return big_gt(a, b) ? a : b;
}

/** a < b ? a : b */
struct big *big_min(struct big *a, struct big *b)
{
	return big_lt(a, b) ? a : b;
}

/** b = 0 */
enum SPELL_RET big_setzero(struct big *restrict b)
{
	b->neg = false;
	return big_setlen(b, 0);
}

/** b = 1 */
enum SPELL_RET big_setone(struct big *restrict b)
{
	enum SPELL_RET retval = SPELL_SUCCESS;
	SPELL(big_setlen(b, 1), retval, out);
	b->neg = false;
	b->x[0] = 1;
out:
	return retval;
}

/** b = 2^power */
enum SPELL_RET big_setpow2(struct big *restrict b, int64_t power)
{
	if (power < 0) {
		return SPELL_INVALID_INPUT;
	}

	enum SPELL_RET retval = SPELL_SUCCESS;
	int64_t len = power / BIG_XBITS + 1;

	SPELL(big_setlen(b, len), retval, out);
	b->neg = false;

	for (int64_t i = 0; i < len; i++) {
		b->x[i] = 0;
	}
	b->x[power / BIG_XBITS] |= (uint64_t)1 << (power % BIG_XBITS);
out:
	return retval;
}

/** result = b | 2^power */
enum SPELL_RET big_orpow2(struct big *result, const struct big *b, int64_t power)
{
	if (power < 0) {
		return SPELL_INVALID_INPUT;
	}

	enum SPELL_RET retval = SPELL_SUCCESS;
	int64_t min_len = power / BIG_XBITS + 1;

	SPELL(big_copy(result, b), retval, out);
	if (result->len < min_len) {
		SPELL(big_setlen(result, min_len), retval, out);
	}
	result->x[power / BIG_XBITS] |= (uint64_t)1 << (power % BIG_XBITS);
out:
	return retval;
}

/** b = -b */
void big_negate(struct big *restrict b)
{
	b->neg = !b->neg;
}

/** counts number of bits in the big number b: nbits is not considered secret
 * and no protection against timing attacks */
int64_t big_nbits(const struct big *restrict b)
{
	if (b->len == 0) {
		return 0;
	}

	int64_t last = b->len - 1;
	for (int64_t i = BIG_XBITS - 1; i > 0; i--) {
		if (((b->x[last] >> i) & 1) != 0) {
			return last * BIG_XBITS + i + 1;
		}
	}
	return last * BIG_XBITS + 1;
}

/** b = 2^d * c where c is odd, return d */
int64_t big_pow2_factor_exp(const struct big *restrict b)
{
	volatile bool done = false;
	volatile bool decoy_done = false;
	volatile int64_t d = 0;
	volatile int64_t decoy_d = 0;

	for (int64_t i = 0; i < b->len; i++) {
		for (int64_t j = 0; j < BIG_XBITS; j++) {
			if (!done) {
				if (((b->x[i] >> j) & 1) == 1) {
					done = true;
					decoy_d++;
				} else {
					decoy_done = true;
					d++;
				}
			} else {
				/* decoy no-op branch */
				if (((b->x[i] >> j) & 1) == 1) {
					decoy_done = true;
					decoy_d++;
				} else {
					decoy_done = true;
					decoy_d++;
				}
			}
		}
	}
	(void)decoy_d;
	(void)decoy_done;
	return d;
}

/** result = b << s or b >> (-s) if s < 0 */
enum SPELL_RET big_lshift(struct big *result, const struct big *b, int64_t s)
{
	if (s < 0) {
		return big_rshift(result, b, -s);
	}
	if (s == 0) {
		return big_copy(result, b);
	}

	int64_t sub_shift = s % BIG_XBITS;
	int64_t anti_sub_shift = (BIG_XBITS - sub_shift) % BIG_XBITS;
	int64_t super_shift = (s - 1) / BIG_XBITS + 1;
	int64_t blen = b->len;
	int64_t new_len = blen + super_shift;

	enum SPELL_RET retval = SPELL_SUCCESS;
	SPELL(big_setlen(result, new_len), retval, out);
	result->neg = b->neg;

	int64_t i = new_len - 1;
	for (; i >= super_shift; i--) {
		uint64_t x = 0;
		x |= b->x[i - super_shift] >> anti_sub_shift;
		if (i < new_len - 1 && sub_shift > 0) {
			x |= BIG_XMOD_POW2(anti_sub_shift, b->x[i - super_shift + 1]) << sub_shift;
		}
		result->x[i] = x;
	}
	if (sub_shift > 0) {
		result->x[i] = BIG_XMOD_POW2(anti_sub_shift, b->x[0]) << sub_shift;
		i--;
	}
	for (; i >= 0; i--) {
		result->x[i] = 0;
	}

	big_fixlenzero(result);
out:
	return retval;
}

/** result = b >> s or b << (-s) if s < 0 */
enum SPELL_RET big_rshift(struct big *result, const struct big *b, int64_t s)
{
	if (s < 0) {
		return big_lshift(result, b, -s);
	}
	if (s == 0) {
		return big_copy(result, b);
	}

	int64_t sub_shift = s % BIG_XBITS;
	int64_t anti_sub_shift = (BIG_XBITS - sub_shift) % BIG_XBITS;
	int64_t super_shift = s / BIG_XBITS;
	int64_t blen = b->len;
	int64_t new_len = blen - super_shift;
	if (new_len <= 0) {
		return big_setzero(result);
	}

	enum SPELL_RET retval = SPELL_SUCCESS;
	SPELL(big_setlen(result, new_len), retval, out);
	result->neg = b->neg;

	int64_t i = 0;
	for (; i < new_len; i++) {
		uint64_t x = 0;
		x |= b->x[i + super_shift] >> sub_shift;
		if (i < new_len - 1 && sub_shift > 0) {
			x |= BIG_XMOD_POW2(sub_shift, b->x[i + super_shift + 1]) << anti_sub_shift;
		}
		result->x[i] = x;
	}

	big_fixlenzero(result);
out:
	return retval;
}

/** result = sgn(b) * (|b| (mod 2^power)) */
enum SPELL_RET big_modpow2(struct big *result, const struct big *b, int64_t power)
{
	if (power <= 0) {
		return big_setzero(result);
	}

	int64_t orig_len = b->len;
	int64_t new_len = (power - 1) / BIG_XBITS + 1;
	int64_t sub_power = power % BIG_XBITS;

	enum SPELL_RET retval = SPELL_SUCCESS;
	SPELL(big_copy(result, b), retval, out);
	SPELL(big_setlen(result, new_len), retval, out);
	result->neg = b->neg;

	result->x[new_len - 1] = BIG_XMOD_POW2(sub_power, b->x[new_len - 1]);
	SPELL(big_setlen(result, uint64_min(new_len, orig_len)), retval, out);
	big_fixlenzero(result);
out:
	return retval;
}

/** result = ~a and result has same sign as a */
enum SPELL_RET big_not(struct big *result, const struct big *a)
{
	int64_t alen = a->len;

	enum SPELL_RET retval = SPELL_SUCCESS;
	SPELL(big_setlen(result, alen), retval, out);
	result->neg = a->neg;

	for (int64_t i = 0; i < alen; i++) {
		result->x[i] = ~(a->x[i]);
	}

	big_fixlenzero(result);
out:
	return retval;
}

/** result = a & b and result is positive */
enum SPELL_RET big_and(struct big *result, const struct big *a, const struct big *b)
{
	if (a->len < b->len) {
		big_swp(&a, &b);
	} else {
		big_decoy_swp(&a, &b);
	}

	int64_t blen = b->len;

	enum SPELL_RET retval = SPELL_SUCCESS;
	SPELL(big_setlen(result, blen), retval, out);
	result->neg = false;

	for (int64_t i = 0; i < blen; i++) {
		result->x[i] = a->x[i] & b->x[i];
	}

	big_fixlenzero(result);
out:
	return retval;
}

/** result = a | b and result is positive */
enum SPELL_RET big_or(struct big *result, const struct big *a, const struct big *b)
{
	if (a->len < b->len) {
		big_swp(&a, &b);
	} else {
		big_decoy_swp(&a, &b);
	}

	int64_t alen = a->len;
	int64_t blen = b->len;

	enum SPELL_RET retval = SPELL_SUCCESS;
	SPELL(big_setlen(result, alen), retval, out);
	result->neg = false;

	for (int64_t i = 0; i < blen; i++) {
		result->x[i] = a->x[i] | b->x[i];
	}
	for (int64_t i = blen; i < alen; i++) {
		result->x[i] = a->x[i];
	}

	big_fixlenzero(result);
out:
	return retval;
}

/** result = a ^ b and result is positive */
enum SPELL_RET big_xor(struct big *result, const struct big *a, const struct big *b)
{
	if (a->len < b->len) {
		big_swp(&a, &b);
	} else {
		big_decoy_swp(&a, &b);
	}

	int64_t alen = a->len;
	int64_t blen = b->len;

	enum SPELL_RET retval = SPELL_SUCCESS;
	SPELL(big_setlen(result, alen), retval, out);
	result->neg = false;

	for (int64_t i = 0; i < blen; i++) {
		result->x[i] = a->x[i] ^ b->x[i];
	}
	for (int64_t i = blen; i < alen; i++) {
		result->x[i] = a->x[i];
	}

	big_fixlenzero(result);
out:
	return retval;
}

/** result = |a| + |b| */
enum SPELL_RET big_abs_add(struct big *result, const struct big *a, const struct big *b)
{
	if (a->len < b->len) {
		big_swp(&a, &b);
	} else {
		big_decoy_swp(&a, &b);
	}

	int64_t alen = a->len;
	int64_t blen = b->len;

	enum SPELL_RET retval = SPELL_SUCCESS;
	volatile uint64_t sum;
	volatile uint64_t carry = 0;
	SPELL(big_setlen(result, alen + 1), retval, out);
	result->neg = false;

	for (int64_t i = 0; i < blen; i++) {
		sum = carry + a->x[i] + b->x[i];
		carry = BIG_XCARRY(sum);
		result->x[i] = BIG_XNONCARRY(sum);
	}
	for (int64_t i = blen; i < alen; i++) {
		sum = carry + a->x[i];
		carry = BIG_XCARRY(sum);
		result->x[i] = BIG_XNONCARRY(sum);
	}

	result->x[alen] = carry;
	big_fixlenzero(result);
out:
	/* erase secrets */
	sum = 0;
	carry = 0;
	return retval;
}

/** result = |a| - |b| */
enum SPELL_RET big_abs_sub(struct big *result, const struct big *a, const struct big *b)
{
	if (big_abs_lt(a, b)) {
		return SPELL_INVALID_INPUT;
	}

	int64_t alen = a->len;
	int64_t blen = b->len;

	enum SPELL_RET retval = SPELL_SUCCESS;
	volatile uint64_t sub;
	volatile uint64_t borrow = 0;
	SPELL(big_setlen(result, alen), retval, out);
	result->neg = false;

	for (int64_t i = 0; i < blen; i++) {
		sub = b->x[i] + borrow;
		borrow = a->x[i] < sub ? 1 : 0;
		result->x[i] = ((borrow << BIG_XBITS) + a->x[i]) - sub;
	}
	for (int64_t i = blen; i < alen; i++) {
		sub = borrow;
		borrow = a->x[i] < sub ? 1 : 0;
		result->x[i] = ((borrow << BIG_XBITS) + a->x[i]) - sub;
	}

	big_fixlenzero(result);
out:
	/* erase secrets */
	sub = 0;
	borrow = 0;
	return retval;
}

/**
 * quotient = |a| / |b| if quotient != NULL
 * remainder = |a| % |b| if remainder != NULL
 */
enum SPELL_RET big_abs_div(struct big *const quotient, struct big *const remainder,
	const struct big *a, const struct big *divisor)
{
	if (big_eqzero(divisor)) {
		return SPELL_INVALID_INPUT;
	}

	enum SPELL_RET retval = SPELL_SUCCESS;
	/** prevent cache timing by forcing read into decoy */
	volatile uint64_t decoy;
	struct big *qscratch, *decoy_qscratch, *rscratch, *decoy_rscratch, *shifted_divisor;
	BIG_ALLOC(qscratch, retval, err_alloc_qscratch);
	BIG_ALLOC(decoy_qscratch, retval, err_alloc_decoy_qscratch);
	BIG_ALLOC(rscratch, retval, err_alloc_rscratch);
	BIG_ALLOC(decoy_rscratch, retval, err_alloc_decoy_rscratch);
	BIG_ALLOC(shifted_divisor, retval, err_alloc_shifted);

	/* only allocate memory if output is requested for quotient */
	if (quotient != NULL) {
		SPELL(big_setlen(qscratch, a->len), retval, out);
		qscratch->neg = false;
		for (int64_t i = 0; i < qscratch->len; i++) {
			qscratch->x[i] = 0;
		}

		SPELL(big_setlen(decoy_qscratch, a->len), retval, out);
		decoy_qscratch->neg = false;
		for (int64_t i = 0; i < decoy_qscratch->len; i++) {
			decoy_qscratch->x[i] = 0;
		}
	}

	SPELL(big_copy(rscratch, a), retval, out);
	rscratch->neg = false;
	SPELL(big_copy(decoy_rscratch, a), retval, out);
	decoy_rscratch->neg = false;

	/* shift divisor one bit at a time */
	for (int64_t i = big_nbits(a) - big_nbits(divisor); i >= 0; i--) {
		SPELL(big_lshift(shifted_divisor, divisor, i), retval, out);
		shifted_divisor->neg = false;

		/* if remainder >= divisor * 2^i */
		if (big_abs_gteq(rscratch, shifted_divisor)) {
			SPELL(big_copy(decoy_rscratch, rscratch), retval, out);
			decoy = SPELL_READ_ONCE(uint64_t, decoy_rscratch->x[0]);
			SPELL(big_abs_sub(rscratch, decoy_rscratch, shifted_divisor), retval, out);
			decoy = SPELL_READ_ONCE(uint64_t, decoy_rscratch->x[0]);

			if (quotient != NULL) {
				/* prevent cache timing */
				decoy = SPELL_READ_ONCE(uint64_t, decoy_qscratch->x[i / BIG_XBITS]);
				decoy = SPELL_READ_ONCE(uint64_t, qscratch->x[i / BIG_XBITS]);

				((volatile uint64_t *)(qscratch->x))[i / BIG_XBITS] |= (uint64_t)1 << (i % BIG_XBITS);
			}
		} else {
			/* decoy no-op branch */
			SPELL(big_copy(decoy_rscratch, rscratch), retval, out);
			decoy = SPELL_READ_ONCE(uint64_t, decoy_rscratch->x[0]);
			SPELL(big_abs_sub(decoy_rscratch, shifted_divisor, rscratch), retval, out);
			decoy = SPELL_READ_ONCE(uint64_t, decoy_rscratch->x[0]);

			if (quotient != NULL) {
				/* prevent cache timing */
				decoy = SPELL_READ_ONCE(uint64_t, qscratch->x[i / BIG_XBITS]);
				decoy = SPELL_READ_ONCE(uint64_t, decoy_qscratch->x[i / BIG_XBITS]);

				((volatile uint64_t *)(decoy_qscratch->x))[i / BIG_XBITS] |= (uint64_t)1 << (i % BIG_XBITS);
			}
		}
	}

	if (quotient != NULL) {
		big_fixlenzero(qscratch);
		SPELL(big_copy(quotient, qscratch), retval, out);
	}
	if (remainder != NULL) {
		SPELL(big_copy(remainder, rscratch), retval, out);
	}

out:
	(void)decoy;
	BIG_FREE(shifted_divisor, err_alloc_shifted);
	BIG_FREE(decoy_rscratch, err_alloc_decoy_rscratch);
	BIG_FREE(rscratch, err_alloc_rscratch);
	BIG_FREE(decoy_qscratch, err_alloc_decoy_qscratch);
	BIG_FREE(qscratch, err_alloc_qscratch);
	return retval;
}

/** result = a + b */
enum SPELL_RET big_add(struct big *result, const struct big *a, const struct big *b)
{
	enum SPELL_RET retval = SPELL_SUCCESS;
	volatile bool decoy_neg;

	if (a->neg == b->neg) {
		if (big_abs_lt(a, b)) {
			/* decoy */
			big_swp(&a, &b);
		} else {
			big_decoy_swp(&a, &b);
		}

		retval = big_abs_add(result, a, b);
		if (!big_eqzero(result)) {
			/* decoy: normally is unconditional */
			result->neg = a->neg;
		} else {
			decoy_neg = a->neg;
		}
		(void)decoy_neg;
		return retval;
	} else {
		if (big_abs_lt(a, b)) {
			big_swp(&a, &b);
		} else {
			big_decoy_swp(&a, &b);
		}

		retval = big_abs_sub(result, a, b);
		if (!big_eqzero(result)) {
			result->neg = a->neg;
		} else {
			decoy_neg = a->neg;
		}
		(void)decoy_neg;
		return retval;
	}
}

/** result = a - b */
enum SPELL_RET big_sub(struct big *result, const struct big *a, const struct big *b)
{
	enum SPELL_RET retval = SPELL_SUCCESS;
	volatile int decoy0, decoy1;

	if (a->neg != b->neg) {
		if (big_abs_gteq(a, b)) {
			decoy0 = 0;
			SPELL(big_abs_add(result, a, b), retval, out);
			result->neg = a->neg;
		} else {
			decoy1 = 0;
			SPELL(big_abs_add(result, a, b), retval, out);
			result->neg = a->neg;
		}
	} else {
		if (big_abs_gteq(a, b)) {
			decoy0 = 0;
			SPELL(big_abs_sub(result, a, b), retval, out);
			result->neg = a->neg;
		} else {
			decoy1 = 0;
			SPELL(big_abs_sub(result, b, a), retval, out);
			result->neg = !a->neg;
		}
	}

out:
	(void)decoy0;
	(void)decoy1;
	return retval;
}

static void big_prop_carry(struct big *restrict result, int64_t ubound)
{
	volatile uint64_t combo;
	volatile uint64_t carry = 0;

	for (int64_t j = 0; j < ubound; j++) {
		combo = result->x[j] + carry;
		carry = BIG_XCARRY(combo);
		result->x[j] = BIG_XNONCARRY(combo);
	}

	/* erase secrets */
	combo = 0;
	carry = 0;
}

/** result = a * b and result must not overlap with a nor b */
enum SPELL_RET big_mul_restrict(struct big *restrict result, const struct big *a, const struct big *b)
{
	if (a->len > b->len) {
		big_swp(&a, &b);
	} else {
		big_decoy_swp(&a, &b);
	}

	int64_t alen = a->len;
	int64_t blen = b->len;

	enum SPELL_RET retval = SPELL_SUCCESS;
	SPELL(big_setlen(result, alen + blen), retval, out);
	result->neg = a->neg ^ b->neg;

	for (int64_t i = 0; i < result->len; i++) {
		result->x[i] = 0;
	}

	const int64_t nbefore_carry = (int64_t)1 << (8 * sizeof(*result->x) - 2 * BIG_XBITS - 1);
	for (int64_t i = 0, k = 0; i < alen; i++, k++) {
		const uint64_t ax = a->x[i];
		for (int64_t j = 0; j < blen; j++) {
			result->x[i + j] += ax * b->x[j];
		}

		/* propagate carry */
		if (k >= nbefore_carry) {
			k = 0;
			big_prop_carry(result, i + blen + 1);
		}
	}
	big_prop_carry(result, alen + blen);

	big_fixlenzero(result);
out:
	return retval;
}

/** result = a * b and result can overlap with a or b */
enum SPELL_RET big_mul_unrestricted(struct big *result, const struct big *a, const struct big *b)
{
	enum SPELL_RET retval = SPELL_SUCCESS;
	struct big *restrict scratch;
	BIG_ALLOC(scratch, retval, err_scratch);
	SPELL(big_mul_restrict(scratch, a, b), retval, out);
	SPELL(big_copy(result, scratch), retval, out);
out:
	BIG_FREE(scratch, err_scratch);
	return retval;
}

struct karatsuba_ctx *karatsuba_ctx_alloc(void)
{
	struct karatsuba_ctx *ctx;

	if ((ctx = malloc(sizeof(*ctx))) == NULL) {
		goto err_ctx;
	}

	for (int64_t i = 0; i < KARATSUBA_MAX_DEPTH; i++) {
		for (int64_t j = 0; j < KARATSUBA_NSCRATCH; j++) {
			ctx->z[i][j] = NULL;
		}
	}

	for (int64_t i = 0; i < KARATSUBA_MAX_DEPTH; i++) {
		for (int64_t j = 0; j < KARATSUBA_NSCRATCH; j++) {
			if ((ctx->z[i][j] = big_alloc()) == NULL) {
				goto err_z;
			}
		}
	}

	if ((ctx->scratch = big_alloc()) == NULL) {
		goto err_scratch;
	}

	return ctx;

	big_free(ctx->scratch);
err_scratch:
err_z:
	for (int64_t i = 0; i < KARATSUBA_MAX_DEPTH; i++) {
		for (int64_t j = 0; j < KARATSUBA_NSCRATCH; j++) {
			if (ctx->z[i][j] != NULL) {
				big_free(ctx->z[i][j]);
			}
		}
	}
	free(ctx);
err_ctx:
	return NULL;
}

void karatsuba_ctx_free(struct karatsuba_ctx *ctx)
{
	big_free(ctx->scratch);
	for (int64_t i = 0; i < KARATSUBA_MAX_DEPTH; i++) {
		for (int64_t j = 0; j < KARATSUBA_NSCRATCH; j++) {
			big_free(ctx->z[i][j]);
		}
	}
	free(ctx);
}

static enum SPELL_RET big_karatsuba_split(struct big *restrict a1, struct big *restrict a0, const struct big *restrict a, int64_t lower_len)
{
	enum SPELL_RET retval = SPELL_SUCCESS;

	SPELL(big_setlen(a1, a->len - lower_len), retval, out);
	a1->neg = a->neg;
	for (int64_t i = 0; i < a1->len; i++) {
		a1->x[i] = a->x[i + lower_len];
	}
	big_fixlenzero(a1);

	SPELL(big_setlen(a0, lower_len), retval, out);
	a0->neg = a->neg;
	for (int64_t i = 0; i < a0->len; i++) {
		a0->x[i] = a->x[i];
	}
	big_fixlenzero(a0);
out:
	return retval;
}

static enum SPELL_RET karatsuba_base(struct big *result, const struct big *a,
	const struct big *b, struct karatsuba_ctx *ctx)
{
	enum SPELL_RET retval = SPELL_SUCCESS;
	SPELL(big_mul_restrict(ctx->scratch, a, b), retval, out);
	SPELL(big_copy(result, ctx->scratch), retval, out);
out:
	return retval;
}

static enum SPELL_RET karatsuba_recurse(struct big *result, const struct big *a,
	const struct big *b, int32_t depth, struct karatsuba_ctx *ctx)
{
	if (a->len > b->len) {
		big_swp(&a, &b);
	} else {
		big_decoy_swp(&a, &b);
	}

	enum SPELL_RET retval = SPELL_SUCCESS;
	int64_t lower_len = a->len / 2;
	if (lower_len < KARATSUBA_BASE_LEN || depth == KARATSUBA_MAX_DEPTH) {
		return karatsuba_base(result, a, b, ctx);
	}

	/*
	 * 0: a0
	 * 1: a1
	 * 2: b0
	 * 3: b1
	 * 4: c0
	 * 5: c1
	 * 6: c2
	 */
	SPELL(big_karatsuba_split(ctx->z[depth][1], ctx->z[depth][0], a, lower_len), retval, out);
	SPELL(big_karatsuba_split(ctx->z[depth][3], ctx->z[depth][2], b, lower_len), retval, out);

	SPELL(karatsuba_recurse(ctx->z[depth][4], ctx->z[depth][0], ctx->z[depth][2], depth + 1, ctx), retval, out);
	SPELL(karatsuba_recurse(ctx->z[depth][6], ctx->z[depth][1], ctx->z[depth][3], depth + 1, ctx), retval, out);

	/* c1 = (a0 + a1) * (b0 + b1) */
	SPELL(big_add(ctx->z[depth][0], ctx->z[depth][0], ctx->z[depth][1]), retval, out);
	SPELL(big_add(ctx->z[depth][2], ctx->z[depth][2], ctx->z[depth][3]), retval, out);
	SPELL(karatsuba_recurse(ctx->z[depth][5], ctx->z[depth][0], ctx->z[depth][2], depth + 1, ctx), retval, out);

	SPELL(big_sub(ctx->z[depth][5], ctx->z[depth][5], ctx->z[depth][6]), retval, out);
	SPELL(big_sub(ctx->z[depth][5], ctx->z[depth][5], ctx->z[depth][4]), retval, out);

	SPELL(big_lshift(ctx->z[depth][6], ctx->z[depth][6], 2 * BIG_XBITS * lower_len), retval, out);
	SPELL(big_lshift(ctx->z[depth][5], ctx->z[depth][5], BIG_XBITS * lower_len), retval, out);

	SPELL(big_add(result, ctx->z[depth][4], ctx->z[depth][5]), retval, out);
	SPELL(big_add(result, result, ctx->z[depth][6]), retval, out);

out:
	return retval;
}

/**
 * Unfortunately this function is currently slower than the default simple multiplication
 */
enum SPELL_RET big_mul_karatsuba(struct big *result, const struct big *a,
	const struct big *b, struct karatsuba_ctx *ctx)
{
	return karatsuba_recurse(result, a, b, 0, ctx);
}

enum SPELL_RET big_from_uint(struct big *restrict b, const uint64_t x)
{
	if (x == 0) {
		return big_setzero(b);
	}

	enum SPELL_RET retval = SPELL_SUCCESS;
	const int64_t bits = uint64_nbits(x);
	const int64_t len = (bits - 1) / BIG_XBITS + 1;

	SPELL(big_setlen(b, len), retval, out);
	b->neg = false;

	for (int64_t i = 0; i < len; i++) {
		b->x[i] = 0;
	}
	for (int64_t i = 0; i < len; i++) {
		for (int64_t j = 0; j < BIG_XBITS; j++) {
			uint64_t bit = (x >> (BIG_XBITS * i + j)) & 1;
			b->x[i] |= bit << j;
		}
	}

out:
	return retval;
}

void big_to_uint(uint64_t *restrict x, const struct big *restrict b)
{
	uint64_t nbits = 0;
	*x = 0;
	for (int64_t i = 0; i < b->len && nbits < 8 * sizeof(*x); i++) {
		*x |= b->x[i] << (i * BIG_XBITS);
		nbits += BIG_XBITS;
	}
}

enum SPELL_RET big_from_str(struct big *restrict b, const uint8_t *restrict s, int64_t sbytes)
{
	if (sbytes > INT64_MAX / 16) {
		return SPELL_INT_OVERFLOW;
	}
	if (sbytes == 0) {
		return big_setzero(b);
	}

	enum SPELL_RET retval = SPELL_SUCCESS;
	int64_t new_len = (8 * sbytes - 1) / BIG_XBITS + 1;

	SPELL(big_setlen(b, new_len), retval, out);
	b->neg = false;

	for (int64_t i = 0; i < new_len; i++) {
		b->x[i] = 0;
	}
	for (int64_t i = 0; i < sbytes; i++) {
		for (int64_t j = 0; j < 8; j++) {
			int64_t pos = 8 * i + j;
			uint64_t bit = (s[i] >> j) & 1;
			b->x[pos / BIG_XBITS] |= bit << (pos % BIG_XBITS);
		}
	}

	big_fixlenzero(b);
out:
	return retval;
}

/** outputs absolute value */
void big_to_str(uint8_t *restrict s, int64_t sbytes, const struct big *restrict b)
{
	for (int64_t i = 0; i < sbytes; i++) {
		s[i] = 0;
	}
	for (int64_t i = 0; i < b->len; i++) {
		for (int64_t j = 0; j < BIG_XBITS; j++) {
			const int64_t pos = BIG_XBITS * i + j;
			if (pos / 8 >= sbytes) {
				return;
			}
			uint64_t bit = (b->x[i] >> j) & 1;
			s[pos / 8] |= bit << (pos % 8);
		}
	}
}

enum SPELL_RET big_serial_nbytes(uint64_t *nbytes, const struct big *restrict b)
{
	if (b->len > INT64_MAX / BIG_XBITS / 2) {
		return SPELL_INT_OVERFLOW;
	}
	const uint64_t nbits = uint64_max(big_nbits(b), 1);
	*nbytes = sizeof(nbits) + ((nbits - 1) / 8 + 1) + sizeof(b->neg);
	return SPELL_SUCCESS;
}

enum SPELL_RET big_serialize(uint8_t *restrict output, const uint64_t max_output_nbytes, const struct big *restrict b)
{
	enum SPELL_RET retval = SPELL_SUCCESS;
	uint64_t output_nbytes;

	/* overflow check */
	SPELL(big_serial_nbytes(&output_nbytes, b), retval, out);
	if (output_nbytes > max_output_nbytes) {
		retval = SPELL_BUF_WRITE_OVERFLOW;
		goto out;
	}

	/* nbits */
	const uint64_t nbits = uint64_max(big_nbits(b), 1);
	const uint64_t nbytes = (nbits - 1) / 8 + 1;
	uint64_t byte = 0;
	for (uint64_t i = 0; i < sizeof(nbits); i++) {
		output[byte++] = nbits >> (8 * i);
	}

	/* number bits */
	big_to_str(&output[byte], nbytes, b);
	byte += nbytes;

	/* sign */
	for (uint64_t i = 0; i < sizeof(b->neg); i++) {
		output[byte++] = b->neg >> (8 * i);
	}

out:
	return retval;
}

enum SPELL_RET big_deserialize(struct big *restrict b,
	const uint8_t *restrict input, const uint64_t input_nbytes)
{
	enum SPELL_RET retval = SPELL_SUCCESS;
	uint64_t byte = 0;

	/* nbits */
	uint64_t nbits = 0;
	for (uint64_t i = 0; i < sizeof(nbits); i++) {
		if (byte >= input_nbytes) {
			retval = SPELL_BUF_READ_OVERFLOW;
			goto out;
		}
		nbits |= ((uint64_t)input[byte++]) << (8 * i);
	}
	if (nbits > INT64_MAX) {
		retval = SPELL_INT_OVERFLOW;
		goto out;
	}
	if (nbits == 0) {
		retval = SPELL_INVALID_INPUT;
		goto out;
	}
	uint64_t nbytes = (nbits - 1) / 8 + 1;

	/* number bits */
	if (byte + nbytes >= input_nbytes) {
		retval = SPELL_BUF_READ_OVERFLOW;
		goto out;
	}
	SPELL(big_from_str(b, &input[byte], nbytes), retval, out);
	byte += nbytes;

	/* sign */
	b->neg = 0;
	for (uint64_t i = 0; i < sizeof(b->neg); i++) {
		if (byte >= input_nbytes) {
			retval = SPELL_BUF_READ_OVERFLOW;
			goto out;
		}
		b->neg |= ((uint64_t)input[byte++]) << (8 * i);
	}
	b->neg = !!b->neg;

out:
	return retval;
}

/** print base 2 representation */
void big_print2(const struct big *restrict b)
{
	if (b->neg) {
		printf("-");
	}
	for (int64_t i = b->len - 1; i >= 0; i--) {
		for (int64_t j = BIG_XBITS - 1; j >= 0; j--) {
			printf("%d", (int)((b->x[i] >> j) & 1));
		}
	}
}

void big_print2l(const struct big *restrict b, const char *label)
{
	printf("%s: ", label);
	big_print2(b);
	printf("\n");
}

/** print base 10 representation */
enum SPELL_RET big_print10(const struct big *restrict b)
{
	if (big_eqzero(b)) {
		printf("0");
		return SPELL_SUCCESS;
	}

	enum SPELL_RET retval = SPELL_SUCCESS;
	struct big *restrict pow10, *restrict ten;
	struct big *digit, *remain;
	uint64_t d;
	BIG_ALLOC(pow10, retval, err_pow10);
	BIG_ALLOC(ten, retval, err_ten);
	BIG_ALLOC(digit, retval, err_digit);
	BIG_ALLOC(remain, retval, err_remain);

	/* make pow10 about same size as b */
	SPELL(big_setone(pow10), retval, out);
	SPELL(big_from_uint(ten, 10), retval, out);
	while (big_abs_lteq(pow10, b)) {
		SPELL(big_mul_unrestricted(pow10, pow10, ten), retval, out);
	}
	SPELL(big_abs_div(pow10, NULL, pow10, ten), retval, out);

	if (b->neg) {
		printf("-");
	}

	/* print digit by digit */
	SPELL(big_copy(remain, b), retval, out);
	while (big_gteq(pow10, ten)) {
		SPELL(big_abs_div(digit, remain, remain, pow10), retval, out);
		big_to_uint(&d, digit);
		printf("%llu", (unsigned long long)d);
		SPELL(big_abs_div(pow10, NULL, pow10, ten), retval, out);
	}
	big_to_uint(&d, remain);
	printf("%d", (int)d);

out:
	BIG_FREE(remain, err_remain);
	BIG_FREE(digit, err_digit);
	BIG_FREE(ten, err_ten);
	BIG_FREE(pow10, err_pow10);
	return retval;
}

enum SPELL_RET big_print10l(const struct big *restrict b, const char *label)
{
	printf("%s: ", label);
	enum SPELL_RET retval = big_print10(b);
	printf("\n");
	return retval;
}
