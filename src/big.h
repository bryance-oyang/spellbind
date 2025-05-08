#ifndef BIG_H
#define BIG_H

#include "spellbind.h"
#include "util.h"
#include <stdlib.h>

#define BIG_XBITS 28
#define BIG_MIN_CAP 8

#define BIG_XDIV_POW2(e, x) ((x) >> (e))
#define BIG_XMOD_POW2(e, x) ((BIG_XDIV_POW2((e), (x)) << (e)) ^ (x))
#define BIG_XCARRY(x) (BIG_XDIV_POW2(BIG_XBITS, (x)))
#define BIG_XNONCARRY(x) (BIG_XMOD_POW2(BIG_XBITS, (x)))

struct big {
	/** array containing bits representing the number, each element holding BIG_XBITS of the number */
	volatile uint64_t *x;
	/** number of elements of x representing actual data */
	volatile int64_t len;
	/** memory allocated for x == cap * sizeof(*x) */
	volatile int64_t cap;
	/** false means positive, true means negative */
	volatile bool neg;
};

#define KARATSUBA_MAX_DEPTH 4
#define KARATSUBA_NSCRATCH 7
#define KARATSUBA_BASE_LEN 8

struct karatsuba_ctx {
	struct big *z[KARATSUBA_MAX_DEPTH][KARATSUBA_NSCRATCH];
	struct big *scratch;
};

/** erase secrets */
static void big_erase(struct big *restrict b)
{
	/* erase secrets */
	for (int64_t i = 0; i < b->cap; i++) {
		SPELL_WRITE_ONCE(uint64_t, b->x[i], 0);
	}
}

/**
 * expands memory capacity; should have matching big_fixlen to remove leading 0s
 * later
 */
static enum SPELL_RET big_setlen(struct big *b, int64_t new_len)
{
	if (new_len > INT64_MAX / BIG_XBITS) {
		return SPELL_INT_OVERFLOW;
	}

	const int64_t old_len = b->len;

	if (new_len <= b->len) {
		b->len = new_len;
		return SPELL_SUCCESS;
	} else {
		int64_t new_cap = (int64_t)1 << uint64_nbits(new_len);
		new_cap = uint64_max(new_cap, BIG_MIN_CAP);
		/* never shrink memory: required for arithmetic functions below to operate correctly */
		if (new_cap <= b->cap) {
			b->len = new_len;
			return SPELL_SUCCESS;
		}

		uint64_t *new_x = malloc(new_cap * sizeof(*new_x));
		if (new_x == NULL) {
			return SPELL_ALLOC_FAILURE;
		}

		/* copy old data to new */
		for (int64_t i = 0; i < old_len; i++) {
			new_x[i] = b->x[i];
		}

		/* erase secrets */
		big_erase(b);
		free((void *)b->x);

		b->x = new_x;
		b->len = new_len;
		b->cap = new_cap;
		return SPELL_SUCCESS;
	}
}

/** shrinks the length to remove leading 0s and makes 0 always positive */
static void big_fixlenzero(struct big *restrict b)
{
	int64_t len;
	for (len = b->len; len > 0; len--) {
		if (b->x[len - 1] != 0) {
			break;
		}
	}
	b->len = len;
	if (b->len == 0) {
		b->neg = false;
	}
}

#endif /* BIG_H */
