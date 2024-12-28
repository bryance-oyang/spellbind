#ifndef QUIRKY_RNG_H
#define QUIRKY_RNG_H

#include "spellbind.h"
#include "sha3.h"

/* make divisible by 64 */
#define QUIRKY_RNG_SECURITY_LEVEL ((((int)(SPELLBIND_SECURITY_LEVEL) - 1) / 64 + 1) * 64)

/* sponge parameters */
#define QUIRKY_RNG_ERASE_NBITS QUIRKY_RNG_SECURITY_LEVEL
#define QUIRKY_RNG_CAPACITY_NBITS (2 * QUIRKY_RNG_SECURITY_LEVEL + QUIRKY_RNG_ERASE_NBITS)
#define QUIRKY_RNG_RATE_NBITS (1600 - QUIRKY_RNG_CAPACITY_NBITS)
#define QUIRKY_RNG_RATE_NBYTES (QUIRKY_RNG_RATE_NBITS / 8)

/** maximum nbits to output before ratchet */
#define QUIRKY_RNG_OUTPUT_NBITS QUIRKY_RNG_RATE_NBITS
#define QUIRKY_RNG_OUTPUT_NBYTES QUIRKY_RNG_RATE_NBYTES

struct quirky_rng {
	/** index of first word erased in keccak state */
	int32_t erase_start;
	/** number of keccak words erased */
	int32_t erase_nwords;
	/** number of times ratchet has been applied: breaks ratchet symmetry */
	uint64_t ratchet_counter;
	/** keccak internal state (5 x 5 x w) and parameters */
	struct keccak_ctx k;
};

/** erase secrets */
static void quirky_rng_destroy(struct quirky_rng *restrict rng)
{
	SPELL_WRITE_ONCE(uint64_t, rng->ratchet_counter, 0);
	keccak_erase_state(&rng->k);
}

#endif /* QUIRKY_RNG_H */
