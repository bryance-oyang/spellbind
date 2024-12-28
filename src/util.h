/**
 * @file
 * @brief Basic utility functions for spellbind internal use
 */

#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>

static inline int64_t uint64_nbits(uint64_t x)
{
	int64_t nbits = 0;
	while (x > 0) {
		x >>= 1;
		nbits++;
	}
	return nbits;
}

static inline uint64_t uint64_max(uint64_t x, uint64_t y)
{
	return x > y ? x : y;
}

static inline uint64_t uint64_min(uint64_t x, uint64_t y)
{
	return x < y ? x : y;
}

static inline void erase_buf(volatile uint8_t *buf, uint64_t buf_nbytes)
{
	for (uint64_t i = 0; i < buf_nbytes; i++) {
		buf[i] = 0;
	}
}

#endif /* UTIL_H */
