#ifndef TEST_UTIL_H
#define TEST_UTIL_H

#include "../spellbind.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define SPELL_TEST(spell) do { \
	enum SPELL_RET test_retval_; \
	if ((test_retval_ = (spell)) != SPELL_SUCCESS) { \
		fprintf(stderr, "%s\n", spellbind_strerr(test_retval_)); \
		fflush(stderr); \
		assert(test_retval_ == SPELL_SUCCESS); \
	} \
} while (0)

static void run_test(const char *test_name, void(*test)())
{
	printf("======\n");
	printf("Running test: %s\n", test_name);
	test();
	printf("Finished test: %s\n", test_name);
	printf("======\n\n");
	fflush(stdout);
}

static void printb(int64_t x)
{
	if (x < 0) {
		printf("-");
		x = -x;
	}
	for (int64_t i = 63; i >= 0; i--) {
		printf("%d", (int)((x >> i) & 1));
	}
	fflush(stdout);
}

static void printsha(const uint8_t *hash, int64_t nbits)
{
	int64_t nbytes = nbits / 8;
	for (int64_t i = 0; i < nbytes; i++) {
		printf("%02x", hash[i]);
	}
	fflush(stdout);
}

static void printbin(const uint8_t *bin, uint64_t nbytes)
{
	for (uint64_t i = 0; i < nbytes; i++) {
		printf("%c", bin[i]);
	}
	fflush(stdout);
}

static void mkdigest(uint8_t *digest, const uint8_t *hash, uint64_t nbits)
{
	int64_t nbytes = nbits / 8;
	for (int64_t i = 0; i < nbytes; i++) {
		sprintf((char *)(&digest[2 * i]), "%02x", hash[i]);
	}
}

/* for benchmarking */
struct timespec bench_start_time, bench_end_time;
float bench_duration_ms;
static void bench_start()
{
	clock_gettime(CLOCK_MONOTONIC_RAW, &bench_start_time);
}
static float bench_end(const char *format)
{
	clock_gettime(CLOCK_MONOTONIC_RAW, &bench_end_time);
	bench_duration_ms = (bench_end_time.tv_sec - bench_start_time.tv_sec) * 1000 + (float)(bench_end_time.tv_nsec - bench_start_time.tv_nsec) / 1e6;
	printf(format, bench_duration_ms);
	fflush(stdout);
	return bench_duration_ms;
}

static unsigned long get_cpu_clock()
{
	unsigned a, d;
	asm volatile("rdtsc" : "=a" (a), "=d" (d));
	return ((unsigned long)a) | (((unsigned long)d) << 32);
}

static bool ueq(uint64_t nbytes, const void *a, const void *b)
{
	for (uint64_t i = 0; i < nbytes; i++) {
		if (((uint8_t *)a)[i] != ((uint8_t *)b)[i]) {
			printsha(a, nbytes * 8);
			printf(" != ");
			printsha(b, nbytes * 8);
			printf("\n%llu: %d != %d\n", (unsigned long long)i, ((uint8_t*)a)[i], ((uint8_t*)b)[i]);
			return false;
		}
	}
	return true;
}

static void erase_buf(volatile uint8_t *buf, uint64_t nbytes)
{
	for (uint64_t i = 0; i < nbytes; i++) {
		buf[i] = 0;
	}
}

#endif /* TEST_UTIL_H */
