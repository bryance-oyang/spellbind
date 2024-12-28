#ifndef TEST_KDF_H
#define TEST_KDF_H

#include "test.h"

static void kdf()
{
	uint8_t out[64];
	char *key = "hello, world!";
	char *salt = "goodbye, world!";
	bench_start();
#ifdef DEBUG
	mistify_kdf(out, 64, (uint8_t *)key, strlen(key), (uint8_t *)salt, strlen(salt), 8);
#else /* DEBUG */
	mistify_kdf(out, 64, (uint8_t *)key, strlen(key), (uint8_t *)salt, strlen(salt), 65536);
#endif /* DEBUG */
	bench_end("kdf (ms): %f\n");
}

#endif /* TEST_KDF_H */
