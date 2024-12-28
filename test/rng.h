#ifndef TEST_RNG_H
#define TEST_RNG_H

#include "test.h"

static void rng_bench()
{
	unsigned long start, end;
	float ms, cpb;

#ifdef DEBUG
	uint64_t outlen = 1 << 10;
#else /* DEBUG */
	uint64_t outlen = 1 << 30;
#endif /* DEBUG */
	uint8_t *out = malloc(outlen);
	uint8_t *scratch = malloc(outlen);
	uint8_t out2[64];
	char *in = "The quick brown fox";
	struct quirky_rng *m = quirky_rng_alloc();
	quirky_rng_init(m);
	quirky_rng_add_entropy(m, (uint8_t *)in, strlen(in));

	/* rng */
	bench_start();
	start = get_cpu_clock();
	quirky_rng_rand_bytes(out, outlen, m);
	end = get_cpu_clock();
	ms = bench_end("quirky (ms): %f\n");
	printf("bps: %e\n", (float)outlen * 1000 / ms);
	cpb = (float)(end - start) / outlen;
	printf("cpb: %f\n", cpb);

	/* mistify */
	struct mist *mist = mist_alloc();
	bench_start();
	start = get_cpu_clock();
	mistify(mist, out, outlen, out, outlen, (uint8_t *)in, strlen(in), NULL, 0, 0, m);
	end = get_cpu_clock();
	ms = bench_end("mistify (ms): %f\n");
	printf("bps: %e\n", (float)outlen * 1000 / ms);
	cpb = (float)(end - start) / outlen;
	printf("cpb: %f\n", cpb);

	/* demistify */
	bench_start();
	start = get_cpu_clock();
	demistify(out, outlen, mist, out, (uint8_t *)in, strlen(in), NULL, 0, 0);
	end = get_cpu_clock();
	ms = bench_end("demistify (ms): %f\n");
	printf("bps: %e\n", (float)outlen * 1000 / ms);
	cpb = (float)(end - start) / outlen;
	printf("cpb: %f\n", cpb);

	/* sha3 */
	bench_start();
	start = get_cpu_clock();
	sha3_256(out2, out, outlen);
	end = get_cpu_clock();
	ms = bench_end("sha3 (ms): %f\n");
	printf("bps: %e\n", (float)outlen * 1000 / ms);
	cpb = (float)(end - start) / outlen;
	printf("cpb: %f\n", cpb);

	/* ecc */
	uint64_t nbytes;
	bench_start();
	start = get_cpu_clock();
	ecc_encode_nbytes(&nbytes, outlen / 2);
	ecc_encode(out, outlen, out, outlen / 2, scratch, outlen, m);
	end = get_cpu_clock();
	ms = bench_end("ecc encode (ms): %f\n");
	printf("bps: %e\n", (float)outlen * 1000 / ms);
	cpb = (float)(end - start) / outlen;
	printf("cpb: %f\n", cpb);

	bench_start();
	start = get_cpu_clock();
	ecc_decode(out, outlen / 2, &nbytes, out, nbytes, scratch, outlen);
	end = get_cpu_clock();
	ms = bench_end("ecc decode (ms): %f\n");
	printf("bps: %e\n", (float)outlen * 1000 / ms);
	cpb = (float)(end - start) / outlen;
	printf("cpb: %f\n", cpb);

	mist_free(mist);
	free(out);
	free(scratch);
	quirky_rng_free(m);
}

#endif /* TEST_RNG_H */
