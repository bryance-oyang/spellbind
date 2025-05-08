/**
 * @file
 * @brief Generate 4096-bit Diffie-Hellman parameters to stdout.
 */

#include "common.h"

int main()
{
	int retval = 0;
	enum SPELL_RET spell_ret;

	const char *seed = "hi";
	struct quirky_rng *rng;
	if ((rng = quirky_rng_alloc()) == NULL) {
		retval = -1;
		fprintf(stderr, "error: quirky_rng_alloc() failed\n");
		fflush(stderr);
		goto err_rng;
	}
	quirky_rng_init(rng);
	quirky_rng_add_entropy(rng, (const uint8_t *)seed, strlen(seed));

	struct dh_param *dh_param;
	if ((dh_param = dh_param_alloc()) == NULL) {
		retval = -1;
		fprintf(stderr, "error: dh_param_alloc() failed\n");
		fflush(stderr);
		goto err_dh_param;
	}

	if ((spell_ret = dh_param_init(dh_param, 4096, rng)) != SPELL_SUCCESS) {
		retval = -1;
		fprintf(stderr, "error: dh_param_init() failed: %s\n", spellbind_strerr(spell_ret));
		fflush(stderr);
		goto err_dh_param_init;
	}

	uint64_t serial_nbytes;
	if ((spell_ret = dh_param_serial_nbytes(&serial_nbytes, dh_param)) != SPELL_SUCCESS) {
		retval = -1;
		fprintf(stderr, "error: dh_param_serial_nbytes() failed: %s\n", spellbind_strerr(spell_ret));
		fflush(stderr);
		goto err_dh_serial_nbytes;
	}

	uint8_t *dh_serial;
	if ((dh_serial = malloc(serial_nbytes)) == NULL) {
		retval = -1;
		fprintf(stderr, "error: dh_serial alloc failed\n");
		fflush(stderr);
		goto err_dh_serial_alloc;
	}

	if ((spell_ret = dh_param_serialize(dh_serial, serial_nbytes, dh_param)) != SPELL_SUCCESS) {
		retval = -1;
		fprintf(stderr, "error: dh_param_serialize() failed: %s\n", spellbind_strerr(spell_ret));
		fflush(stderr);
		goto err_dh_serialize;
	}

	uint64_t b64_nbytes;
	if ((spell_ret = spell_b64_encode_nbytes(&b64_nbytes, serial_nbytes)) != SPELL_SUCCESS) {
		retval = -1;
		fprintf(stderr, "error: spell_b64_encode_nbytes() failed: %s\n", spellbind_strerr(spell_ret));
		fflush(stderr);
		goto err_b64_nbytes;
	}

	uint8_t *b64;
	if ((b64 = malloc(b64_nbytes)) == NULL) {
		retval = -1;
		fprintf(stderr, "error: b64 alloc failed\n");
		fflush(stderr);
		goto err_b64_alloc;
	}

	if ((spell_ret = spell_b64_encode(b64, b64_nbytes, dh_serial, serial_nbytes)) != SPELL_SUCCESS) {
		retval = -1;
		fprintf(stderr, "error: spell_b64_encode() failed: %s\n", spellbind_strerr(spell_ret));
		fflush(stderr);
		goto err_b64_encode;
	}

	for (uint64_t i = 0; i < b64_nbytes; i++) {
		putchar(b64[i]);
	}

err_b64_encode:
	free(b64);
err_b64_alloc:
err_b64_nbytes:
err_dh_serialize:
	free(dh_serial);
err_dh_serial_alloc:
err_dh_serial_nbytes:
err_dh_param_init:
	dh_param_free(dh_param);
err_dh_param:
	quirky_rng_free(rng);
err_rng:
	return retval;
}
