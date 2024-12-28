/**
 * @file
 * @brief Diffie-Hellman key exchange (prime field version)
 *
 * Prime field Z/pZ where p is a safe prime: p = 2q + 1 where q is also prime.
 * This ensures the only multiplicative subgroups have order 1, 2, q, or 2q.
 *
 * Base is chosen to be the square g = 4 to have order q (g^q = 1 (mod p)). This
 * prevents distinguishing between even and odd private exponents.
 *
 * Alice's private key: a
 * Alice's public key: g^a (mod p)
 *
 * Bob's private key: b
 * Bob's public key: g^b (mod p)
 *
 * Derived shared secret: g^(ab) (mod p)
 */

#include "spellbind.h"
#include "quirky_rng.h"

/** nbits of p for prime field Z/pZ used in Diffie-Hellman */
#define DH_MIN_P_NBITS 32

struct dh_param {
	struct big *g;
	struct big *p;
};

struct dh_param *dh_param_alloc(void)
{
	struct dh_param *dh_param = malloc(sizeof(*dh_param));
	if (dh_param == NULL) {
		goto err_d;
	}
	if ((dh_param->g = big_alloc()) == NULL) {
		goto err_g;
	}
	if ((dh_param->p = big_alloc()) == NULL) {
		goto err_modulus;
	}

	return dh_param;

	big_free(dh_param->p);
err_modulus:
	big_free(dh_param->g);
err_g:
	free(dh_param);
err_d:
	return NULL;
}

void dh_param_free(struct dh_param *dh_param)
{
	big_free(dh_param->p);
	big_free(dh_param->g);
	free(dh_param);
}

/** recommend nbits >= 2048 */
enum SPELL_RET dh_param_init(struct dh_param *dh_param, const uint64_t nbits, struct quirky_rng *rng)
{
	if (nbits < DH_MIN_P_NBITS) {
		return SPELL_INVALID_INPUT;
	}

	enum SPELL_RET retval = SPELL_SUCCESS;
	SPELL(quirky_rng_rand_big(dh_param->p, nbits, rng), retval, out);
	SPELL(z_find_safe_prime(dh_param->p, dh_param->p), retval, out);

	/* pick generator to be 4 so it has order q, which prevents
	 * distinguishing even/odd private exponents */
	SPELL(big_from_uint(dh_param->g, 4), retval, out);
out:
	return retval;
}

enum SPELL_RET dh_param_serial_nbytes(uint64_t *nbytes, const struct dh_param *dh_param)
{
	enum SPELL_RET retval = SPELL_SUCCESS;
	uint64_t tmp;
	*nbytes = 0;

	SPELL(big_serial_nbytes(&tmp, dh_param->p), retval, out);
	if ((*nbytes += tmp) < tmp) {
		retval = SPELL_INT_OVERFLOW;
		goto out;
	}

	SPELL(big_serial_nbytes(&tmp, dh_param->g), retval, out);
	if ((*nbytes += tmp) < tmp) {
		retval = SPELL_INT_OVERFLOW;
		goto out;
	}

out:
	return retval;
}

enum SPELL_RET dh_param_serialize(uint8_t *output,
	uint64_t max_output_nbytes, const struct dh_param *dh_param)
{
	enum SPELL_RET retval = SPELL_SUCCESS;
	uint64_t nbytes_needed, tmp;

	SPELL(dh_param_serial_nbytes(&nbytes_needed, dh_param), retval, out);
	if (max_output_nbytes < nbytes_needed) {
		retval = SPELL_BUF_WRITE_OVERFLOW;
		goto out;
	}

	uint64_t nbytes = 0;
	SPELL(big_serialize(&output[nbytes], max_output_nbytes - nbytes, dh_param->p), retval, out);
	SPELL(big_serial_nbytes(&tmp, dh_param->p), retval, out);
	nbytes += tmp;

	SPELL(big_serialize(&output[nbytes], max_output_nbytes - nbytes, dh_param->g), retval, out);
	SPELL(big_serial_nbytes(&tmp, dh_param->g), retval, out);
	nbytes += tmp;

out:
	return retval;
}

enum SPELL_RET dh_param_deserialize(struct dh_param *dh_param,
	uint8_t *input, uint64_t input_nbytes)
{
	enum SPELL_RET retval = SPELL_SUCCESS;
	uint64_t tmp;
	uint64_t nbytes = 0;

	if (nbytes >= input_nbytes) {
		retval = SPELL_BUF_READ_OVERFLOW;
		goto out;
	}
	SPELL(big_deserialize(dh_param->p, &input[nbytes], input_nbytes - nbytes), retval, out);
	SPELL(big_serial_nbytes(&tmp, dh_param->p), retval, out);
	nbytes += tmp;

	if (nbytes >= input_nbytes) {
		retval = SPELL_BUF_READ_OVERFLOW;
		goto out;
	}
	SPELL(big_deserialize(dh_param->g, &input[nbytes], input_nbytes - nbytes), retval, out);
	SPELL(big_serial_nbytes(&tmp, dh_param->g), retval, out);
	nbytes += tmp;

out:
	return retval;
}

enum SPELL_RET dh_gen_key(struct big *public, struct big *private,
	const struct dh_param *dh_param, struct quirky_rng *rng)
{
	if (big_nbits(dh_param->p) < DH_MIN_P_NBITS) {
		return SPELL_INVALID_INPUT;
	}

	enum SPELL_RET retval = SPELL_SUCCESS;
	/* guarantee private_exponent and -private_exponent are large (mod (p - 1) / 2) */
	uint64_t nbits = big_nbits(dh_param->p) - 3;
	SPELL(quirky_rng_rand_big(private, nbits, rng), retval, out);
	SPELL(dh_blinded_pow(public, dh_param->g, private, dh_param, rng), retval, out);
out:
	return retval;
}

/**
 * result = square_base^exponent (mod dh_param->p) but guard against timing
 * attacks by blinding
 *
 * square_base must have order (p - 1) / 2 (i.e. square_base is a square)
 */
enum SPELL_RET dh_blinded_pow(struct big *result,
	const struct big *square_base, const struct big *private_exponent,
	const struct dh_param *dh_param, struct quirky_rng *rng)
{
	if (big_nbits(dh_param->p) < DH_MIN_P_NBITS) {
		return SPELL_INVALID_INPUT;
	}

	enum SPELL_RET retval = SPELL_SUCCESS;
	struct big *q, *r, *s;
	BIG_ALLOC(q, retval, err_q);
	BIG_ALLOC(r, retval, err_r);
	BIG_ALLOC(s, retval, err_s);

	/* q = (p - 1) / 2 (which is prime) */
	SPELL(big_rshift(q, dh_param->p, 1), retval, out);

	/* guarantee both r and s = r^-1 are big (mod (p - 1) / 2) */
	uint64_t r_nbits = big_nbits(q) / 2;
	SPELL(quirky_rng_rand_big(r, r_nbits, rng), retval, out);

	/* s = r^-1 (mod (p - 1) / 2) */
	SPELL(z_modinv(s, r, q), retval, out);

	/* result = (square_base^(rx))^s (mod p) = square_base^x (mod p) since q
	 * is the order of square_base since square_base is a square */
	SPELL(big_mul_unrestricted(r, r, private_exponent), retval, out);
	SPELL(z_mod(r, r, q), retval, out);
	SPELL(z_crt_modpow(result, square_base, r, dh_param->p), retval, out);
	SPELL(z_crt_modpow(result, result, s, dh_param->p), retval, out);

out:
	BIG_FREE(s, err_s);
	BIG_FREE(r, err_r);
	BIG_FREE(q, err_q);
	return retval;
}

/** key = hash(other_public^private_exponent (mod dh_param->p)) */
enum SPELL_RET dh_finalize_key(uint8_t *key, uint64_t key_nbytes,
	const struct big *other_public, const struct big *private_exponent,
	const struct dh_param *dh_param, struct quirky_rng *rng)
{
	enum SPELL_RET retval = SPELL_SUCCESS;
	struct quirky_rng keygen;
	struct big *shared_secret;
	BIG_ALLOC(shared_secret, retval, err_ss);
	quirky_rng_init(&keygen);

	SPELL(dh_blinded_pow(shared_secret, other_public, private_exponent, dh_param, rng), retval, out);
	big_to_str(key, key_nbytes, shared_secret);

	quirky_rng_add_entropy(&keygen, key, key_nbytes);
	quirky_rng_rand_bytes(key, key_nbytes, &keygen);
out:
	quirky_rng_destroy(&keygen);
	BIG_FREE(shared_secret, err_ss);
	return retval;
}
