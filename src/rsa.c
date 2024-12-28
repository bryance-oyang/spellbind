/**
 * @file
 * @brief RSA public key encryption or digital signature
 *
 * Parameters:
 * 	p, q are primes
 * 	N = p * q (recommend N >= 2^2048 and p, q >= 2^1024 each)
 * 	e * d = 1 (mod (p - 1)(q - 1) / gcd(p - 1, q - 1))
 *
 * 	N and e are public, all others are secret and private
 *
 * Encryption (or signature verification):
 * 	ciphertext = plaintext^e (mod N)
 *
 * Decryption (or digital signature):
 * 	plaintext = ciphertext^d (mod N)
 *
 * Note that safe usage requires padding
 */

#include "spellbind.h"
#include "big.h"
#include "quirky_rng.h"

#define RSA_MIN_KEY_NBITS 32

struct rsa_private_key {
	/** public modulus */
	struct big *N;

	/** public exponent */
	struct big *e;

	/** private exponent */
	struct big *d;

	/* private primes where modulus = p * q where*/
	struct big *p;
	struct big *q;

	/** largest multiplicative order = (p - 1)(q - 1) / gcd(p - 1, q - 1) */
	struct big *lambda_N;
};

struct rsa_public_key {
	/** public modulus */
	struct big *N;
	/** public exponent */
	struct big *e;
};

struct rsa_private_key *rsa_private_key_alloc(void)
{
	struct rsa_private_key *key = malloc(sizeof(*key));
	if (key == NULL) {
		goto err_key;
	}
	if ((key->N = big_alloc()) == NULL) {
		goto err_N;
	}
	if ((key->e = big_alloc()) == NULL) {
		goto err_e;
	}
	if ((key->d = big_alloc()) == NULL) {
		goto err_d;
	}
	if ((key->p = big_alloc()) == NULL) {
		goto err_p;
	}
	if ((key->q = big_alloc()) == NULL) {
		goto err_q;
	}
	if ((key->lambda_N = big_alloc()) == NULL) {
		goto err_lambda_N;
	}

	return key;

	big_free(key->lambda_N);
err_lambda_N:
	big_free(key->q);
err_q:
	big_free(key->p);
err_p:
	big_free(key->d);
err_d:
	big_free(key->e);
err_e:
	big_free(key->N);
err_N:
	free(key);
err_key:
	return NULL;
}

void rsa_private_key_free(struct rsa_private_key *key)
{
	big_free(key->lambda_N);
	big_free(key->q);
	big_free(key->p);
	big_free(key->d);
	big_free(key->e);
	big_free(key->N);
	free(key);
}

enum SPELL_RET rsa_private_key_serial_nbytes(uint64_t *nbytes, const struct rsa_private_key *key)
{
	enum SPELL_RET retval = SPELL_SUCCESS;
	uint64_t tmp;
	*nbytes = 0;

	SPELL(big_serial_nbytes(&tmp, key->N), retval, out);
	if ((*nbytes += tmp) < tmp) {
		retval = SPELL_INT_OVERFLOW;
		goto out;
	}

	SPELL(big_serial_nbytes(&tmp, key->e), retval, out);
	if ((*nbytes += tmp) < tmp) {
		retval = SPELL_INT_OVERFLOW;
		goto out;
	}

	SPELL(big_serial_nbytes(&tmp, key->d), retval, out);
	if ((*nbytes += tmp) < tmp) {
		retval = SPELL_INT_OVERFLOW;
		goto out;
	}

	SPELL(big_serial_nbytes(&tmp, key->p), retval, out);
	if ((*nbytes += tmp) < tmp) {
		retval = SPELL_INT_OVERFLOW;
		goto out;
	}

	SPELL(big_serial_nbytes(&tmp, key->q), retval, out);
	if ((*nbytes += tmp) < tmp) {
		retval = SPELL_INT_OVERFLOW;
		goto out;
	}

	SPELL(big_serial_nbytes(&tmp, key->lambda_N), retval, out);
	if ((*nbytes += tmp) < tmp) {
		retval = SPELL_INT_OVERFLOW;
		goto out;
	}

out:
	return retval;
}

enum SPELL_RET rsa_private_key_serialize(uint8_t *output,
	uint64_t max_output_nbytes, const struct rsa_private_key *key)
{
	enum SPELL_RET retval = SPELL_SUCCESS;
	uint64_t nbytes_needed, tmp;

	SPELL(rsa_private_key_serial_nbytes(&nbytes_needed, key), retval, out);
	if (max_output_nbytes < nbytes_needed) {
		retval = SPELL_BUF_WRITE_OVERFLOW;
		goto out;
	}

	uint64_t nbytes = 0;
	SPELL(big_serialize(&output[nbytes], max_output_nbytes - nbytes, key->N), retval, out);
	SPELL(big_serial_nbytes(&tmp, key->N), retval, out);
	nbytes += tmp;

	SPELL(big_serialize(&output[nbytes], max_output_nbytes - nbytes, key->e), retval, out);
	SPELL(big_serial_nbytes(&tmp, key->e), retval, out);
	nbytes += tmp;

	SPELL(big_serialize(&output[nbytes], max_output_nbytes - nbytes, key->d), retval, out);
	SPELL(big_serial_nbytes(&tmp, key->d), retval, out);
	nbytes += tmp;

	SPELL(big_serialize(&output[nbytes], max_output_nbytes - nbytes, key->p), retval, out);
	SPELL(big_serial_nbytes(&tmp, key->p), retval, out);
	nbytes += tmp;

	SPELL(big_serialize(&output[nbytes], max_output_nbytes - nbytes, key->q), retval, out);
	SPELL(big_serial_nbytes(&tmp, key->q), retval, out);
	nbytes += tmp;

	SPELL(big_serialize(&output[nbytes], max_output_nbytes - nbytes, key->lambda_N), retval, out);
	SPELL(big_serial_nbytes(&tmp, key->lambda_N), retval, out);
	nbytes += tmp;

out:
	return retval;
}

enum SPELL_RET rsa_private_key_deserialize(struct rsa_private_key *key,
	uint8_t *input, uint64_t input_nbytes)
{
	enum SPELL_RET retval = SPELL_SUCCESS;
	uint64_t tmp;
	uint64_t nbytes = 0;

	if (nbytes >= input_nbytes) {
		retval = SPELL_BUF_READ_OVERFLOW;
		goto out;
	}
	SPELL(big_deserialize(key->N, &input[nbytes], input_nbytes - nbytes), retval, out);
	SPELL(big_serial_nbytes(&tmp, key->N), retval, out);
	nbytes += tmp;

	if (nbytes >= input_nbytes) {
		retval = SPELL_BUF_READ_OVERFLOW;
		goto out;
	}
	SPELL(big_deserialize(key->e, &input[nbytes], input_nbytes - nbytes), retval, out);
	SPELL(big_serial_nbytes(&tmp, key->e), retval, out);
	nbytes += tmp;

	if (nbytes >= input_nbytes) {
		retval = SPELL_BUF_READ_OVERFLOW;
		goto out;
	}
	SPELL(big_deserialize(key->d, &input[nbytes], input_nbytes - nbytes), retval, out);
	SPELL(big_serial_nbytes(&tmp, key->d), retval, out);
	nbytes += tmp;

	if (nbytes >= input_nbytes) {
		retval = SPELL_BUF_READ_OVERFLOW;
		goto out;
	}
	SPELL(big_deserialize(key->p, &input[nbytes], input_nbytes - nbytes), retval, out);
	SPELL(big_serial_nbytes(&tmp, key->p), retval, out);
	nbytes += tmp;

	if (nbytes >= input_nbytes) {
		retval = SPELL_BUF_READ_OVERFLOW;
		goto out;
	}
	SPELL(big_deserialize(key->q, &input[nbytes], input_nbytes - nbytes), retval, out);
	SPELL(big_serial_nbytes(&tmp, key->q), retval, out);
	nbytes += tmp;

	if (nbytes >= input_nbytes) {
		retval = SPELL_BUF_READ_OVERFLOW;
		goto out;
	}
	SPELL(big_deserialize(key->lambda_N, &input[nbytes], input_nbytes - nbytes), retval, out);
	SPELL(big_serial_nbytes(&tmp, key->lambda_N), retval, out);
	nbytes += tmp;

out:
	return retval;
}

struct rsa_public_key *rsa_public_key_alloc(void)
{
	struct rsa_public_key *key = malloc(sizeof(*key));
	if (key == NULL) {
		goto err_key;
	}
	if ((key->N = big_alloc()) == NULL) {
		goto err_N;
	}
	if ((key->e = big_alloc()) == NULL) {
		goto err_e;
	}

	return key;

	big_free(key->e);
err_e:
	big_free(key->N);
err_N:
	free(key);
err_key:
	return NULL;
}

void rsa_public_key_free(struct rsa_public_key *key)
{
	big_free(key->e);
	big_free(key->N);
	free(key);
}

enum SPELL_RET rsa_public_key_serial_nbytes(uint64_t *nbytes, const struct rsa_public_key *key)
{
	enum SPELL_RET retval = SPELL_SUCCESS;
	uint64_t tmp;
	*nbytes = 0;

	SPELL(big_serial_nbytes(&tmp, key->N), retval, out);
	if ((*nbytes += tmp) < tmp) {
		retval = SPELL_INT_OVERFLOW;
		goto out;
	}

	SPELL(big_serial_nbytes(&tmp, key->e), retval, out);
	if ((*nbytes += tmp) < tmp) {
		retval = SPELL_INT_OVERFLOW;
		goto out;
	}

out:
	return retval;
}

enum SPELL_RET rsa_public_key_serialize(uint8_t *output,
	uint64_t max_output_nbytes, const struct rsa_public_key *key)
{
	enum SPELL_RET retval = SPELL_SUCCESS;
	uint64_t nbytes_needed, tmp;

	SPELL(rsa_public_key_serial_nbytes(&nbytes_needed, key), retval, out);
	if (max_output_nbytes < nbytes_needed) {
		retval = SPELL_BUF_WRITE_OVERFLOW;
		goto out;
	}

	uint64_t nbytes = 0;
	SPELL(big_serialize(&output[nbytes], max_output_nbytes - nbytes, key->N), retval, out);
	SPELL(big_serial_nbytes(&tmp, key->N), retval, out);
	nbytes += tmp;

	SPELL(big_serialize(&output[nbytes], max_output_nbytes - nbytes, key->e), retval, out);
	SPELL(big_serial_nbytes(&tmp, key->e), retval, out);
	nbytes += tmp;

out:
	return retval;
}

enum SPELL_RET rsa_public_key_deserialize(struct rsa_public_key *key,
	uint8_t *input, uint64_t input_nbytes)
{
	enum SPELL_RET retval = SPELL_SUCCESS;
	uint64_t tmp;
	uint64_t nbytes = 0;

	if (nbytes >= input_nbytes) {
		retval = SPELL_BUF_READ_OVERFLOW;
		goto out;
	}
	SPELL(big_deserialize(key->N, &input[nbytes], input_nbytes - nbytes), retval, out);
	SPELL(big_serial_nbytes(&tmp, key->N), retval, out);
	nbytes += tmp;

	if (nbytes >= input_nbytes) {
		retval = SPELL_BUF_READ_OVERFLOW;
		goto out;
	}
	SPELL(big_deserialize(key->e, &input[nbytes], input_nbytes - nbytes), retval, out);
	SPELL(big_serial_nbytes(&tmp, key->e), retval, out);
	nbytes += tmp;

out:
	return retval;
}

enum SPELL_RET rsa_publish(struct rsa_public_key *public,
	const struct rsa_private_key *private)
{
	enum SPELL_RET retval = SPELL_SUCCESS;
	SPELL(big_copy(public->N, private->N), retval, out);
	SPELL(big_copy(public->e, private->e), retval, out);
out:
	return retval;
}

enum SPELL_RET rsa_gen_key(struct rsa_private_key *private,
	const int64_t key_nbits, struct quirky_rng *rng)
{
	if (key_nbits < RSA_MIN_KEY_NBITS) {
		return SPELL_INVALID_INPUT;
	}

	enum SPELL_RET retval = SPELL_SUCCESS;
	struct big *one, *scratch, *p_min_one, *q_min_one;
	BIG_ALLOC(one, retval, err_one);
	BIG_ALLOC(scratch, retval, err_scratch);
	BIG_ALLOC(p_min_one, retval, err_p_min_one);
	BIG_ALLOC(q_min_one, retval, err_q_min_one);

	SPELL(big_setone(one), retval, out);

	/* generate p, q */
	int64_t pq_nbits = key_nbits / 2;
	int64_t lambda_N_nbits;
	for (;;) {
		SPELL(quirky_rng_rand_big(private->p, pq_nbits, rng), retval, out);
		SPELL(quirky_rng_rand_big(private->q, pq_nbits, rng), retval, out);
		SPELL(z_find_prime(private->p, private->p), retval, out);
		SPELL(z_find_prime(private->q, private->q), retval, out);

		/* ensure |p - q| is large enough (prevent Fermat factorization) */
		SPELL(big_sub(scratch, private->p, private->q), retval, out);
		if (big_nbits(scratch) < key_nbits / 4) {
			continue;
		}

		SPELL(big_sub(p_min_one, private->p, one), retval, out);
		SPELL(big_sub(q_min_one, private->q, one), retval, out);

		SPELL(z_euclid_alg(scratch, NULL, NULL, p_min_one, q_min_one), retval, out);
		SPELL(big_abs_div(private->lambda_N, NULL, p_min_one, scratch), retval, out);
		SPELL(big_mul_unrestricted(private->lambda_N, private->lambda_N, q_min_one), retval, out);

		lambda_N_nbits = big_nbits(private->lambda_N);
		/* guarantee lambda_N is still big */
		if (lambda_N_nbits < 7 * key_nbits / 8) {
			continue;
		}

		break;
	}
	SPELL(big_mul_restrict(private->N, private->p, private->q), retval, out);

	/*
	 * generate e, d
	 * e shall be big but not too big to guarantee d is even bigger
	 *
	 * 1/8 == log2(e) / log2(lambda_N) and 7/8 <= log2(d) / log2(lambda_N)
	 * 1/8 * 7/8 <= log2(e) / log2(N) <= 1/8 and 7/8 * 7/8 <= log2(d) / log2(N)
	 */
	int64_t e_nbits = uint64_min(lambda_N_nbits / 8, 255);
	for (;;) {
		SPELL(quirky_rng_rand_big(private->e, e_nbits, rng), retval, out);
		/* make e odd */
		private->e->x[0] |= 1;
		retval = z_modinv(private->d, private->e, private->lambda_N);
		if (retval == SPELL_SUCCESS) {
			break;
		} else if (retval == SPELL_NO_MOD_INVERSE) {
			retval = SPELL_SUCCESS;
			continue;
		} else {
			goto out;
		}
	}

out:
	BIG_FREE(q_min_one, err_q_min_one);
	BIG_FREE(p_min_one, err_p_min_one);
	BIG_FREE(scratch, err_scratch);
	BIG_FREE(one, err_one);
	return retval;
}

enum SPELL_RET rsa_public_pow(struct big *result, const struct big *base, const struct rsa_public_key *public)
{
	enum SPELL_RET retval = SPELL_SUCCESS;
	SPELL(z_crt_modpow(result, base, public->e, public->N), retval, out);
out:
	return retval;
}

/** result = base^d but guard against timing attack with blinding */
enum SPELL_RET rsa_blinded_pow(struct big *result, const struct big *base,
	const struct rsa_private_key *private, struct quirky_rng *rng)
{
	enum SPELL_RET retval = SPELL_SUCCESS;
	struct big *r;
	BIG_ALLOC(r, retval, err_r);

	/* generate random r where gcd(r, N) == 1 */
	do {
		SPELL(quirky_rng_rand_big(r, big_nbits(private->N) / 2, rng), retval, out);
		SPELL(z_euclid_alg(result, NULL, NULL, r, private->N), retval, out);
	} while (!big_eqone(result));

	/* result = base * r^e (mod N) */
	SPELL(z_crt_modpow(result, r, private->e, private->N), retval, out);
	SPELL(big_mul_unrestricted(result, result, base), retval, out);
	SPELL(z_mod(result, result, private->N), retval, out);

	/* result = base^d * r (mod N) */
	SPELL(z_crt_modpow(result, result, private->d, private->N), retval, out);

	/* result *= r^-1 (mod N) */
	SPELL(z_modinv(r, r, private->N), retval, out);
	SPELL(big_mul_unrestricted(result, result, r), retval, out);
	SPELL(z_mod(result, result, private->N), retval, out);

out:
	BIG_FREE(r, err_r);
	return retval;
}

/** use message to seed quirky_rng to generate a large number as its hash */
enum SPELL_RET rsa_large_domain_hash(struct big *hash,
	const uint8_t *message, uint64_t message_nbytes,
	const struct big *modulus)
{
	enum SPELL_RET retval = SPELL_SUCCESS;
	struct quirky_rng hash_rng;
	quirky_rng_init(&hash_rng);
	quirky_rng_add_entropy(&hash_rng, message, message_nbytes);

	/* ensure hash will be large but smaller than modulus
	but also guarantee (modulus - hash) is also large */
	const uint64_t hash_nbits = uint64_max(big_nbits(modulus), RSA_MIN_KEY_NBITS) - 2;
	SPELL(quirky_rng_rand_big(hash, hash_nbits, &hash_rng), retval, out);

out:
	/* erase secrets */
	quirky_rng_destroy(&hash_rng);
	return retval;
}

uint64_t rsa_signature_nbytes(const struct rsa_private_key *private)
{
	return (big_nbits(private->N) - 1) / 8 + 1;
}

enum SPELL_RET rsa_sign_message(uint8_t *signature, const uint64_t signature_nbytes,
	const uint8_t *message, const uint64_t message_nbytes,
	const struct rsa_private_key *private, struct quirky_rng *rng)
{
	enum SPELL_RET retval = SPELL_SUCCESS;
	struct big *hash;
	BIG_ALLOC(hash, retval, err_hash);

	/* hash(message)^d (mod N) where hash(message) is guaranteed to be large */
	SPELL(rsa_large_domain_hash(hash, message, message_nbytes, private->N), retval, out);
	SPELL(rsa_blinded_pow(hash, hash, private, rng), retval, out);

	/* serialize signature into bytes */
	const uint64_t needed_signature_nbytes = rsa_signature_nbytes(private);
	if (signature_nbytes < needed_signature_nbytes) {
		retval = SPELL_BUF_WRITE_OVERFLOW;
		goto out;
	}
	big_to_str(signature, needed_signature_nbytes, hash);

out:
	BIG_FREE(hash, err_hash);
	return retval;
}

enum SPELL_RET rsa_verify_signature(bool *is_valid,
	const uint8_t *signature, const uint64_t signature_nbytes,
	const uint8_t *message, const uint64_t message_nbytes,
	const struct rsa_public_key *public)
{
	*is_valid = false;
	enum SPELL_RET retval = SPELL_SUCCESS;
	struct big *their_hash;
	struct big *our_hash;
	BIG_ALLOC(their_hash, retval, err_their_hash);
	BIG_ALLOC(our_hash, retval, err_our_hash);

	/* compute their hash from signature */
	SPELL(big_from_str(their_hash, signature, signature_nbytes), retval, out);
	SPELL(z_crt_modpow(their_hash, their_hash, public->e, public->N), retval, out);

	/* produce hash from message */
	SPELL(rsa_large_domain_hash(our_hash, message, message_nbytes, public->N), retval, out);

	*is_valid = big_eq(their_hash, our_hash);

out:
	BIG_FREE(our_hash, err_our_hash);
	BIG_FREE(their_hash, err_their_hash);
	return retval;
}
