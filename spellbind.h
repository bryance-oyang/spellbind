/**
 * @file
 * @brief spellbind header file
 */

#ifndef SPELLBIND_H
#define SPELLBIND_H

/* bits of entropy for various algorithms */
#ifndef SPELLBIND_SECURITY_LEVEL
#define SPELLBIND_SECURITY_LEVEL 256
#endif /* SPELLBIND_SECURITY_LEVEL */

#include <stdint.h>
#include <stdbool.h>

/**
 * Return codes for spellbind
 */
enum SPELL_RET {
	SPELL_SUCCESS,
	SPELL_FAILURE,
	SPELL_INVALID_INPUT,
	SPELL_INT_OVERFLOW,
	SPELL_BUF_READ_OVERFLOW,
	SPELL_BUF_WRITE_OVERFLOW,
	SPELL_ALLOC_FAILURE,
	SPELL_FOPEN_FAILURE,
	SPELL_FREAD_FAILURE,
	SPELL_FWRITE_FAILURE,
	SPELL_NO_MOD_INVERSE,
	SPELL_KEY_ERROR,
	SPELL_MAC_ERROR,
};
const char *spellbind_strerr(enum SPELL_RET retval);

/**
 * Perform operation and set retval, on failure goto a label
 *
 * Example:
 * 	enum SPELL_RET retval = SPELL_SUCCESS;
 * 	SPELL(do_stuff(), retval, out);
 * 	do_other_stuff();
 * out:
 * 	return retval;
 */
#define SPELL(operation, retval, goto_label) do { \
	if (((retval) = (operation)) != SPELL_SUCCESS) { \
		goto goto_label; \
	} \
} while (0)

/**
 * SPELL_ALLOC and SPELL_FREE must be matching pairs
 *
 * Uses alloc_function to allocate. If return value is NULL indicating failure,
 * set retval appropriately and goto matching SPELL_FREE's label.
 *
 * Example:
 * 	enum SPELL_RET retval = SPELL_SUCCESS;
 * 	struct big *b;
 * 	SPELL_ALLOC(big_alloc, b, retval, err_b);
 * 	do_stuff();
 * 	SPELL_FREE(big_free, b, err_b);
 * 	return retval;
 */
#define SPELL_ALLOC(alloc_function, b, retval, goto_label) \
do { \
	if (((b) = (alloc_function)()) == NULL) { \
		(retval) = SPELL_ALLOC_FAILURE; \
		goto goto_label; \
	}

/**
 * SPELL_ALLOC and SPELL_FREE must be matching pairs
 * See SPELL_ALLOC.
 */
#define SPELL_FREE(free_function, b, goto_label) \
	(free_function)(b); \
goto_label: \
	(void)0; \
} while (0)

/**
 * Ensure value is written (e.g. for secure erasing of data)
 */
#define SPELL_WRITE_ONCE(type, var, value) do { \
	*(volatile type *)(&(var)) = (value); \
} while (0)

/**
 * Ensure value is read
 */
#define SPELL_READ_ONCE(type, var) (*(volatile type *)(&(var)))

/*
 *
 * big
 *
 */
struct big;
struct big *big_alloc(void);
void big_free(struct big *restrict b);
#define BIG_ALLOC(b, retval, goto_label) SPELL_ALLOC(big_alloc, b, retval, goto_label)
#define BIG_FREE(b, goto_label) SPELL_FREE(big_free, b, goto_label)
enum SPELL_RET big_copy(struct big *result, const struct big *a);
bool big_eq(const struct big *a, const struct big *b);
bool big_eqzero(const struct big *b);
bool big_eqone(const struct big *b);
bool big_is_even(const struct big *b);
bool big_is_odd(const struct big *b);
bool big_abs_lt(const struct big *a, const struct big *b);
bool big_abs_gt(const struct big *a, const struct big *b);
bool big_abs_lteq(const struct big *a, const struct big *b);
bool big_abs_gteq(const struct big *a, const struct big *b);
bool big_lt(const struct big *a, const struct big *b);
bool big_gt(const struct big *a, const struct big *b);
bool big_lteq(const struct big *a, const struct big *b);
bool big_gteq(const struct big *a, const struct big *b);
struct big *big_max(struct big *a, struct big *b);
struct big *big_min(struct big *a, struct big *b);
enum SPELL_RET big_setzero(struct big *restrict b);
enum SPELL_RET big_setone(struct big *restrict b);
enum SPELL_RET big_setpow2(struct big *restrict b, int64_t power);
enum SPELL_RET big_orpow2(struct big *result, const struct big *b, int64_t power);
void big_negate(struct big *restrict b);
int64_t big_nbits(const struct big *restrict b);
int64_t big_pow2_factor_exp(const struct big *restrict b);
enum SPELL_RET big_lshift(struct big *result, const struct big *b, int64_t s);
enum SPELL_RET big_rshift(struct big *result, const struct big *b, int64_t s);
enum SPELL_RET big_modpow2(struct big *result, const struct big *b, int64_t power);
enum SPELL_RET big_not(struct big *result, const struct big *a);
enum SPELL_RET big_and(struct big *result, const struct big *a, const struct big *b);
enum SPELL_RET big_or(struct big *result, const struct big *a, const struct big *b);
enum SPELL_RET big_xor(struct big *result, const struct big *a, const struct big *b);
enum SPELL_RET big_abs_add(struct big *result, const struct big *a, const struct big *b);
enum SPELL_RET big_abs_sub(struct big *result, const struct big *a, const struct big *b);
enum SPELL_RET big_abs_div(struct big *const quotient, struct big *const remainder, const struct big *a, const struct big *divisor);
enum SPELL_RET big_add(struct big *result, const struct big *a, const struct big *b);
enum SPELL_RET big_sub(struct big *result, const struct big *a, const struct big *b);
enum SPELL_RET big_mul_restrict(struct big *restrict result, const struct big *a, const struct big *b);
enum SPELL_RET big_mul_unrestricted(struct big *result, const struct big *a, const struct big *b);
enum SPELL_RET big_from_uint(struct big *restrict b, const uint64_t x);
void big_to_uint(uint64_t *restrict x, const struct big *restrict b);
enum SPELL_RET big_from_str(struct big *restrict b, const uint8_t *restrict s, int64_t sbytes);
void big_to_str(uint8_t *restrict s, int64_t sbytes, const struct big *restrict b);
enum SPELL_RET big_serial_nbytes(uint64_t *nbytes, const struct big *restrict b);
enum SPELL_RET big_serialize(uint8_t *restrict output, const uint64_t max_output_nbytes, const struct big *restrict b);
enum SPELL_RET big_deserialize(struct big *restrict b, const uint8_t *restrict input, const uint64_t input_nbytes);
void big_print2(const struct big *restrict b);
void big_print2l(const struct big *restrict b, const char *label);
enum SPELL_RET big_print10(const struct big *restrict b);
enum SPELL_RET big_print10l(const struct big *restrict b, const char *label);

/*
 *
 * sha3
 *
 */
void sha3_224(uint8_t *output, const uint8_t *message, uint64_t message_nbytes);
void sha3_256(uint8_t *output, const uint8_t *message, uint64_t message_nbytes);
void sha3_384(uint8_t *output, const uint8_t *message, uint64_t message_nbytes);
void sha3_512(uint8_t *output, const uint8_t *message, uint64_t message_nbytes);

/*
 *
 * quirky_rng
 *
 */
struct quirky_rng;
struct quirky_rng *quirky_rng_alloc(void);
void quirky_rng_free(struct quirky_rng *rng);
void quirky_rng_init(struct quirky_rng *restrict rng);
void quirky_rng_ratchet(struct quirky_rng *restrict rng);
void quirky_rng_add_entropy(struct quirky_rng *restrict rng, const uint8_t *restrict entropy, const uint64_t entropy_nbytes);
void quirky_rng_rand_bytes(volatile uint8_t *output, const uint64_t nbytes, struct quirky_rng *restrict rng);
enum SPELL_RET quirky_rng_rand_big(struct big *restrict result, int64_t nbits, struct quirky_rng *restrict rng);

/*
 *
 * mistify
 *
 */
struct mist;
struct mist *mist_alloc(void);
void mist_free(struct mist *mist);
uint64_t mist_serial_nbytes(void);
enum SPELL_RET mist_serialize(uint8_t *restrict output, const uint64_t max_output_nbytes, const struct mist *restrict mist);
enum SPELL_RET mist_deserialize(struct mist *restrict mist, const uint8_t *restrict input, const uint64_t input_nbytes);
uint64_t mist_message_nbytes(const struct mist *mist);
enum SPELL_RET mistify(struct mist *mist, uint8_t *ciphertext, const uint64_t max_ciphertext_nbytes, const uint8_t *plaintext, const uint64_t plaintext_nbytes, const uint8_t *secret_key, const uint64_t secret_key_nbytes, const uint8_t *kdf_input, const uint64_t kdf_input_nbytes, const uint64_t kdf_niter, struct quirky_rng *nonce_rng);
enum SPELL_RET demistify(uint8_t *plaintext, const uint64_t max_plaintext_nbytes, struct mist *restrict mist, const uint8_t *ciphertext, const uint8_t *secret_key, const uint64_t secret_key_nbytes, const uint8_t *kdf_input, const uint64_t kdf_input_nbytes, const uint64_t kdf_niter);
void mistify_kdf(uint8_t *out_key, const uint64_t out_key_nbytes, const uint8_t *in_key, const uint64_t in_key_nbytes, const uint8_t *salt, const uint64_t salt_nbytes, const uint64_t niter);
enum SPELL_RET mistify_file(const char *out_fname, const char *in_fname, const uint8_t *secret_key, const uint64_t secret_key_nbytes, const uint8_t *kdf_input, const uint64_t kdf_input_nbytes, const uint64_t kdf_niter, struct quirky_rng *nonce_rng);
enum SPELL_RET demistify_file(const char *out_fname, const char *in_fname, const uint8_t *secret_key, const uint64_t secret_key_nbytes, const uint8_t *kdf_input, const uint64_t kdf_input_nbytes, const uint64_t kdf_niter);
void mistify_dance(uint8_t *data, const uint64_t nbytes, const uint64_t key);

/*
 *
 * ztheory
 *
 */
enum SPELL_RET z_euclid_alg(struct big *const gcd, struct big *const a_coeff, struct big *const b_coeff, const struct big *a, const struct big *b);
enum SPELL_RET z_mod(struct big *result, const struct big *a, const struct big *modulus);
enum SPELL_RET z_modinv(struct big *result, const struct big *b, const struct big *modulus);
enum SPELL_RET z_crt_modpow(struct big *result, const struct big *a, const struct big *exponent, const struct big *modulus);
enum SPELL_RET z_find_prime(struct big *prime, const struct big *start);
enum SPELL_RET z_find_safe_prime(struct big *prime, const struct big *start);

/*
 *
 * diffie_hellman
 *
 */
struct dh_param;
struct dh_param *dh_param_alloc(void);
void dh_param_free(struct dh_param *dh_param);
enum SPELL_RET dh_param_init(struct dh_param *dh_param, const uint64_t nbits, struct quirky_rng *rng);
enum SPELL_RET dh_param_serial_nbytes(uint64_t *nbytes, const struct dh_param *dh_param);
enum SPELL_RET dh_param_serialize(uint8_t *output, uint64_t max_output_nbytes, const struct dh_param *dh_param);
enum SPELL_RET dh_param_deserialize(struct dh_param *dh_param, uint8_t *input, uint64_t input_nbytes);
enum SPELL_RET dh_param_gen_base(struct dh_param *dh_param, struct quirky_rng *rng);
enum SPELL_RET dh_gen_key(struct big *public, struct big *private, const struct dh_param *dh_param, struct quirky_rng *rng);
enum SPELL_RET dh_blinded_pow(struct big *result, const struct big *base, const struct big *private_exponent, const struct dh_param *dh_param, struct quirky_rng *rng);
enum SPELL_RET dh_finalize_key(uint8_t *key, uint64_t key_nbytes, const struct big *other_public, const struct big *private_exponent, const struct dh_param *dh_param, struct quirky_rng *rng);

/*
 *
 * rsa
 *
 */
struct rsa_private_key;
struct rsa_public_key;
struct rsa_private_key *rsa_private_key_alloc(void);
void rsa_private_key_free(struct rsa_private_key *key);
enum SPELL_RET rsa_private_key_serial_nbytes(uint64_t *nbytes, const struct rsa_private_key *key);
enum SPELL_RET rsa_private_key_serialize(uint8_t *output, uint64_t max_output_nbytes, const struct rsa_private_key *key);
enum SPELL_RET rsa_private_key_deserialize(struct rsa_private_key *key, uint8_t *input, uint64_t input_nbytes);
struct rsa_public_key *rsa_public_key_alloc(void);
void rsa_public_key_free(struct rsa_public_key *key);
enum SPELL_RET rsa_public_key_serial_nbytes(uint64_t *nbytes, const struct rsa_public_key *key);
enum SPELL_RET rsa_public_key_serialize(uint8_t *output, uint64_t max_output_nbytes, const struct rsa_public_key *key);
enum SPELL_RET rsa_public_key_deserialize(struct rsa_public_key *key, uint8_t *input, uint64_t input_nbytes);
enum SPELL_RET rsa_publish(struct rsa_public_key *public, const struct rsa_private_key *private);
enum SPELL_RET rsa_gen_key(struct rsa_private_key *private, const int64_t key_nbits, struct quirky_rng *rng);
enum SPELL_RET rsa_public_pow(struct big *result, const struct big *base, const struct rsa_public_key *public);
enum SPELL_RET rsa_blinded_pow(struct big *result, const struct big *base, const struct rsa_private_key *private, struct quirky_rng *rng);
enum SPELL_RET rsa_large_domain_hash(struct big *hash, const uint8_t *message, uint64_t message_nbytes, const struct big *modulus);
uint64_t rsa_signature_nbytes(const struct rsa_private_key *private);
enum SPELL_RET rsa_sign_message(uint8_t *signature, const uint64_t signature_nbytes, const uint8_t *message, const uint64_t message_nbytes, const struct rsa_private_key *private, struct quirky_rng *rng);
enum SPELL_RET rsa_verify_signature(bool *is_valid, const uint8_t *signature, const uint64_t signature_nbytes, const uint8_t *message, const uint64_t message_nbytes, const struct rsa_public_key *public);

/*
 *
 * file
 *
 */
enum SPELL_RET spell_fnbytes(uint64_t *nbytes, const char *fname);
enum SPELL_RET spell_fread(uint8_t *out, uint64_t nbytes, const char *fname);
enum SPELL_RET spell_fwrite(const char *fname, const uint8_t *buf, const uint64_t nbytes);

/*
 *
 * base64
 *
 */
enum SPELL_RET spell_b64_encode_nbytes(uint64_t *b64_nbytes, const uint64_t binary_nbytes);
enum SPELL_RET spell_b64_decode_max_nbytes(uint64_t *binary_nbytes, const uint64_t b64_nbytes);
enum SPELL_RET spell_b64_encode(uint8_t *b64, const uint64_t max_b64_nbytes, const uint8_t *binary, const uint64_t binary_nbytes);
enum SPELL_RET spell_b64_decode(uint8_t *binary, const uint64_t max_binary_nbytes, uint64_t *binary_nbytes, const uint8_t *b64, const uint64_t b64_nbytes);

/*
 *
 * ecc
 *
 */
enum SPELL_RET ecc_encode_nbytes(uint64_t *encoded_nbytes, const uint64_t plain_nbytes);
enum SPELL_RET ecc_encode(uint8_t *encoded, const uint64_t max_encoded_nbytes, const uint8_t *plain, const uint64_t plain_nbytes, uint8_t *restrict scratch, const uint64_t max_scratch_nbytes, struct quirky_rng *rng);
enum SPELL_RET ecc_decode(uint8_t *plain, const uint64_t max_plain_nbytes, uint64_t *plain_nbytes, const uint8_t *encoded, const uint64_t encoded_nbytes, uint8_t *restrict scratch, const uint64_t max_scratch_nbytes);

#endif /* SPELLBIND_H */
