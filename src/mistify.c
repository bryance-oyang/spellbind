/**
 * @file
 * @brief mistify: an authenticated stream cipher based on SHA-3/Keccak sponge
 * and quirky_rng
 *
 * High Wizards:
 * 	G. Bertoni, J. Daemen, M. Peeters, G. Van Assche and R. Van Keer, CAESAR
 * 	submission: Keyak v2, CAESAR competition (round 3), 2016
 *
 * Encrypt:
 *	mistify(output_mist, output_ciphertext, max_ciphertext_nbytes
 *		input_plaintext, plaintext_nbytes,
 *		secret_key, secret_key_nbytes,
 *		kdf_input, kdf_input_nbytes, kdf_niter,
 *		nonce_rng);
 *
 * Decrypt:
 * 	demistify(output_plaintext, max_plaintext_nbytes
 *		input_mist, input_ciphertext
 *		secret_key, secret_key_nbytes,
 *		kdf_input, kdf_input_nbytes, kdf_niter);
 *
 * A Keccak sponge is initialized with the secret_key then nonce. The rate bits
 * are xor'ed with the plaintext to produce the ciphertext while also absorbing
 * the plaintext. A one-way ratchet is used to advance the sponge state (see
 * quirky_rng). A mac is squeezed out of the sponge at the end.
 */

#include "spellbind.h"
#include "quirky_rng.h"
#include "util.h"
#include <stdio.h>
#include <string.h>

#define MISTIFY_SECURITY_LEVEL SPELLBIND_SECURITY_LEVEL

#define MISTIFY_KEY_CHECK_NBYTES (MISTIFY_SECURITY_LEVEL / 8)
#define MISTIFY_MAC_NBYTES (MISTIFY_SECURITY_LEVEL / 8)
#define MISTIFY_NONCE_NBYTES (MISTIFY_SECURITY_LEVEL / 8)
#define MISTIFY_KDF_OUTPUT_NBYTES (MISTIFY_SECURITY_LEVEL / 8)

/** mistify encryption metadata */
struct mist {
	/** initialization vector */
	uint8_t nonce[MISTIFY_NONCE_NBYTES];
	/** hash of key and nonce to quickly check for key correctness */
	uint8_t key_check[MISTIFY_KEY_CHECK_NBYTES];
	/** message authentication code */
	uint8_t mac[MISTIFY_MAC_NBYTES];
	uint64_t message_nbytes;
};

struct mist *mist_alloc(void)
{
	struct mist *mist = malloc(sizeof(*mist));
	if (mist == NULL) {
		goto err_mist;
	}
	mist->message_nbytes = 0;
	return mist;

	free(mist);
err_mist:
	return NULL;
}

void mist_free(struct mist *mist)
{
	free(mist);
}

/** returns nbytes if mist were serialized */
uint64_t mist_serial_nbytes(void)
{
	struct mist *mist;
	return MISTIFY_NONCE_NBYTES + MISTIFY_KEY_CHECK_NBYTES + MISTIFY_MAC_NBYTES + sizeof(mist->message_nbytes);
}

/** convert mist struct into byte string */
enum SPELL_RET mist_serialize(uint8_t *restrict output, const uint64_t max_output_nbytes, const struct mist *restrict mist)
{
	const uint64_t serial_nbytes = mist_serial_nbytes();
	if (serial_nbytes > max_output_nbytes) {
		return SPELL_BUF_WRITE_OVERFLOW;
	}

	uint64_t byte = 0;
	for (uint64_t i = 0; i < MISTIFY_NONCE_NBYTES; i++) {
		output[byte++] = mist->nonce[i];
	}
	for (uint64_t i = 0; i < MISTIFY_KEY_CHECK_NBYTES; i++) {
		output[byte++] = mist->key_check[i];
	}
	for (uint64_t i = 0; i < MISTIFY_MAC_NBYTES; i++) {
		output[byte++] = mist->mac[i];
	}
	for (uint64_t i = 0; i < sizeof(mist->message_nbytes); i++) {
		output[byte++] = mist->message_nbytes >> (8 * i);
	}

	/* obscure */
	uint64_t dance_key = 0;
	for (uint64_t i = 0; i < 8 && i < MISTIFY_NONCE_NBYTES; i++) {
		dance_key |= ((uint64_t)output[i]) << (8 * i);
	}
	mistify_dance(&output[MISTIFY_NONCE_NBYTES], serial_nbytes - MISTIFY_NONCE_NBYTES, dance_key);
	return SPELL_SUCCESS;
}

/** convert byte string into mist struct */
enum SPELL_RET mist_deserialize(struct mist *restrict mist,
	const uint8_t *restrict input, const uint64_t input_nbytes)
{
	const uint64_t serial_nbytes = mist_serial_nbytes();
	if (serial_nbytes > input_nbytes) {
		return SPELL_BUF_READ_OVERFLOW;
	}

	uint8_t *buf;
	if ((buf = malloc(serial_nbytes)) == NULL) {
		return SPELL_ALLOC_FAILURE;
	}
	memcpy(buf, input, serial_nbytes);

	/* unobscure */
	uint64_t dance_key = 0;
	for (uint64_t i = 0; i < 8 && i < MISTIFY_NONCE_NBYTES; i++) {
		dance_key |= ((uint64_t)buf[i]) << (8 * i);
	}
	mistify_dance(&buf[MISTIFY_NONCE_NBYTES], serial_nbytes - MISTIFY_NONCE_NBYTES, dance_key);

	uint64_t byte = 0;
	for (uint64_t i = 0; i < MISTIFY_NONCE_NBYTES; i++) {
		mist->nonce[i] = buf[byte++];
	}
	for (uint64_t i = 0; i < MISTIFY_KEY_CHECK_NBYTES; i++) {
		mist->key_check[i] = buf[byte++];
	}
	for (uint64_t i = 0; i < MISTIFY_MAC_NBYTES; i++) {
		mist->mac[i] = buf[byte++];
	}

	mist->message_nbytes = 0;
	for (uint64_t i = 0; i < sizeof(mist->message_nbytes); i++) {
		mist->message_nbytes |= ((uint64_t)buf[byte++]) << (8 * i);
	}

	free(buf);
	return SPELL_SUCCESS;
}

uint64_t mist_message_nbytes(const struct mist *mist)
{
	return mist->message_nbytes;
}

enum MISTIFY_CIPHER_MODE {
	MISTIFY_CIPHER_ENCRYPT,
	MISTIFY_CIPHER_DECRYPT,
	MISTIFY_CIPHER_CHECK_KEY,
};

/**
 * Authenticated stream cipher: xor with sponge output to encrypt/decrypt and
 * also simultaneously absorb into sponge for mac generation at end
 */
static void mistify_auth_cipher(const enum MISTIFY_CIPHER_MODE mode,
	const struct mist *mist,
	uint8_t *const plaintext, uint8_t *const ciphertext, uint8_t *mac, uint8_t *key_check,
	const uint8_t *secret_key, const uint64_t secret_key_nbytes,
	const uint8_t *kdf_input, const uint64_t kdf_input_nbytes, const uint64_t kdf_niter)
{
	const uint64_t message_nbytes = mist->message_nbytes;
	struct quirky_rng cipher_rng;
	quirky_rng_init(&cipher_rng);

	/* seed rng with secret_key and nonce */
	quirky_rng_add_entropy(&cipher_rng, secret_key, secret_key_nbytes);
	if (kdf_input != NULL && kdf_input_nbytes > 0 && kdf_niter > 0) {
		uint8_t kdf_output[MISTIFY_KDF_OUTPUT_NBYTES];
		mistify_kdf(kdf_output, MISTIFY_KDF_OUTPUT_NBYTES, kdf_input, kdf_input_nbytes, mist->nonce, MISTIFY_NONCE_NBYTES, kdf_niter);
		quirky_rng_add_entropy(&cipher_rng, kdf_output, MISTIFY_KDF_OUTPUT_NBYTES);
		erase_buf(kdf_output, MISTIFY_KDF_OUTPUT_NBYTES);
	}
	quirky_rng_add_entropy(&cipher_rng, mist->nonce, MISTIFY_NONCE_NBYTES);

	/* hash of key and nonce to verify key correctness */
	quirky_rng_rand_bytes(key_check, MISTIFY_KEY_CHECK_NBYTES, &cipher_rng);
	if (mode == MISTIFY_CIPHER_CHECK_KEY) {
		goto out;
	}

	/*
	 * Sponge's rate bits supply random bits which are xor'ed into either
	 * the plaintext for encryption, or ciphertext for decryption
	 *
	 * The plaintext itself is absorbed into the sponge's rate bits with xor
	 * as well, so the sponge state incorporates the entire message to
	 * produce the mac
	 */

	/* operate first on 64 bit chunks for efficiency */
	/* i, j index blocks of 64 bits: i for message, j for sponge */
	uint64_t i = 0, j = 0;
	for (; i < message_nbytes / 8; i++) {
		uint64_t chunk64 = 0;
		if (mode == MISTIFY_CIPHER_DECRYPT) {
			/* store 64 bits of ciphertext in chunk64 */
			for (uint64_t k = 0; k < 8; k++) {
				chunk64 |= ((uint64_t)ciphertext[8 * i + k]) << (8 * k);
			}

			/* xor with sponge to get plaintext */
			cipher_rng.k.A[j] ^= chunk64;

			/* extract 64 bits of plaintext */
			if (plaintext != NULL) {
				for (uint64_t k = 0; k < 8; k++) {
					plaintext[8 * i + k] = cipher_rng.k.A[j] >> (8 * k);
				}
			}

			/* sponge is now ciphertext */
			cipher_rng.k.A[j] = chunk64;
		} else {
			/* store 64 bits of plaintext in chunk64 */
			for (uint64_t k = 0; k < 8; k++) {
				chunk64 |= ((uint64_t)plaintext[8 * i + k]) << (8 * k);
			}

			/* xor with sponge to get ciphertext */
			/* sponge is now ciphertext */
			cipher_rng.k.A[j] ^= chunk64;

			/* extract 64 bits of ciphertext */
			for (uint64_t k = 0; k < 8; k++) {
				ciphertext[8 * i + k] = cipher_rng.k.A[j] >> (8 * k);
			}
		}

		/* ratchet whenever current sponge rate is used up */
		j++;
		if (j == QUIRKY_RNG_RATE_NBYTES / 8) {
			j = 0;
			quirky_rng_ratchet(&cipher_rng);
		}
	}

	/* convert i, j to index bytes: i for message, j for sponge */
	i *= 8;
	j *= 8;
	/* perform same operation on remaining bytes that did not fit in 64-bit chunks */
	for (; i < message_nbytes; i++) {
		if (mode == MISTIFY_CIPHER_DECRYPT) {
			uint8_t rng_byte = cipher_rng.k.A[j / 8] >> (8 * (j % 8));
			uint8_t plaintext_byte = ciphertext[i] ^ rng_byte;
			if (plaintext != NULL) {
				plaintext[i] = plaintext_byte;
			}
			cipher_rng.k.A[j / 8] ^= ((uint64_t)plaintext_byte) << (8 * (j % 8));
		} else {
			cipher_rng.k.A[j / 8] ^= ((uint64_t)plaintext[i]) << (8 * (j % 8));
			ciphertext[i] = cipher_rng.k.A[j / 8] >> (8 * (j % 8));
		}

		/* ratchet whenever current sponge rate is used up */
		j++;
		if (j == QUIRKY_RNG_RATE_NBYTES) {
			j = 0;
			quirky_rng_ratchet(&cipher_rng);
		}
	}

	/* simple pad: 0's until rate's end then length */
	quirky_rng_ratchet(&cipher_rng);
	cipher_rng.k.A[0] ^= message_nbytes;

	/* produce mac */
	quirky_rng_ratchet(&cipher_rng);
	quirky_rng_rand_bytes(mac, MISTIFY_MAC_NBYTES, &cipher_rng);

out:
	/* erase secrets */
	quirky_rng_destroy(&cipher_rng);
}

/** encrypt */
enum SPELL_RET mistify(struct mist *mist, uint8_t *ciphertext, const uint64_t max_ciphertext_nbytes,
	const uint8_t *plaintext, const uint64_t plaintext_nbytes,
	const uint8_t *secret_key, const uint64_t secret_key_nbytes,
	const uint8_t *kdf_input, const uint64_t kdf_input_nbytes, const uint64_t kdf_niter,
	struct quirky_rng *nonce_rng)
{
	if (max_ciphertext_nbytes < plaintext_nbytes) {
		return SPELL_BUF_WRITE_OVERFLOW;
	}

	mist->message_nbytes = plaintext_nbytes;
	quirky_rng_rand_bytes(mist->nonce, MISTIFY_NONCE_NBYTES, nonce_rng);
	mistify_auth_cipher(MISTIFY_CIPHER_ENCRYPT, mist, (uint8_t *)plaintext,
		ciphertext, mist->mac, mist->key_check, secret_key, secret_key_nbytes,
		kdf_input, kdf_input_nbytes, kdf_niter);
	return SPELL_SUCCESS;
}

/** decrypt */
enum SPELL_RET demistify(uint8_t *plaintext, const uint64_t max_plaintext_nbytes,
	struct mist *restrict mist, const uint8_t *ciphertext,
	const uint8_t *secret_key, const uint64_t secret_key_nbytes,
	const uint8_t *kdf_input, const uint64_t kdf_input_nbytes, const uint64_t kdf_niter)
{
	if (plaintext != NULL && max_plaintext_nbytes < mist->message_nbytes) {
		return SPELL_BUF_WRITE_OVERFLOW;
	}

	enum SPELL_RET retval = SPELL_SUCCESS;
	uint8_t verify_key_check[MISTIFY_KEY_CHECK_NBYTES];
	uint8_t verify_mac[MISTIFY_MAC_NBYTES];

	/* check key */
	mistify_auth_cipher(MISTIFY_CIPHER_CHECK_KEY, mist, NULL,
		NULL, NULL, verify_key_check,
		secret_key, secret_key_nbytes,
		kdf_input, kdf_input_nbytes, kdf_niter);
	for (uint64_t i = 0; i < MISTIFY_KEY_CHECK_NBYTES; i++) {
		if (verify_key_check[i] != mist->key_check[i]) {
			retval = SPELL_KEY_ERROR;
			goto err_key;
		}
	}

	/* decrypt and mac */
	mistify_auth_cipher(MISTIFY_CIPHER_DECRYPT, mist, plaintext,
		(uint8_t *)ciphertext, verify_mac, verify_key_check,
		secret_key, secret_key_nbytes,
		kdf_input, kdf_input_nbytes, kdf_niter);

	/* check mac */
	for (uint64_t i = 0; i < MISTIFY_MAC_NBYTES; i++) {
		if (verify_mac[i] != mist->mac[i]) {
			retval = SPELL_MAC_ERROR;
			goto err_mac;
		}
	}

err_mac:
	/* erase secrets */
	erase_buf(verify_mac, MISTIFY_MAC_NBYTES);
	if (retval != SPELL_SUCCESS && plaintext != NULL) {
		erase_buf(plaintext, mist->message_nbytes);
	}
err_key:
	erase_buf(verify_key_check, MISTIFY_KEY_CHECK_NBYTES);
	return retval;
}

/** key derivation function: recommend niter >= 65536 */
void mistify_kdf(uint8_t *out_key, const uint64_t out_key_nbytes,
	const uint8_t *in_key, const uint64_t in_key_nbytes,
	const uint8_t *salt, const uint64_t salt_nbytes,
	const uint64_t niter)
{
	struct quirky_rng kdf_rng;

	quirky_rng_init(&kdf_rng);
	for (uint64_t i = 0; i < niter; i++) {
		quirky_rng_add_entropy(&kdf_rng, in_key, in_key_nbytes);
		quirky_rng_add_entropy(&kdf_rng, salt, salt_nbytes);
	}
	quirky_rng_rand_bytes(out_key, out_key_nbytes, &kdf_rng);

	/* erase secrets */
	quirky_rng_destroy(&kdf_rng);
}

enum SPELL_RET mistify_file(const char *out_fname, const char *in_fname,
	const uint8_t *secret_key, const uint64_t secret_key_nbytes,
	const uint8_t *kdf_input, const uint64_t kdf_input_nbytes, const uint64_t kdf_niter,
	struct quirky_rng *nonce_rng)
{
	enum SPELL_RET retval = SPELL_SUCCESS;
	struct mist *restrict mist;
	uint8_t *serial_mist;

	/* alloc mist */
	if ((mist = mist_alloc()) == NULL) {
		retval = SPELL_ALLOC_FAILURE;
		goto err_mist_alloc;
	}

	/* filesize determines buffer size */
	SPELL(spell_fnbytes(&mist->message_nbytes, in_fname), retval, err_message_alloc);
	uint8_t *message = malloc(mist->message_nbytes);
	if (message == NULL) {
		retval = SPELL_ALLOC_FAILURE;
		goto err_message_alloc;
	}

	/* read plaintext */
	SPELL(spell_fread(message, mist->message_nbytes, in_fname), retval, err_plaintext);

	/* encrypt then mac */
	if ((retval = mistify(mist, message, mist->message_nbytes,
		message, mist->message_nbytes, secret_key, secret_key_nbytes,
		kdf_input, kdf_input_nbytes, kdf_niter, nonce_rng)) != 0) {
		goto err_serial_mist;
	}

	/* serialize mist */
	const uint64_t serial_mist_nbytes = mist_serial_nbytes();
	if ((serial_mist = malloc(serial_mist_nbytes + mist->message_nbytes)) == NULL) {
		retval = SPELL_ALLOC_FAILURE;
		goto err_serial_mist;
	}
	SPELL(mist_serialize(serial_mist, serial_mist_nbytes, mist), retval, err_output);

	/* write to output */
	for (uint64_t i = 0; i < mist->message_nbytes; i++) {
		serial_mist[serial_mist_nbytes + i] = message[i];
	}
	SPELL(spell_fwrite(out_fname, serial_mist, serial_mist_nbytes + mist->message_nbytes), retval, err_output);

err_output:
	free(serial_mist);
err_serial_mist:
	/* erase secrets */
	erase_buf(message, mist->message_nbytes);
err_plaintext:
	free(message);
err_message_alloc:
	mist_free(mist);
err_mist_alloc:
	return retval;
}

enum SPELL_RET demistify_file(const char *out_fname, const char *in_fname,
	const uint8_t *secret_key, const uint64_t secret_key_nbytes,
	const uint8_t *kdf_input, const uint64_t kdf_input_nbytes, const uint64_t kdf_niter)
{
	enum SPELL_RET retval = SPELL_SUCCESS;
	uint8_t *serial_mist;
	uint64_t serial_mist_msg_nbytes;
	struct mist *mist;

	/* alloc serial_mist */
	SPELL(spell_fnbytes(&serial_mist_msg_nbytes, in_fname), retval, err_serial_mist);
	if ((serial_mist = malloc(serial_mist_msg_nbytes)) == NULL) {
		retval = SPELL_ALLOC_FAILURE;
		goto err_serial_mist;
	}

	/* read serial_mist from file */
	SPELL(spell_fread(serial_mist, serial_mist_msg_nbytes, in_fname), retval, err_mist_alloc);

	/* deserialize mist */
	if ((mist = mist_alloc()) == NULL) {
		retval = SPELL_ALLOC_FAILURE;
		goto err_mist_alloc;
	}
	if ((retval = mist_deserialize(mist, serial_mist, serial_mist_msg_nbytes)) != 0) {
		goto err_decrypt;
	}
	const uint64_t serial_mist_nbytes = mist_serial_nbytes();
	uint8_t *message = &serial_mist[serial_mist_nbytes];

	/* decrypt into ciphertext buffer */
	SPELL(demistify(message, serial_mist_msg_nbytes - serial_mist_nbytes,
		mist, message, secret_key, secret_key_nbytes,
		kdf_input, kdf_input_nbytes, kdf_niter), retval, err_decrypt);

	/* write to output */
	SPELL(spell_fwrite(out_fname, message, mist->message_nbytes), retval, err_write);

err_write:
	/* erase secrets */
	erase_buf(message, mist->message_nbytes);
err_decrypt:
	mist_free(mist);
err_mist_alloc:
	free(serial_mist);
err_serial_mist:
	return retval;
}

#define LROT32(x, y) (((x) << (y)) | ((x) >> ((32 - (y)) % 32)))
#define LROT64(x, y) (((x) << (y)) | ((x) >> ((64 - (y)) % 64)))

static inline void dance(uint32_t *b, const uint32_t *a, uint32_t i)
{
	for (uint32_t j = 0; j < 4; j++) {
		b[j] = a[j];
	}
	b[0] ^= i;
	for (uint32_t j = 0; j < 8; j++) {
		b[0] += b[1];
		b[3] ^= b[0];
		b[3] = LROT32(b[3], 16);
		b[2] += b[3];
		b[1] ^= b[2];
		b[1] = LROT32(b[1], 12);
		b[0] += b[1];
		b[3] ^= b[0];
		b[3] = LROT32(b[3], 8);
		b[2] += b[3];
		b[1] ^= b[2];
		b[1] = LROT32(b[1], 7);
	}
}

void mistify_dance(uint8_t *data, const uint64_t nbytes, const uint64_t key)
{
	uint32_t a[4];
	for (uint64_t i = 0; i < 4; i++) {
		a[i] = LROT64(nbytes, i) + (i << (2 * i)) + LROT64(key, 9 * i);
	}
	for (uint64_t i = 0; i < nbytes; i++) {
		uint32_t b[4];
		dance(b, a, i);
		data[i] ^= b[1];
	}
}
