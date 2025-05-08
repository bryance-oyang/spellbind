/**
 * @file
 * @brief Command line utility for temporarily decrypting to ephemeral file.
 */

#include "common.h"
#include <signal.h>

#define KEY_MIN_NBYTES (SPELLBIND_SECURITY_LEVEL / 8)
#define PASSWDLEN 1024
#define SALTLEN (SPELLBIND_SECURITY_LEVEL / 8)
#define KDF_NITER 65536

/* read base64 encoded key from fname, and decode into returned buffer, also outputting key_nbytes */
static uint8_t *key_alloc(uint64_t *key_nbytes, const char *fname)
{
	uint8_t *retval = NULL;
	enum SPELL_RET spell_ret;
	uint8_t *key;
	uint64_t b64_len, key_alloc_nbytes;
	struct fmap keymap;

	if (fmap_init(&keymap, fname, -1, true) != 0) {
		fprintf(stderr, "error: failed to fmap key file %s\n", fname);
		goto err_fmap;
	}
	b64_len = (keymap.nbytes / 4) * 4;
	if ((spell_ret = spell_b64_decode_max_nbytes(&key_alloc_nbytes, b64_len)) != SPELL_SUCCESS) {
		fprintf(stderr, "error: b64 to binary length conversion error: %s\n", spellbind_strerr(spell_ret));
		goto err_decode_len;
	}
	if ((key = malloc(key_alloc_nbytes)) == NULL) {
		fprintf(stderr, "error: failed to malloc key\n");
		goto err_key;
	}
	if ((spell_ret = spell_b64_decode(key, key_alloc_nbytes, key_nbytes, keymap.map, b64_len)) != SPELL_SUCCESS) {
		fprintf(stderr, "error: failed to b64 decode key file %s: %s\n", fname, spellbind_strerr(spell_ret));
		goto err_decode;
	}
	if (*key_nbytes < KEY_MIN_NBYTES) {
		fprintf(stderr, "error: key file length too short %s\n", fname);
		goto err_decode;
	}
	retval = key;

err_decode:
	if (retval == NULL) {
		erase_buf(key, key_alloc_nbytes);
		free(key);
	}
err_key:
err_decode_len:
	fmap_destroy(&keymap);
err_fmap:
	fflush(stderr);
	return retval;
}

static void key_free(uint8_t *key, uint64_t key_nbytes)
{
	erase_buf(key, key_nbytes);
	free(key);
}

static int decrypt_cipher_file(const char *plain_fname, const char *cipher_fname,
	const char *key_fname, const uint8_t *passwd, uint64_t passwd_nbytes)
{
	int retval = 0;
	enum SPELL_RET spell_ret;
	struct mist *mist;
	const uint64_t serial_mist_nbytes = mist_serial_nbytes();
	struct fmap plain_fmap, cipher_fmap;
	uint8_t *key;
	uint64_t keylen;

	if (fmap_init(&cipher_fmap, cipher_fname, -1, true) != 0) {
		retval = -1;
		fprintf(stderr, "error: fmap_init() failed for cipher file at %s\n", cipher_fname);
		goto err_fmap_cipher;
	}
	if ((mist = mist_alloc()) == NULL) {
		retval = -1;
		fprintf(stderr, "error: failed to alloc mist\n");
		goto err_mist;
	}
	if ((spell_ret = mist_deserialize(mist, cipher_fmap.map, cipher_fmap.nbytes)) != SPELL_SUCCESS) {
		retval = -1;
		fprintf(stderr, "error: failed to deserialize mist: %s\n", spellbind_strerr(spell_ret));
		goto err_mist_deserial;
	}
	if (fmap_init(&plain_fmap, plain_fname, mist_message_nbytes(mist), false) != 0) {
		retval = -1;
		fprintf(stderr, "error: fmap_init() failed for plain file at %s\n", plain_fname);
		goto err_fmap_plain;
	}
	if ((key = key_alloc(&keylen, key_fname)) == NULL) {
		retval = -1;
		fprintf(stderr, "error: failed to get key at %s\n", key_fname);
		goto err_key;
	}
	if ((spell_ret = demistify(plain_fmap.map, plain_fmap.nbytes, mist, &cipher_fmap.map[serial_mist_nbytes], key, keylen, passwd, passwd_nbytes, KDF_NITER)) != SPELL_SUCCESS) {
		retval = -1;
		fprintf(stderr, "error: failed to demistify: %s\n", spellbind_strerr(spell_ret));
		goto err_demistify;
	}
	erase_buf(key, keylen);
	if (fmap_sync(&plain_fmap) != 0) {
		retval = -1;
		fprintf(stderr, "error: failed to sync plain file at %s\n", plain_fname);
		goto err_sync;
	}

err_sync:
err_demistify:
	key_free(key, keylen);
err_key:
	fmap_destroy(&plain_fmap);
err_fmap_plain:
err_mist_deserial:
	mist_free(mist);
err_mist:
	fmap_destroy(&cipher_fmap);
err_fmap_cipher:
	fflush(stderr);
	return retval;
}

static int encrypt_cipher_file(const char *plain_fname, const char *cipher_fname,
	const char *key_fname, const uint8_t *passwd, uint64_t passwd_nbytes,
	struct quirky_rng *rng)
{
	int retval = 0;
	enum SPELL_RET spell_ret;
	struct mist *mist;
	const uint64_t serial_mist_nbytes = mist_serial_nbytes();
	struct fmap plain_fmap, cipher_fmap;
	uint8_t *key;
	uint64_t keylen, cipherlen;

	if (fmap_init(&plain_fmap, plain_fname, -1, true) != 0) {
		retval = -1;
		fprintf(stderr, "error: fmap_init() failed for plain file at %s\n", plain_fname);
		goto err_fmap_plain;
	}
	if ((cipherlen = serial_mist_nbytes + plain_fmap.nbytes) < serial_mist_nbytes) {
		retval = -1;
		fprintf(stderr, "error: integer overflow for cipherlen\n");
		goto err_cipherlen;
	}
	if (fmap_init(&cipher_fmap, cipher_fname, cipherlen, false) != 0) {
		retval = -1;
		fprintf(stderr, "error: fmap_init() failed for cipher file at %s\n", cipher_fname);
		goto err_fmap_cipher;
	}
	if ((mist = mist_alloc()) == NULL) {
		retval = -1;
		fprintf(stderr, "error: failed to alloc mist\n");
		goto err_mist;
	}
	if ((key = key_alloc(&keylen, key_fname)) == NULL) {
		retval = -1;
		fprintf(stderr, "error: failed to get key %s\n", key_fname);
		goto err_key;
	}
	if ((spell_ret = mistify(mist, &cipher_fmap.map[serial_mist_nbytes], cipher_fmap.nbytes - serial_mist_nbytes, plain_fmap.map, plain_fmap.nbytes, key, keylen, passwd, passwd_nbytes, KDF_NITER, rng)) != SPELL_SUCCESS) {
		retval = -1;
		fprintf(stderr, "error: failed to mistify: %s\n", spellbind_strerr(spell_ret));
		goto err_mistify;
	}
	erase_buf(key, keylen);
	if ((spell_ret = mist_serialize(cipher_fmap.map, serial_mist_nbytes, mist)) != SPELL_SUCCESS) {
		retval = -1;
		fprintf(stderr, "error: failed to serialize mist: %s\n", spellbind_strerr(spell_ret));
		goto err_mist_serial;
	}
	if (fmap_sync(&cipher_fmap) != 0) {
		retval = -1;
		fprintf(stderr, "error: failed to sync cipher file at %s\n", cipher_fname);
		goto err_sync;
	}

err_sync:
err_mist_serial:
err_mistify:
	key_free(key, keylen);
err_key:
	mist_free(mist);
err_mist:
	fmap_destroy(&cipher_fmap);
err_fmap_cipher:
err_cipherlen:
	fmap_destroy(&plain_fmap);
err_fmap_plain:
	fflush(stderr);
	return retval;
}

const char *usage = "Usage: wisp [-p] [-s seed_fname] key_fname cipher_fname plain_fname\n"
	"\t-p\n\t\tUse password\n\n"
	"\t-s seed_fname\n\t\tUse seed_fname as a seed for the random number generator\n\n"
	"\t-d\n\t\tFor device files: limit number of bytes read from seed_fname to compiled security level\n";
char *seed_fname_arg = NULL;
char *key_fname_arg = NULL;
char *cipher_fname_arg = NULL;
char *plain_fname_arg = NULL;
bool use_passwd = false;
int rng_seed_mode = 0;

static int parse_opt(int argc, char **argv)
{
	if (argc < 1 || strlen(argv[0]) != 2) {
		return -1;
	}

	if (argv[0][1] == 'p' && !use_passwd) {
		use_passwd = true;
		return 1;
	} else if (argv[0][1] == 's' && argc >= 2 && seed_fname_arg == NULL) {
		seed_fname_arg = argv[1];
		return 2;
	} else if (argv[0][1] == 'd' && rng_seed_mode == 0) {
		rng_seed_mode = 1;
		return 1;
	}

	return -1;
}

static int parse_fnames(int argc, char **argv)
{
	if (argc < 3 || key_fname_arg != NULL
		|| cipher_fname_arg != NULL || plain_fname_arg != NULL) {
		return -1;
	}
	key_fname_arg = argv[0];
	cipher_fname_arg = argv[1];
	plain_fname_arg = argv[2];
	return 3;
}

static int parse_args(int argc, char **argv)
{
	int advance = 1;
	for (; argc > 0 && advance > 0; argc -= advance, argv += advance) {
		if (argv[0][0] == '-') {
			advance = parse_opt(argc, argv);
		} else {
			advance = parse_fnames(argc, argv);
		}
	}
	return advance;
}

int main(int argc, char **argv)
{
	if (parse_args(argc - 1, &argv[1]) < 0 || key_fname_arg == NULL
		|| cipher_fname_arg == NULL || plain_fname_arg == NULL) {
		fprintf(stderr, "%s", usage);
		return -1;
	}

	const char *const urandom_fname = "/dev/urandom";
	const char *const seed_fname = seed_fname_arg;
	const char *const key_fname = key_fname_arg;
	const char *const cipher_fname = cipher_fname_arg;
	const char *const plain_fname = plain_fname_arg;

	if (access(key_fname, R_OK) != 0) {
		fprintf(stderr, "error: key file not readable at %s\n", key_fname);
		fflush(stderr);
		return -1;
	}

	int retval = 0;
	int sig;
	uint8_t passwd[PASSWDLEN], passwd_check[PASSWDLEN];
	uint8_t salt[SALTLEN];
	struct quirky_rng *rng;
	bool urandom_exists, plain_file_exists, cipher_file_exists;
	struct timespec bench;

	urandom_exists = (access(urandom_fname, F_OK) == 0);
	plain_file_exists = (access(plain_fname, F_OK) == 0);
	cipher_file_exists = (access(cipher_fname, F_OK) == 0);

	if (!urandom_exists) {
		printf("warning: /dev/urandom doesn't exist\n");
		fflush(stdout);
		if (seed_fname == NULL) {
			fprintf(stderr, "error: seed_fname (-s) not provided: no way to seed rng\n");
			fflush(stderr);
			return -1;
		}
	}

	if ((rng = quirky_rng_alloc()) == NULL) {
		retval = -1;
		fprintf(stderr, "error: quirky_rng_alloc() failed\n");
		fflush(stderr);
		goto err_rng;
	}
	quirky_rng_init(rng);
	if (seed_fname == NULL) {
		printf("warning: rng seeded only using /dev/urandom\n");
		fflush(stdout);
	}
	if ((urandom_exists && seed_rng(rng, urandom_fname, 1) != 0) || (seed_fname != NULL && seed_rng(rng, seed_fname, rng_seed_mode) != 0)) {
		retval = -1;
		fprintf(stderr, "error: failed to seed rng\n");
		fflush(stderr);
		goto err_passwd;
	}

	uint64_t passwd_len = 0;
	if (use_passwd) {
		printf("password: ");
		fflush(stdout);
		if (get_passwd(passwd, PASSWDLEN) != 0) {
			retval = -1;
			fprintf(stderr, "error: get_passwd() failed\n");
			fflush(stderr);
			goto err_passwd;
		}
		printf("\n");
		fflush(stdout);
		passwd_len = PASSWDLEN;

		while (!cipher_file_exists) {
			printf("retype password: ");
			fflush(stdout);
			if (get_passwd(passwd_check, PASSWDLEN) != 0) {
				retval = -1;
				fprintf(stderr, "error: get_passwd() failed\n");
				fflush(stderr);
				goto err_passwd_check;
			}
			printf("\n");
			fflush(stdout);
			if (buf_eq(PASSWDLEN, passwd, passwd_check)) {
				erase_buf(passwd_check, PASSWDLEN);
				break;
			} else {
				printf("password mismatch\n");
				fflush(stdout);
			}
		}

		quirky_rng_rand_bytes(salt, SALTLEN, rng);
		mistify_kdf(salt, SALTLEN, passwd, PASSWDLEN, salt, SALTLEN, KDF_NITER);
		quirky_rng_add_entropy(rng, salt, SALTLEN);
		erase_buf(salt, SALTLEN);
	}

	if (plain_file_exists) {
		retval = -1;
		fprintf(stderr, "error: plaintext file already exists at %s\n", plain_fname);
		fflush(stderr);
		goto err_create_plain;
	}
	if (create_file(plain_fname) != 0) {
		retval = -1;
		fprintf(stderr, "error: failed to create plain file %s\n", plain_fname);
		fflush(stderr);
		goto err_create_plain;
	}

	struct tmp_file tmp_cipher_file;
	if (tmp_file_create(&tmp_cipher_file, cipher_fname) != 0) {
		retval = -1;
		fprintf(stderr, "error: failed to create copy on write tmp file for cipher file at %s\n", cipher_fname);
		fflush(stderr);
		goto err_tmp_cipher_file;
	}

	if (cipher_file_exists) {
		printf("decrypting %s -> %s...\n", cipher_fname, plain_fname);
		fflush(stdout);

		struct stat sb_cipher;
		if (stat(cipher_fname, &sb_cipher) != 0) {
			retval = -1;
			fprintf(stderr, "error: failed to stat cipher file %s\n", cipher_fname);
			fflush(stderr);
			goto err_decrypt;
		}

		bench_start(&bench);
		if (decrypt_cipher_file(plain_fname, cipher_fname, key_fname, passwd, passwd_len) != 0) {
			retval = -1;
			fprintf(stderr, "error: failed to decrypt cipher file %s to plain file %s\n", cipher_fname, plain_fname);
			fflush(stderr);
			goto err_decrypt;
		}
		double dt = bench_end(&bench);
		printf("finished decrypting in %.3g sec (%.3g MB/sec)\n", dt, sb_cipher.st_size / (dt * 1e6));
		fflush(stdout);
	} else {
		printf("creating new cipher file at %s...\n", cipher_fname);
		fflush(stdout);

		if (create_file(cipher_fname) != 0) {
			retval = -1;
			fprintf(stderr, "error: failed to create cipher file %s\n", cipher_fname);
			fflush(stderr);
			goto err_decrypt;
		}
	}

	struct stat sb_before;
	if (stat(plain_fname, &sb_before) != 0) {
		retval = -1;
		fprintf(stderr, "error: failed to stat plain file %s\n", plain_fname);
		fflush(stderr);
		goto err_sig;
	}

	/* wait for signal */
	sigset_t sigset;
	if (sigemptyset(&sigset) != 0) {
		retval = -1;
		fprintf(stderr, "error: sigemptyset()\n");
		fflush(stderr);
		goto err_sig;
	}
	if (sigaddset(&sigset, SIGTERM) != 0 || sigaddset(&sigset, SIGINT) != 0 || sigaddset(&sigset, SIGHUP) != 0) {
		retval = -1;
		fprintf(stderr, "error: sigaddset()\n");
		fflush(stderr);
		goto err_sig;
	}
	if (sigprocmask(SIG_BLOCK, &sigset, NULL) != 0) {
		retval = -1;
		fprintf(stderr, "error: sigprocmask()\n");
		fflush(stderr);
		goto err_sig;
	}
	printf("data ready (ctrl-c when done)\n");
	fflush(stdout);
	if (sigwait(&sigset, &sig) != 0) {
		retval = -1;
		fprintf(stderr, "error: sigwait()\n");
		fflush(stderr);
		goto err_sig;
	}

	struct stat sb_after;
	if (stat(plain_fname, &sb_after) != 0) {
		retval = -1;
		fprintf(stderr, "error: failed to stat plain file %s\n", plain_fname);
		fflush(stderr);
		goto err_finalize;
	}
	if (sb_after.st_mtime > sb_before.st_mtime || !cipher_file_exists) {
		printf("\nencrypting %s -> %s...\n", plain_fname, cipher_fname);
		fflush(stdout);

		bench_start(&bench);
		if (encrypt_cipher_file(plain_fname, tmp_cipher_file.fname, key_fname, passwd, passwd_len, rng) != 0) {
			retval = -1;
			fprintf(stderr, "error: failed to encrypt %s -> %s\n", plain_fname, tmp_cipher_file.fname);
			fflush(stderr);
			goto err_finalize;
		}
		double dt = bench_end(&bench);
		printf("finished encrypting in %.3g sec (%.3g MB/sec)\n", dt, sb_after.st_size / (dt * 1e6));
		fflush(stdout);

		if (rename(tmp_cipher_file.fname, cipher_fname) != 0) {
			retval = -1;
			fprintf(stderr, "error: failed to rename %s -> %s\n", tmp_cipher_file.fname, cipher_fname);
			fflush(stderr);
			goto err_finalize;
		}
	} else {
		printf("\nplain file unmodified\n");
		fflush(stdout);
	}

	printf("cleaning up...\n");
	fflush(stdout);

err_finalize:
err_sig:
	if (retval != 0 && !cipher_file_exists) {
		/* file was created by this program since it didn't exist, but we have error so delete it */
		unlink(cipher_fname);
	}
err_decrypt:
	tmp_file_destroy(&tmp_cipher_file);
err_tmp_cipher_file:
	unlink(plain_fname);
err_create_plain:
	erase_buf(passwd_check, PASSWDLEN);
err_passwd_check:
	erase_buf(passwd, PASSWDLEN);
err_passwd:
	quirky_rng_free(rng);
err_rng:
	if (retval == 0) {
		printf("success\n");
	}
	return retval;
}
