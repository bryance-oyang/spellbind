/**
 * @file
 * @brief Command line utility to make random key and save base64
 * encoded key to key_fname
 */

#include "common.h"
#include <string.h>

#define KEYLEN (SPELLBIND_SECURITY_LEVEL / 8)
#define PASSWDLEN 1024
#define SALTLEN (SPELLBIND_SECURITY_LEVEL / 8)
#define KDF_NITER 65536

const char *usage = "Usage: mint_key [-p] [-s seed_fname] key_fname\n"
	"\t-p\n\t\tUse additional entropy from keyboard\n\n"
	"\t-s seed_fname\n\t\tUse seed_fname as a seed for the random number generator\n"
	"\t-d\n\t\tFor device files: limit number of bytes read from seed_fname to compiled security level\n";
char *seed_fname_arg = NULL;
char *key_fname_arg = NULL;
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
	if (argc < 1 || key_fname_arg != NULL) {
		return -1;
	}
	key_fname_arg = argv[0];
	return 1;
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
	if (parse_args(argc - 1, &argv[1]) < 0 || key_fname_arg == NULL) {
		fprintf(stderr, "%s", usage);
		return -1;
	}

	const char *const urandom_fname = "/dev/urandom";
	const char *const seed_fname = seed_fname_arg;
	const char *const key_fname = key_fname_arg;

	if (access(key_fname, F_OK) == 0) {
		fprintf(stderr, "file already exists at %s\n", key_fname);
		return -1;
	}

	int retval = 0;
	enum SPELL_RET spell_ret;
	int fd;
	uint8_t passwd[PASSWDLEN];
	uint8_t salt[SALTLEN];
	uint8_t key[KEYLEN];
	uint8_t *b64;
	uint64_t b64_len;
	struct quirky_rng *rng;
	bool urandom_exists;

	urandom_exists = (access(urandom_fname, F_OK) == 0);

	if (!urandom_exists) {
		printf("warning: /dev/urandom doesn't exist\n");
		fflush(stdout);
		if (seed_fname == NULL) {
			fprintf(stderr, "error: seed_fname (-s) not provided: no way to seed rng\n");
			fflush(stderr);
			return -1;
		}
	}

	if ((spell_ret = spell_b64_encode_nbytes(&b64_len, KEYLEN)) != SPELL_SUCCESS) {
		retval = -1;
		fprintf(stderr, "error: spell_b64_encode_nbytes() failed: %s\n", spellbind_strerr(spell_ret));
		goto err_rng;
	}

	if ((rng = quirky_rng_alloc()) == NULL) {
		retval = -1;
		fprintf(stderr, "error: quirky_rng_alloc() failed\n");
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
		goto err_passwd;
	}

	if (use_passwd) {
		printf("additional entropy: ");
		fflush(stdout);
		if (get_passwd(passwd, PASSWDLEN) != 0) {
			retval = -1;
			fprintf(stderr, "error: get_passwd() failed\n");
			fflush(stderr);
			goto err_passwd;
		}
		printf("\n");
		fflush(stdout);

		quirky_rng_rand_bytes(salt, SALTLEN, rng);
		mistify_kdf(salt, SALTLEN, passwd, PASSWDLEN, salt, SALTLEN, KDF_NITER);
		erase_buf(passwd, PASSWDLEN);
		quirky_rng_add_entropy(rng, salt, SALTLEN);
		erase_buf(salt, SALTLEN);
	}

	if ((fd = open(key_fname, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR)) < 0) {
		retval = -1;
		fprintf(stderr, "error: failed to open key file %s\n", key_fname);
		goto err_open;
	}

	if (ftruncate(fd, b64_len) != 0) {
		retval = -1;
		fprintf(stderr, "error: failed to truncate key file %s\n", key_fname);
		goto err_mmap;
	}
	if ((b64 = mmap(NULL, b64_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == NULL) {
		retval = -1;
		fprintf(stderr, "error: failed to mmap key file %s\n", key_fname);
		goto err_mmap;
	}

	quirky_rng_rand_bytes(key, KEYLEN, rng);
	if ((spell_ret = spell_b64_encode(b64, b64_len, key, KEYLEN)) != SPELL_SUCCESS) {
		retval = -1;
		fprintf(stderr, "error: failed to b64 encode to key file %s: %s\n", key_fname, spellbind_strerr(spell_ret));
		goto err_b64_encode;
	}

err_b64_encode:
	erase_buf(key, KEYLEN);
	munmap(b64, b64_len);
err_mmap:
	close(fd);
err_open:
	erase_buf(passwd, PASSWDLEN);
err_passwd:
	quirky_rng_free(rng);
err_rng:
	fflush(stderr);
	return retval;
}
