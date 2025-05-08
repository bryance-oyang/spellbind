#ifndef COMMON_H
#define COMMON_H

#define _POSIX_C_SOURCE 200809L

#include "spellbind.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <termios.h>

#define RNG_SEED_MIN_NBYTES (SPELLBIND_SECURITY_LEVEL / 8)

static bool buf_eq(uint64_t nbytes, const uint8_t *a, const uint8_t *b)
{
	volatile bool retval = true;
	volatile bool decoy = true;
	for (uint64_t i = 0; i < nbytes; i++) {
		if (a[i] != b[i]) {
			retval = false;
		} else {
			decoy = false;
		}
	}
	(void)decoy;
	return retval;
}

static void erase_buf(volatile uint8_t *buf, uint64_t buf_nbytes)
{
	for (uint64_t i = 0; i < buf_nbytes; i++) {
		buf[i] = 0;
	}
}

static int create_file(const char *fname)
{
	int fd;
	if ((fd = open(fname, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR)) < 0) {
		fprintf(stderr, "error: create_file(%s) failed\n", fname);
		fflush(stderr);
		return -1;
	}
	if (fsync(fd) != 0) {
		fprintf(stderr, "error: create_file(%s) failed\n", fname);
		fflush(stderr);
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

/* returns true if fname is a regular file */
static bool is_regular_file(const char *fname)
{
	struct stat sb;

	if (stat(fname, &sb) != 0) {
		return false;
	}

	return S_ISREG(sb.st_mode);
}

struct fmap {
	bool read_only;
	uint8_t *map;
	int fd;
	uint64_t nbytes;
};

static int fmap_init(struct fmap *fmap, const char *fname, int64_t truncate_nbytes, bool read_only)
{
	int retval = 0;
	struct stat sb;
	int oflag, mflag;

	fmap->read_only = read_only;
	if (fmap->read_only) {
		oflag = O_RDONLY;
		mflag = PROT_READ;
	} else {
		oflag = O_RDWR;
		mflag = PROT_READ | PROT_WRITE;
	}

	if ((fmap->fd = open(fname, oflag)) < 0) {
		retval = -1;
		fprintf(stderr, "error: failed to open %s\n", fname);
		goto err_open;
	}

	if (truncate_nbytes < 0) {
		if (fstat(fmap->fd, &sb) != 0) {
			retval = -1;
			fprintf(stderr, "error: failed to fstat %s\n", fname);
			goto err_len;
		}
		fmap->nbytes = sb.st_size;
	} else {
		if (ftruncate(fmap->fd, truncate_nbytes) != 0) {
			retval = -1;
			fprintf(stderr, "error: failed to ftruncate %s\n", fname);
			goto err_len;
		}
		fmap->nbytes = truncate_nbytes;
	}

	fmap->map = NULL;
	if (fmap->nbytes > 0 && (fmap->map = mmap(NULL, fmap->nbytes, mflag, MAP_SHARED, fmap->fd, 0)) == NULL) {
		retval = -1;
		fprintf(stderr, "error: failed to mmap %s\n", fname);
		goto err_mmap;
	}

	if (retval != 0) munmap(fmap->map, fmap->nbytes);
err_mmap:
err_len:
	if (retval != 0) close(fmap->fd);
err_open:
	fflush(stderr);
	return retval;
}

static int fmap_sync(const struct fmap *fmap)
{
	if (fmap->read_only) {
		return 0;
	}

	int retval = 0;
	if (fmap->nbytes > 0 && msync(fmap->map, fmap->nbytes, MS_SYNC | MS_INVALIDATE) != 0) {
		retval = -1;
		fprintf(stderr, "error: msync() failed\n");
		goto out;
	}
	if (fsync(fmap->fd) != 0) {
		retval = -1;
		fprintf(stderr, "error: fsync() failed\n");
		goto out;
	}

out:
	return retval;
}

static void fmap_destroy(struct fmap *fmap)
{
	munmap(fmap->map, fmap->nbytes);
	close(fmap->fd);
}

struct tmp_file {
	char *fname;
};

static int tmp_file_create(struct tmp_file *tmp, const char *base_fname)
{
	int retval = 0;
	const char *tmp_ext = ".spell.tmp";
	const uint64_t tmp_ext_len = strlen(tmp_ext);
	uint64_t tmp_fname_nbytes;
	if ((tmp_fname_nbytes = strlen(base_fname) + tmp_ext_len) < tmp_ext_len) {
		retval = -1;
		fprintf(stderr, "error: integer overflow forming tmp fname: concat(%s, %s)\n", base_fname, tmp_ext);
		fflush(stderr);
		goto err_overflow;
	}
	if ((tmp_fname_nbytes += 1) < 1) {
		retval = -1;
		fprintf(stderr, "error: integer overflow forming tmp fname: concat(%s, %s)\n", base_fname, tmp_ext);
		fflush(stderr);
		goto err_overflow;
	}
	if ((tmp->fname = malloc(tmp_fname_nbytes)) == NULL) {
		retval = -1;
		fprintf(stderr, "error: malloc() failed forming tmp fname: concat(%s, %s)\n", base_fname, tmp_ext);
		fflush(stderr);
		goto err_fname;
	}
	int snprintf_retval = snprintf(tmp->fname, tmp_fname_nbytes, "%s%s", base_fname, tmp_ext);
	if (snprintf_retval < 0 || (uint64_t)snprintf_retval >= tmp_fname_nbytes) {
		retval = -1;
		fprintf(stderr, "error: snprintf() failed forming tmp fname: concat(%s, %s)\n", base_fname, tmp_ext);
		fflush(stderr);
		goto err_snprintf;
	}
	if (access(tmp->fname, F_OK) == 0) {
		retval = -1;
		fprintf(stderr, "error: tmp file already exists at %s\n", tmp->fname);
		fflush(stderr);
		goto err_file;
	}
	if (create_file(tmp->fname) != 0) {
		retval = -1;
		fprintf(stderr, "error: failed to create tmp file at %s\n", tmp->fname);
		fflush(stderr);
		goto err_create;
	}


	if (retval != 0) unlink(tmp->fname);
err_create:
err_file:
err_snprintf:
	if (retval != 0) free(tmp->fname);
err_fname:
err_overflow:
	fflush(stderr);
	return retval;
}

static void tmp_file_destroy(struct tmp_file *tmp)
{
	unlink(tmp->fname);
	free(tmp->fname);
}

static int seed_rng(struct quirky_rng *rng, const char *seed_fname, int mode)
{
	int retval = 0;
	int fd;
	struct stat sb;
	uint8_t *entropy;
	uint64_t len;

	if ((fd = open(seed_fname, O_RDONLY)) < 0) {
		retval = -1;
		fprintf(stderr, "error: unable to open rng seed file %s\n", seed_fname);
		goto err_open;
	}
	if (fstat(fd, &sb) != 0) {
		retval = -1;
		fprintf(stderr, "error: unable to fstat rng seed file %s\n", seed_fname);
		goto err_entropy;
	}

	if (mode == 1) {
		len = RNG_SEED_MIN_NBYTES;
	} else {
		len = sb.st_size;
	}

	if (len < RNG_SEED_MIN_NBYTES) {
		retval = -1;
		fprintf(stderr, "error: rng seed file too small %s\n", seed_fname);
		goto err_entropy;
	}

	/* read len bytes into entropy buffer */
	if ((entropy = malloc(len)) == NULL) {
		retval = -1;
		fprintf(stderr, "error: entropy malloc failed\n");
		goto err_entropy;
	}
	uint64_t nbytes_needed = len;
	while (nbytes_needed > 0) {
		int64_t nbytes_read = read(fd, &entropy[len - nbytes_needed], nbytes_needed);
		if (nbytes_read <= 0) {
			retval = -1;
			fprintf(stderr, "error: failed to read entropy file %s\n", seed_fname);
			goto err_read;
		}
		nbytes_needed -= nbytes_read;
	}
	quirky_rng_add_entropy(rng, entropy, len);

err_read:
	erase_buf(entropy, len);
	free(entropy);
err_entropy:
	close(fd);
err_open:
	fflush(stderr);
	return retval;
}

static int get_passwd(uint8_t *passwd_buf, uint64_t buf_nbytes)
{
	erase_buf(passwd_buf, buf_nbytes);

	int retval = 0;
	struct termios old, new;

	if (tcgetattr(STDIN_FILENO, &old) != 0) {
		retval = -1;
		fprintf(stderr, "error: tcgetattr()\n");
		goto err;
	}
	new = old;
	new.c_lflag &= ~(ECHO);
	if (tcsetattr(STDIN_FILENO, TCSANOW, &new) != 0) {
		retval = -1;
		fprintf(stderr, "error: tcsetattr()\n");
		goto err;
	}

	uint64_t i = 0;
	int c;
	while ((c = getchar()) != '\n' && c != EOF && i < buf_nbytes) {
		passwd_buf[i++] = c;
	}
	for (; i < buf_nbytes; i++) {
		passwd_buf[i] = 0;
	}

	if (tcsetattr(STDIN_FILENO, TCSANOW, &old) != 0) {
		retval = -1;
		fprintf(stderr, "error: tcsetattr()\n");
		goto err;
	}
err:
	fflush(stderr);
	return retval;
}

static void bench_start(struct timespec *bench_start_time)
{
#ifndef CLOCK_MONOTONIC_RAW
	clock_gettime(CLOCK_REALTIME, bench_start_time);
#else /* CLOCK_MONOTONIC_RAW */
	clock_gettime(CLOCK_MONOTONIC_RAW, bench_start_time);
#endif /* CLOCK_MONOTONIC_RAW */
}

static double bench_end(struct timespec *bench_start_time)
{
	struct timespec bench_end_time;
#ifndef CLOCK_MONOTONIC_RAW
	clock_gettime(CLOCK_REALTIME, &bench_end_time);
#else /* CLOCK_MONOTONIC_RAW */
	clock_gettime(CLOCK_MONOTONIC_RAW, &bench_end_time);
#endif /* CLOCK_MONOTONIC_RAW */
	return (double)(bench_end_time.tv_sec - bench_start_time->tv_sec)
		+ (double)(bench_end_time.tv_nsec - bench_start_time->tv_nsec) / 1e9;
}

#endif /* COMMON_H */
