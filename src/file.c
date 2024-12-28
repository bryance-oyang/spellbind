/**
 * @file
 * @brief file operations
 */

#include "spellbind.h"
#include <stdio.h>
#include <stdlib.h>

/** get number of bytes in file */
enum SPELL_RET spell_fnbytes(uint64_t *nbytes, const char *fname)
{
	FILE *file;
	enum SPELL_RET retval = SPELL_SUCCESS;

	if ((file = fopen(fname, "rb")) == NULL) {
		retval = SPELL_FOPEN_FAILURE;
		goto err_open;
	}
	if (fseek(file, 0, SEEK_END) != 0) {
		retval = SPELL_FREAD_FAILURE;
		goto err_read;
	}
	*nbytes = ftell(file);

err_read:
	fclose(file);
err_open:
	return retval;
}

/** read nbytes from file into out */
enum SPELL_RET spell_fread(uint8_t *out, uint64_t nbytes, const char *fname)
{
	FILE *file;
	enum SPELL_RET retval = SPELL_SUCCESS;

	if ((file = fopen(fname, "rb")) == NULL) {
		retval = SPELL_FOPEN_FAILURE;
		goto err_open;
	}
	if (fread(out, 1, nbytes, file) != nbytes) {
		retval = SPELL_FREAD_FAILURE;
		goto err_read;
	}

err_read:
	fclose(file);
err_open:
	return retval;
}

/** write nbytes of buf to fname */
enum SPELL_RET spell_fwrite(const char *fname, const uint8_t *buf, const uint64_t nbytes)
{
	FILE *file;
	enum SPELL_RET retval = SPELL_SUCCESS;

	if ((file = fopen(fname, "wb")) == NULL) {
		retval = SPELL_FOPEN_FAILURE;
		goto err_open;
	}
	if (fwrite(buf, 1, nbytes, file) != nbytes) {
		retval = SPELL_FWRITE_FAILURE;
		goto err_write;
	}
	if (fflush(file) != 0) {
		retval = SPELL_FWRITE_FAILURE;
		goto err_write;
	}

err_write:
	fclose(file);
err_open:
	return retval;
}
