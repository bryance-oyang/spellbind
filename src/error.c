/**
 * @file
 * @brief spellbind error handling
 */

#include "spellbind.h"

const char *spellbind_strerr(enum SPELL_RET retval)
{
	switch (retval) {
	case SPELL_SUCCESS:
		return "spellbind: success";
	case SPELL_FAILURE:
		return "spellbind: failure";
	case SPELL_INVALID_INPUT:
		return "spellbind: invalid input";
	case SPELL_INT_OVERFLOW:
		return "spellbind: integer overflow";
	case SPELL_BUF_READ_OVERFLOW:
		return "spellbind: buffer read overflow";
	case SPELL_BUF_WRITE_OVERFLOW:
		return "spellbind: buffer write overflow";
	case SPELL_ALLOC_FAILURE:
		return "spellbind: alloc failure";
	case SPELL_FOPEN_FAILURE:
		return "spellbind: fopen failure";
	case SPELL_FREAD_FAILURE:
		return "spellbind: fread failure";
	case SPELL_FWRITE_FAILURE:
		return "spellbind: fwrite failure";
	case SPELL_NO_MOD_INVERSE:
		return "spellbind: modulo inverse does not exist";
	case SPELL_MAC_ERROR:
		return "spellbind: message authentication code error";
	case SPELL_KEY_ERROR:
		return "spellbind: bad cipher key";
	}
	return "";
}
