#ifndef TEST_BASE64_H
#define TEST_BASE64_H

#include "test.h"

void test_b64()
{
	uint64_t nbytes;
	uint8_t buf[1024];
	char *x, *y;

	x = "light work.";
	y = "bGlnaHQgd29yay4=";
	assert(spell_b64_encode_nbytes(&nbytes, strlen(x)) == SPELL_SUCCESS);
	spell_b64_encode(buf, 1024, (uint8_t *)x, strlen(x));
	assert(ueq(strlen(y), y, buf));

	x = "light work";
	y = "bGlnaHQgd29yaw==";
	assert(spell_b64_encode_nbytes(&nbytes, strlen(x)) == SPELL_SUCCESS);
	spell_b64_encode(buf, 1024, (uint8_t *)x, strlen(x));
	assert(ueq(strlen(y), y, buf));

	x = "light wor";
	y = "bGlnaHQgd29y";
	assert(spell_b64_encode_nbytes(&nbytes, strlen(x)) == SPELL_SUCCESS);
	spell_b64_encode(buf, 1024, (uint8_t *)x, strlen(x));
	assert(ueq(strlen(y), y, buf));

	x = "light wo";
	y = "bGlnaHQgd28=";
	assert(spell_b64_encode_nbytes(&nbytes, strlen(x)) == SPELL_SUCCESS);
	spell_b64_encode(buf, 1024, (uint8_t *)x, strlen(x));
	assert(ueq(strlen(y), y, buf));

	x = "light w";
	y = "bGlnaHQgdw==";
	assert(spell_b64_encode_nbytes(&nbytes, strlen(x)) == SPELL_SUCCESS);
	spell_b64_encode(buf, 1024, (uint8_t *)x, strlen(x));
	assert(ueq(strlen(y), y, buf));

	x = "bGlnaHQgd29yay4=";
	y = "light work.";
	assert(spell_b64_decode(buf, 1024, &nbytes, (uint8_t *)x, strlen(x)) == SPELL_SUCCESS);
	assert(strlen(y) == nbytes);
	assert(ueq(strlen(y), y, buf));

	x = "bGlnaHQgd29yaw==";
	y = "light work";
	assert(spell_b64_decode(buf, 1024, &nbytes, (uint8_t *)x, strlen(x)) == SPELL_SUCCESS);
	assert(strlen(y) == nbytes);
	assert(ueq(strlen(y), y, buf));

	x = "bGlnaHQgd29y";
	y = "light wor";
	assert(spell_b64_decode(buf, 1024, &nbytes, (uint8_t *)x, strlen(x)) == SPELL_SUCCESS);
	assert(strlen(y) == nbytes);
	assert(ueq(strlen(y), y, buf));

	x = "bGlnaHQgd2=y";
	y = "light wor";
	assert(spell_b64_decode(buf, 1024, &nbytes, (uint8_t *)x, strlen(x)) == SPELL_INVALID_INPUT);
	assert(strlen(y) == nbytes);
	assert(!ueq(strlen(y), y, buf));
}

#endif /* TEST_BASE64_H */
