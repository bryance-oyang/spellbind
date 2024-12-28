/**
 * @file
 * @brief See sha3.h
 */

#include "spellbind.h"
#include "sha3.h"

void sha3_224(uint8_t *output, const uint8_t *message, uint64_t message_nbytes)
{
	struct keccak_ctx k;
	sha3_224_init(&k);
	sha3(output, &k, message, message_nbytes);
	keccak_erase_state(&k);
}

void sha3_256(uint8_t *output, const uint8_t *message, uint64_t message_nbytes)
{
	struct keccak_ctx k;
	sha3_256_init(&k);
	sha3(output, &k, message, message_nbytes);
	keccak_erase_state(&k);
}

void sha3_384(uint8_t *output, const uint8_t *message, uint64_t message_nbytes)
{
	struct keccak_ctx k;
	sha3_384_init(&k);
	sha3(output, &k, message, message_nbytes);
	keccak_erase_state(&k);
}

void sha3_512(uint8_t *output, const uint8_t *message, uint64_t message_nbytes)
{
	struct keccak_ctx k;
	sha3_512_init(&k);
	sha3(output, &k, message, message_nbytes);
	keccak_erase_state(&k);
}
