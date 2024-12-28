#ifndef TEST_SHA3_H
#define TEST_SHA3_H

#include "test.h"

static void test_sha3()
{
	uint8_t output[1024];
	uint8_t digest[1024];
	const uint8_t *empty = (uint8_t *)"";
	sha3_224(output, empty, 0);
	mkdigest(digest, output, 224);
	assert(ueq(224/8, digest, "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"));

	sha3_256(output, empty, 0);
	mkdigest(digest, output, 256);
	assert(ueq(256/8, digest, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"));

	sha3_384(output, empty, 0);
	mkdigest(digest, output, 384);
	assert(ueq(384/8, digest, "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"));

	sha3_512(output, empty, 0);
	mkdigest(digest, output, 512);
	assert(ueq(512/8, digest, "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"));

	const uint8_t *rate = (uint8_t *)"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
	sha3_224(output, rate, strlen((char *)rate));
	mkdigest(digest, output, 224);
	assert(ueq(224/8, digest, "b85b95646a5019d82d881340f4ed4a97f3c8f7846bb80b34d50086b1"));

	sha3_256(output, rate, strlen((char *)rate));
	mkdigest(digest, output, 256);
	assert(ueq(256/8, digest, "b21a444020bd162b850ca686337175262e41be75d52435000535db805d9aaee4"));

	sha3_384(output, rate, strlen((char *)rate));
	mkdigest(digest, output, 384);
	assert(ueq(384/8, digest, "5fba929cc929e83e8cc650e63225747eb2cd12ef8fd8f19749c731dd4e366c05211bed3e8849dcf3ea8ff61fe62c5f81"));

	sha3_512(output, rate, strlen((char *)rate));
	mkdigest(digest, output, 512);
	assert(ueq(512/8, digest, "a5317f50ccfa1ae1d534c475834443ba0ec4ff345f609def4ec15bca86b0c2e24f28fb9fe1c28f2d946d7923db2cffd999fdebea211b43428cea0072f424ba71"));
}

#endif /* TEST_SHA3_H */
