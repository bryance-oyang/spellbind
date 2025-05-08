#include "test.h"

#include "base64.h"
#include "dhkx.h"
#include "ecc.h"
#include "kdf.h"
#include "mistify.h"
#include "number.h"
#include "rng.h"
#include "rsa.h"
#include "sha3.h"

void bench()
{
	run_test("dh bench", dh_bench);
	run_test("kdf bench", kdf);
	run_test("rng bench", rng_bench);
}

int main()
{
	run_test("arithmetic", test_arithmetic);
	run_test("b64", test_b64);
	run_test("dhkx", test_dhkx);
	run_test("ecc", test_ecc);
	run_test("mistify", test_mistify);
	run_test("mistify_file", test_mistify_file);
	run_test("power", test_pow);
	run_test("rsa", test_rsa);
	run_test("sha3", test_sha3);
	run_test("big_serialize", test_big_serialize);

	bench();
	printf("\nAll tests passed!\n");
	return 0;
}
