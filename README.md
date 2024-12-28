# spellbind

Charming and delightful encryption library and utilities.

* Authenticated stream cipher based on SHA-3/Keccak sponge
* Cryptographically secure pseudo random number generator also based on
SHA-3/Keccak sponge
* Arbitrarily large signed integer arithmetic (very big)
* Number theory operations (primality testing, Montgomery modular arithmetic,
Euclidean algorithm, Chinese remainder theorem)
* Public key cryptography with blinding (RSA, Diffie-Hellman)

## Compiling
Dependencies:
- `src/*` C99
- `app/*` C99 and POSIX (`_POSIX_C_SOURCE >= 200809L`)
- `test/*` `gnu99` dialect or similar
- Makefiles depend on `make`, `gcc`, and `ar`

All require 8, 32, and 64 bit integer types to be available.

`make` makes
- `src/spellbind.so` and `src/spellbind.a` libraries
- `app/...` POSIX command line utilities
- `test/a.out` test code

The compile time macro `SPELLBIND_SECURITY_LEVEL` (default 256) sets the
security level in bits for the library.
