# mint_key
Make base64 key file.

1. `make`
2. `./mint_key key_file`

Options:
- `-p` additional keyboard entropy input
- `-s seed_file` seed rng from seed_file

Number of key bits is set by the spellbind library macro
`SPELLBIND_SECURITY_LEVEL`
