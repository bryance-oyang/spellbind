# dh4096
Generate 4096-bit Diffie-Hellman parameters to stdout.

The parameters are b64 encoded and can be decoded with `spell_b64_decode()`
followed by `dh_param_deserialize()`
