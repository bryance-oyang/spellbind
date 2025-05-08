# wisp
Temporary decryption into ephemeral file.

1. `make`
2. create base64 `key_file` (e.g. with `mint_key`)
3. `./wisp key_file cipher_file plain_file`
4. read/write `plain_file` to heart's content
5. `ctrl-c` to save ciphertext into `cipher_file`

Suggestion: `plain_file` can be on a `tmpfs`  so it resides entirely in memory.
`mount -t tmpfs -o rw,mode=1777 name /mountpoint` (`mount_tmpfs` on macOS)

Options:
- `-p` additional password input as encryption key
- `-s seed_file` seed rng from seed_file
