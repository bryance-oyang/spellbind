import mistrng
from number import *

class RSAPrivateKey:
    e: int
    d: int
    N: int
    p: int
    q: int

class RSAPublicKey:
    e: int
    N: int

def rsa_keygen(seed: bytes, bits: int=4096, safe: bool=False, ncpu: int=1) -> RSAPrivateKey:
    if ncpu == 1:
        if safe:
            find_prime = find_safe_prime
        else:
            find_prime = find_any_prime
    else:
        if safe:
            find_prime = lambda start: parallel_find_safe_prime(start, ncpu)
        else:
            find_prime = lambda start: parallel_find_any_prime(start, ncpu)

    rng = mistrng.MistRNG(seed)

    tmp = bits
    bitsofbits = 0
    while tmp > 0:
        tmp >>= 1
        bitsofbits += 1

    pqbits = bits // 2
    pqsep = 1 << (bits // 3)
    while True:
        key = RSAPrivateKey()

        pstart = rng.randrange(1 << (pqbits - 1), 1 << pqbits)
        qstart = rng.randrange(1 << (pqbits - 1), 1 << pqbits)
        if max(pstart, qstart) - min(pstart, qstart) < pqsep:
            continue

        key.p = find_prime(pstart)
        key.q = find_prime(qstart)
        if max(key.p, key.q) - min(key.p, key.q) < pqsep:
            continue

        elower = 1 << (bitsofbits + 2)
        eupper = max(elower + 1, 1 << (bits - (bitsofbits + 2)))
        estart = rng.randrange(elower, eupper)
        if ncpu == 1:
            key.e = find_any_prime(estart)
        else:
            key.e = parallel_find_any_prime(estart, ncpu)

        key.N = key.p * key.q
        phi_N = (key.p - 1) * (key.q - 1)
        key.d = modinv(key.e, phi_N)
        if key.d < 1:
            continue
        return key

def rsa_publish(private: RSAPrivateKey)-> RSAPublicKey:
    public = RSAPublicKey()
    public.e = private.e
    public.N = private.N
    return public
