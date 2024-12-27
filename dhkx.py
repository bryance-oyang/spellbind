import mistrng
from number import find_safe_prime, parallel_find_safe_prime

class DHPublicKey:
    g: int
    N: int

def dh_fieldgen(seed: bytes, bits: int=2048, ncpu: int=1) -> DHPublicKey:
    rng = mistrng.MistRNG(seed)

    key = DHPublicKey()
    pstart = rng.randrange(1 << (bits - 1), 1 << bits)
    if ncpu == 1:
        key.N = find_safe_prime(pstart)
    else:
        key.N = parallel_find_safe_prime(pstart, ncpu)

    h = rng.randrange(2, key.N - 1)
    key.g = (h * h) % key.N

    return key

def dh_secretgen(seed: bytes, public: DHPublicKey) -> int:
    rng = mistrng.MistRNG(seed)

    q = public.N >> 1
    bits = 0
    while q > 0:
        bits += 1
        q >>= 1

    lower = max(2, 1 << (bits // 2))
    upper = max(lower + 1, q - lower)
    return rng.randrange(lower, upper)
