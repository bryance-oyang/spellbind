from typing import Callable
from hashlib import sha3_512, sha512

class MistRNGBase:
    ratchet: Callable[[bytes], bytes]
    ratchet_bits: int
    ratchet_bytes: int
    counter: int
    state: int

    def __init__(self, ratchet: Callable[[bytes], bytes], ratchet_bits: int, seed: bytes):
        self.ratchet = ratchet
        self.ratchet_bits = ratchet_bits
        self.ratchet_bytes = ratchet_bits // 8
        self.counter = 0
        self.state = int.from_bytes(self.ratchet(b'\x40' + seed))

    def _rand(self) -> bytes:
        l = self.ratchet_bytes
        result = self.ratchet((self.state + self.counter).to_bytes(l))
        self.counter += 1
        self.state ^= int.from_bytes(self.ratchet(b'\x04' + (self.state + self.counter).to_bytes(l)))
        return result

    def add_entropy(self, entropy: bytes):
        l = self.ratchet_bytes
        self.counter += 1
        self.state ^= int.from_bytes(self.ratchet(b'\x60' + (self.state + self.counter).to_bytes(l) + entropy))

    def randrange(self, a: int, b: int):
        if a > b:
            tmp = a
            a = b
            b = tmp
        N = b - a
        if N < 2:
            return a

        tmp = N - 1
        nbits = 0
        while tmp > 0:
            tmp >>= 1
            nbits += 1
        nbytes = (nbits - 1) // 8 + 1

        while True:
            result_str = b''
            while len(result_str) < nbytes:
                result_str += self._rand()
            result = int.from_bytes(result_str)
            result >>= len(result_str)*8 - nbits
            if result < N:
                return a + result

class MistRNG(MistRNGBase):
    def __init__(self, seed: bytes):
        def h(x):
            h2 = int.from_bytes(sha512(x).digest())
            h3 = int.from_bytes(sha3_512(x).digest())
            return (h2 ^ h3).to_bytes(64)
        super().__init__(h, 512, seed)
