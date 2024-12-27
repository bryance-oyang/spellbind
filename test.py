from number import *
from mistrng import *
from rsa import *
from dhkx import *
import time

class Timer:
    def start(self):
        self.t0 = time.time_ns()
    def stop(self):
        self.t1 = time.time_ns()
        return self
    def print(self):
        print(f"{(self.t1 - self.t0) // 1000000} ms")

if __name__ == "__main__":
    ncpu = 8
    bits = 128
    timer = Timer()

    timer.start()
    key = dh_fieldgen(b'', bits, ncpu)
    timer.stop().print()

    a = dh_secretgen(b'a', key)
    b = dh_secretgen(b'b', key)

    B = modpow(key.g, b, key.N)
    timer.start()
    A = modpow(key.g, a, key.N)
    print(modpow(B, a, key.N))
    timer.stop().print()
