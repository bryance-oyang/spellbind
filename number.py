import mistrng
import multiprocessing

def gcd(a: int, b: int):
    assert a > 0
    assert b > 0
    if a > b:
        r0 = a
        r1 = b
    else:
        r0 = b
        r1 = a

    while True:
        r2 = r0 % r1
        if r2 == 0:
            return r1
        r0 = r1
        r1 = r2

def modinv(e: int, modulus: int):
    assert modulus > 0
    assert e > 0
    e = e % modulus

    r0 = modulus
    r1 = e
    s0 = 1
    s1 = 0
    t0 = 0
    t1 = 1

    while True:
        q = r0 // r1
        r2 = r0 - q*r1
        if r2 == 0:
            if r1 == 1:
                return ((t1 % modulus) + modulus) % modulus
            else:
                return 0

        s2 = s0 - ((q*s1) % modulus)
        t2 = t0 - ((q*t1) % modulus)

        r0 = r1
        r1 = r2
        s0 = s1
        s1 = s2
        t0 = t1
        t1 = t2

def modpow(base: int, exponent: int, modulus: int):
    assert base >= 0
    assert exponent >= 0
    assert modulus > 0

    base = base % modulus
    result = 1
    running = base

    while exponent > 0:
        if exponent & 1 == 1:
            result = (result * running) % modulus

        running = (running * running) % modulus
        exponent >>= 1

    return result

def miller_rabin(p: int, iterations: int=1):
    rng = mistrng.MistRNG(str(p).encode("utf-8"))

    d = p - 1
    s = 0
    while d & 1 == 0:
        s += 1
        d >>= 1

    def probable_prime() -> bool:
        a = rng.randrange(2, p - 1)
        ad = modpow(a, d, p)
        if ad == 1:
            return True
        if ad == p - 1:
            return True
        for _ in range(1, s):
            ad = (ad * ad) % p
            if ad == p - 1:
                return True
        return False

    for _ in range(iterations):
        if not probable_prime():
            return False
    return True

def find_any_prime(start: int):
    if start < 4:
        return 3

    p = start | 1
    while True:
        if miller_rabin(p):
            return p
        p += 2

def find_safe_prime(start: int):
    if start < 4:
        return 3

    p = start | 1
    q = 2*p + 1
    while True:
        if miller_rabin(p) and miller_rabin(q):
            return q
        p += 2
        q += 4

def _parallel_find_any_prime(lock, p: int, nprocess: int, keep_running, result):
    while keep_running.is_set():
        if miller_rabin(p):
            lock.acquire()
            if keep_running.is_set():
                result.append(p)
                keep_running.clear()
            lock.release()
            return
        p += 2*nprocess

def parallel_find_any_prime(start: int, ncpu: int):
    if start < 4:
        return 3
    p = start | 1
    processes = []
    manager = multiprocessing.Manager()
    lock = manager.Lock()
    keep_running = manager.Event()
    keep_running.set()
    result = manager.list()
    for rank in range(ncpu):
        process = multiprocessing.Process(target=_parallel_find_any_prime,
                    args=(lock, p + 2*rank, ncpu, keep_running, result))
        processes.append(process)
        process.start()
    for process in processes:
        process.join()
    return result[0]


def _parallel_find_safe_prime(lock, p: int, nprocess: int, keep_running, result):
    while keep_running.is_set():
        q = 2*p + 1
        if miller_rabin(p) and miller_rabin(q):
            lock.acquire()
            if keep_running.is_set():
                result.append(q)
                keep_running.clear()
            lock.release()
            return
        p += 2*nprocess
        q += 4*nprocess

def parallel_find_safe_prime(start: int, ncpu: int):
    if start < 4:
        return 3
    p = start | 1
    processes = []
    manager = multiprocessing.Manager()
    lock = manager.Lock()
    keep_running = manager.Event()
    keep_running.set()
    result = manager.list()
    for rank in range(ncpu):
        process = multiprocessing.Process(target=_parallel_find_safe_prime,
                    args=(lock, p + 2*rank, ncpu, keep_running, result))
        processes.append(process)
        process.start()
    for process in processes:
        process.join()
    return result[0]
