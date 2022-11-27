from Crypto.Util.number import *

with open("output.txt") as f:
    exec(f.read())


def f(p):
    return bytes_to_long(str(p).encode())


def factor1(n):
    l = 0
    r = n
    while l + 1 != r:
        m = (l + r) // 2
        mm = bytes_to_long(str(m).encode())
        if m * mm == n:
            break
        elif m * mm > n:
            r = m
        else:
            l = m
    return m, n // m


def factor2(n1, n2):
    n1p = None

    def test_digits(ps, qs):
        nonlocal n1p
        if n1p is not None:
            return False
        p = sum([pi * 10**i for i, pi in enumerate(ps)])
        pp = sum([(48 + pi) * 256**i for i, pi in enumerate(ps)])
        q = sum([pi * 10**i for i, pi in enumerate(qs)])
        qq = sum([(48 + pi) * 256**i for i, pi in enumerate(qs)])
        if p != 0 and p != 1 and n1 % p == 0:
            n1p = p
            return False
        m1 = 10 ** len(ps)
        m2 = 256 ** len(qs)
        return (p * q) % m1 == n1 % m1 and (pp * qq) % m2 == n2 % m2

    def find_ij(ps, qs):
        for i in range(10):
            for j in range(10):
                if test_digits(ps + [i], qs + [j]):
                    yield i, j

    def search(ps, qs):
        for i, j in find_ij(ps, qs):
            search(ps + [i], qs + [j])

    search([], [])
    n2p = bytes_to_long(str(n1p).encode())
    assert n2 % n2p == 0
    return (n1p, n1 // n1p), (n2p, n2 // n2p)


def factor3(n1, n2):
    def try_factor(l, r):
        while l < r:
            m = (l + r) // 2
            if m > 1 and n1 % m == 0:
                return m
            if m * f(n2 // f(m)) < n1:
                l = m + 1
            else:
                r = m - 1

    for i in range(16):
        # brute force top 4 bits of p1
        # because len(str(p1)) must be constant to have monotonic property
        l = i << 508
        r = l + (1 << 508)
        if p1 := try_factor(l, r):
            return (p1, n1 // p1), (f(p1), n2 // f(p1))


p1, q1 = factor1(n1)
assert p1 * q1 == n1
(p2, q2), (p3, q3) = factor2(n2, n3)
assert p2 * q2 == n2
assert p3 * q3 == n3
(p4, q4), (p5, q5) = factor3(n4, n5)
assert p4 * q4 == n4
assert p5 * q5 == n5


def decrypt(c, p, q):
    n = p * q
    d = pow(e, -1, (p - 1) * (q - 1))
    return pow(c, d, n)


ar = [(n1, p1, q1), (n2, p2, q2), (n3, p3, q3), (n4, p4, q4), (n5, p5, q5)]
ar.sort(key=lambda x: x[0], reverse=True)
for n, p, q in ar:
    c = decrypt(c, p, q)
print(long_to_bytes(c).decode())
