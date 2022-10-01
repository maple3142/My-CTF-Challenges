from sage.all import *
from Crypto.Util.number import *


def powmod(a, b, c):
    if b == 0:
        return 1
    h = powmod(a, b // 2, c)
    t = h ^ 2
    if b & 1:
        t *= a
    return t % c


p = getPrime(1024)
q = getPrime(1024)
n = p * q
# e = 65537
# e = 270337
# e = 270593
e = 0b1000000111000000001
d = pow(e, -1, (p - 1) * (q - 1))

Z = ZZ
P = PolynomialRing(Z, "y", 1 + e.bit_length())
x, *ys = list(P.gens())
it = iter(ys)


def powmod_sage(a, b, c):
    if b == 0:
        return 1
    h = powmod_sage(a, b // 2, c)
    t = h + 2 * next(it)
    if b & 1:
        t *= a
    return t


# f = powmod_sage(123456, e, n)
f = powmod_sage(x, e, n)

m = bytes_to_long(b'ictf{^_is_not_power_operator...}')
ar = []


def powmod2(a, b, c):
    if b == 0:
        return 1
    h = powmod2(a, b // 2, c)
    t = h ^ 2
    if (h >> 1) & 1:
        ar.append(-1)
    else:
        ar.append(1)
    if b & 1:
        t *= a
    return t % c


c = powmod2(m, e, n)
f([x] + ar)


# for i in range(1, 20):
#     mm = ZZ(ZZ(c)//i).nth_root(2, truncate_mode=True)[0]
#     print(long_to_bytes(mm))

from itertools import product


Z = Zmod(n)
Z = ZZ
P = PolynomialRing(Z, "x")
x = P.gen()

for aa, bb, cc, dd, ee in product(range(-1, 1), repeat=5):
    poly = (
        (2 * x ** 5 * aa + x ** 5)
        + (2 * x ** 4 * bb)
        + (2 * x ** 3 * cc)
        + (2 * x ** 2 * dd)
        + (2 * x ** 1 * ee)
        - c
    )
    rs = poly.roots()
    if len(rs) > 0 and rs[0][0] > 0:
        print(long_to_bytes(int(rs[0][0])))
        break
