from Crypto.Util.number import *

with open("output.txt") as f:
    exec(f.read())

P = PolynomialRing(ZZ, "x")
x = P.gen()
f = x ^ 2 - pqqp * x + n
p, q = f.roots(multiplicities=False)
assert p * q == n
d = inverse_mod(e, (p - 1) * (q - 1))
m = power_mod(c, d, n)
print(long_to_bytes(m))
