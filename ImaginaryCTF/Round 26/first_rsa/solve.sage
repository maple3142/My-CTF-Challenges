from Crypto.Util.number import long_to_bytes
from itertools import product

with open("output.txt") as f:
    exec(f.read())

Z = Zmod(n)
Z = ZZ
P = PolynomialRing(Z, "x")
x = P.gen()

for aa, bb, cc, dd, ee in product([1, -1], repeat=5):
    poly = (
        (2 * x**5 * aa + x**5)
        + (2 * x**4 * bb)
        + (2 * x**3 * cc)
        + (2 * x**2 * dd)
        + (2 * x**1 * ee)
        - c
    ).monic()
    rs = poly.roots()
    print(aa, bb, cc, dd, ee)
    if len(rs) > 0:
        print(poly)
        print(long_to_bytes(int(rs[0][0])))
        break
