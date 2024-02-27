from sage.all import *
from Crypto.Util.number import *
from secret import p, q, flag

assert isPrime(p) and isPrime(q)
n = p * q
a, b = matrix(ZZ, [[p, 1], [q, 1]]).solve_right(
    vector([p**2 - p**3, q**2 - q**3])
)
E = EllipticCurve(Zmod(n), [a, b])
G = E(p, p) + E(q, q)
C = bytes_to_long(flag) * G

print(f"{a = }")
print(f"{b = }")
print(f"C =", C.xy())
