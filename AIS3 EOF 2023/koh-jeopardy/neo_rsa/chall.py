from Crypto.Util.number import bytes_to_long, getPrime, inverse
from hashlib import sha256
import os
from secret import flag

def keygen(b):
    p = getPrime(b)
    q = getPrime(b)
    n = p * q
    e = inverse(p, (p - 1) * (q - 1))
    return n, e


n, e = keygen(1024)
flag += os.urandom(256 - len(flag))
m1 = bytes_to_long(flag)
m2 = bytes_to_long(sha256(flag).digest())
c1 = pow(m1, e, n)
c2 = pow(m2, e, n)

print(f"{n = }")
# No public exponent for you :P
# print(f"{e = }")
print(f"{c1 = }")
print(f"{c2 = }")
