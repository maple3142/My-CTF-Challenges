from decimal import *
from Crypto.Util.number import *
from hashlib import sha512
from secret import flag

getcontext().prec = 320

p = getPrime(512)
q = getPrime(512)
r = getPrime(512)


e = 65537
n = p * q * r
m = bytes_to_long(flag.encode() + sha512(flag.encode()).digest())
c = pow(m, e, n)

k = Decimal(p) / Decimal(48763 * q - r)

print(f"{n = }")
print(f"{c = }")
print(f"{k = }")
