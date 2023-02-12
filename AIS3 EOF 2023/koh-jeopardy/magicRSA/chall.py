from Crypto.Util.number import *
from secret import flag

p = getPrime(1024)
q = getPrime(1024)
n = p * q
e = 65537

m = bytes_to_long(flag)
c = pow(m, e, n)

print(f"{n = }")
print(f"{e = }")
print(f"{c = }")

d = pow(e, -1, (p - 1) * (q - 1))
magic = d + p + q
print(f"{magic = }")
