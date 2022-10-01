from Crypto.Util.number import *

p = getPrime(1024)
q = getPrime(1024)
n = p * q
e = 65537

m = bytes_to_long(open("flag.txt", "rb").read().strip())
c = pow(m, e, n)

pqqp = (pow(p, q, n) + pow(q, p, n)) % n

print(f"{n = }")
print(f"{e = }")
print(f"{c = }")
print(f"{pqqp = }")
