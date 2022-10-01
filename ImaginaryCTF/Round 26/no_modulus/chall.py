from Crypto.Util.number import *

n = getPrime(512) * getPrime(512)
es = [getPrime(690) for _ in range(69)]
m = bytes_to_long(open("flag.txt", "rb").read().strip())
cs = [pow(m, e, n) for e in es]


# who needs modulus anyway?
# print(f"{n = }")
print(f"{es = }")
print(f"{cs = }")
