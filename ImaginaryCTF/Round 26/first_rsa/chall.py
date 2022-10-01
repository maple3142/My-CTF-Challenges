from Crypto.Util.number import getPrime, bytes_to_long
from secret import flag

assert flag.startswith(b"ictf{")
assert flag.endswith(b"}")
flag = flag[5:-1]


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
e = 265729
m = bytes_to_long(flag)
c = powmod(m, e, n)

print(f"{n = }")
print(f"{e = }")
print(f"{c = }")
