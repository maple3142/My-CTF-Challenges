from pwn import *
from math import gcd, isqrt
from functools import reduce
from Crypto.Util.number import long_to_bytes

# io = process(["python", "server.py"])
io = remote("localhost", 6004)
flagct = int(io.recvlineS())


def encrypt(x):
    io.sendline(str(x).encode())
    return int(io.recvlineS().strip())


xs = [2, 3, 5, 7]
gs = [encrypt(x) ** 2 - encrypt(x * x) for x in xs]
n = reduce(gcd, gs)
print(f"{n = }")
p = isqrt(n)
assert p * p == n
print(f"{p = }")

# (1+p)^e=1+e*p (mod p^2)
e = (encrypt(1 + p) - 1) // p
print(f"{e = }")
d = pow(e, -1, p * (p - 1))
print(long_to_bytes(pow(flagct, d, n)))
