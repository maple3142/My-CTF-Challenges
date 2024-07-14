from sage.all import *
from pwn import process, remote
import random

B = 10**4300
rand = random.Random(1337)

# io = process(["python", "server.py"])
io = remote("zkpof.chal.hitconctf.com", 11111)
io.recvuntil(b"n = ")
n = int(io.recvline().strip().decode())


def oracle(e):
    z = rand.randrange(2, n)
    io.sendlineafter(b"e = ", str(e).encode())
    return b"Exceeds the limit" not in io.recvline()


l = 0
r = 1 << 513
for _ in range(0x137):
    print((l - r).bit_length())
    print(hex(l))
    m = (l + r) // 2
    if oracle(-B // m):
        r = m
    else:
        l = m + 1

p_plus_q = l  # approximation
p_minus_q = isqrt(p_plus_q**2 - 4 * n)  # approximation
p_ap = (p_plus_q + p_minus_q) // 2
x = polygen(Zmod(n))
f = p_ap + x
r = int(f.small_roots(beta=0.499, epsilon=0.03)[0])
p = gcd(n, p_ap + r)
q = n // p
assert p * q == n
print(p, q)
phi = (p - 1) * (q - 1)

for _ in range(floor(13.37)):
    z = rand.randrange(2, n)
    r = 12345
    x = pow(z, r, n)
    io.sendlineafter(b"x = ", str(x).encode())
    io.recvuntil(b"e = ")
    e = int(io.recvline().strip().decode())
    y = r + (n - phi) * e
    io.sendlineafter(b"y = ", str(y).encode())
print(io.recvall().strip().decode())
# hitcon{the_error_is_leaking_some_knowledge}
