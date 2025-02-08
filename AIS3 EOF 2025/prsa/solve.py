from sage.all import *
from pwn import process, remote
from Crypto.Util.number import long_to_bytes

io = process(["python", "server.py"])
# io = remote("localhost", 21337)
io.recvuntil(b"c = ")
c = int(io.recvline().strip())


def r2p(c):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"c = ", str(c).encode())
    io.recvuntil(b"c = ")
    return int(io.recvline().strip())


def p2r(c):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"c = ", str(c).encode())
    io.recvuntil(b"c = ")
    return int(io.recvline().strip())


e = 0x10001
n = 0
n = gcd(n, p2r(2) * 2**e - p2r(4))
n = gcd(n, p2r(3) * 2**e - p2r(9))
n = factor(n, limit=2**20)[-1][0]
print(n)
g = 1 + n

cp = r2p(c)
cc = p2r(cp * g)

# pari already implements halfgcd, so let's use it
f1 = pari(f"Mod(x,{n})^{e}-{c}")
f2 = pari(f"(Mod(x,{n})+1)^{e}-{cc}")
g = pari.gcd(f1, f2).sage({"x": polygen(Zmod(n))})

print(long_to_bytes(int(-g[0] / g[1])))
