from sage.all import *
from Crypto.Util.number import *
from pwn import process, remote
from shlex import quote


def clean(n):
    for p in sieve_base:
        while n % p == 0:
            n //= p
    return n


msgs, _, km = load("precomputed.sobj")

# io = process(["python", "server.py"])
io = remote("chal-echo.chal.hitconctf.com", int(22222))

for m in msgs:
    io.sendline(b"1")
    io.sendline(m.encode())
sigs = []
for _ in msgs:
    io.recvuntil(b"Signature: ")
    sigs.append(int(io.recvline().strip()))

nmul1 = prod([s**e for s, e in zip(sigs, km[0]) if e > 0]) - prod(
    [s**-e for s, e in zip(sigs, km[0]) if e < 0]
)
nmul2 = prod([s**e for s, e in zip(sigs, km[1]) if e > 0]) - prod(
    [s**-e for s, e in zip(sigs, km[1]) if e < 0]
)
n = clean(gcd(nmul1, nmul2))
print(n)

m = bytes_to_long(f"echo {quote(msgs[0])}".encode())
s = sigs[0]

ln = 128  # expected message size
mu = 64  # median of ASCII byte values
S = mu * sum([256**i for i in range(ln)])
v = matrix([S - m] + [256**i for i in range(ln)]).T
L = block_matrix([[ZZ(n), ZZ(0)], [v, ZZ(1)]])
target = b"./give me flag please #"
for i, x in enumerate(target):
    L[1, -(i + 1)] = -(x - mu)
L0 = L
bound = [0, 1] + [64] * (ln - len(target)) + [0] * len(target)
Q = matrix.diagonal([2**10 // x if x else 2**20 for x in bound])
L *= Q
print("BKZ")
L = L.BKZ()
L /= Q
vecs = [v * v[1] for v in L if v[1]]  # fix the sign
v = vecs[0]  # pick the shortest one
print(v)
xxs = [x + mu for x in L0.solve_left(v)[2:]]
assert sum([x * 256**i for i, x in enumerate(xxs)]) % n == m
print(xxs)
mm = bytes(xxs)[::-1]
print(mm)
print(mm.decode())
assert bytes_to_long(mm) % n == m
assert b"\n" not in mm

io.sendlineafter(b">", b"2")
io.sendlineafter(b"Enter command:", mm)
io.sendlineafter(b"Enter signature:", str(s).encode())
io.sendline(b"3")
io.interactive()
