from sage.all import *
from Crypto.Util.number import sieve_base
from pwn import process, remote, context
import ast, re
from itertools import product
from server import ECRSA


# context.log_level = "debug"

# io = process(["python", "server.py"])
io = remote("chal-ezrsa.chal.hitconctf.com", 44444)


def decrypt(x, y):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"C = ", f"{x} {y}".encode())
    return ast.literal_eval(io.recvlineS().strip())


def clean(n, base=sieve_base):
    for p in base:
        while n % p == 0:
            n //= p
    return n


x1, y1 = decrypt(1, 1)
x2, y2 = decrypt(2**2, 2**3)
n = clean(gcd(y1**2 - x1**3, y2**2 - x2**3))
print(f"{n = }")
d = (ZZ(x1) / y1) % n
print(f"{d = }")

# e * d = k (mod n), where k ~= n^0.75
l = 4096
L = matrix(ZZ, [[d, 1], [n, 0]])
bound = [2 ** (ZZ(round(l * 0.75)) + l // 8), 2 ** (l // 8)]
Q = diagonal_matrix([max(bound) // x for x in bound])
L *= Q
L = L.LLL()
L /= Q
L = L.change_ring(ZZ)
for vv in product(range(-10, 10), repeat=2):
    t = vector(vv) * L
    if all([x >= 0 for x in t]) and is_pseudoprime(t[1]):
        e = t[1]
        print(f"{e = }")
        break

kphi = e * d - 1
k = kphi // n
phi = kphi // k
print(f"{phi = }")


def do_factor(n, phi):
    while True:
        try:
            r, m = randint(1, 1000), randint(1, 1000)
            a = (m**2 - r**3) * pow(r, -1, n) % n
            E = EllipticCurve(Zmod(n), [a, 0])
            phi * E(r, m)
        except ZeroDivisionError as ex:
            vs = list(map(ZZ, re.findall("[0-9]+", ex.args[0])))
            g = gcd(vs[0], n)
            if 1 < g < n:
                return g


p = do_factor(n, phi)
q = n // p
print(f"{p = }")
print(f"{q = }")
up = -EllipticCurve(GF(p), [1, 0]).trace_of_frobenius() // 2
vp = abs(EllipticCurve(GF(p), [GF(p)(-1).nth_root(2), 0]).trace_of_frobenius() // 2)
uq = -EllipticCurve(GF(q), [1, 0]).trace_of_frobenius() // 2
vq = abs(EllipticCurve(GF(q), [GF(q)(-1).nth_root(2), 0]).trace_of_frobenius() // 2)
print(f"{up = }")
print(f"{vp = }")
print(f"{uq = }")
print(f"{vq = }")


pub = (n, e)
priv = (p, up, vp, q, uq, vq)
ec = ECRSA(pub, priv)

io.sendlineafter(b"> ", b"3")
for _ in range(16):
    io.recvuntil(b"C = ")
    C = ast.literal_eval(io.recvlineS().strip())
    m = ec.decrypt(C)[1]
    io.sendlineafter(b"m = ", str(m).encode())
io.interactive()
