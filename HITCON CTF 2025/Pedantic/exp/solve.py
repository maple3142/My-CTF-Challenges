from sage.all import *
import gzip
import hashlib

from binteger import Bin
from server import (
    G,
    deserialize_proof,
    hash_point,
    hash_points_to_scalars,
    q,
    scalar_bytes,
    serialize_proof,
    verify,
)
from lll_cvp import reduce_mod_p, kannan_cvp

from pwn import process, remote

# io = process(["python", "server.py"])
# io = remote("localhost", 1337)
io = remote("pedantic.chal.hitconctf.com", 1337)
io.recvuntil(b"proof:\n")
proof = deserialize_proof(io.recvlineS().strip())

Grs, zs = zip(*proof)
cs = hash_points_to_scalars(Grs, len(Grs))
Y = (G * zs[0] - Grs[0]) * pow(cs[0], -1, q)
print(Y)  # use this as input to the golang solver to get solution_with_z.txt

F = GF(q)
a = F(1337)
b = F(7331)
c = int(-b / (a - 1))  # fixed opint
assert a * c + b == c


m = 64
zs = list(range(m))
Grs = [G * z - Y * c for z in zs]
hs = [hash_point(Gr) for Gr in Grs]
L = matrix(F, hs)
rhs = vector(F, [c])

# we want to find a short, positive solution to L * ? = rhs
s0 = L.solve_right(rhs).change_ring(ZZ)
ker = reduce_mod_p(L.right_kernel_matrix(), q)
# solution has form s0 + x * ker ~= [20] * m
# so we compute cvp(ker, [20] * m - s0), and add s0 back
t = s0 + kannan_cvp(ker, vector([20] * m) - s0)
print(t, sum(t))
assert L * t == rhs
assert all([x >= 0 for x in t])

Grs = sum([[Gr] * x for Gr, x in zip(Grs, t)], [])
zs = sum([[z] * x for z, x in zip(zs, t)], [])

proof = list(zip(Grs, zs))
assert verify(Y, proof) == sum(t)

io.sendline(serialize_proof(proof).encode())
print(io.recvallS().strip())
