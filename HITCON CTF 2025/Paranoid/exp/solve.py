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

from pwn import process, remote

# io = process(["python", "server.py"])
# io = remote("localhost", 31337)
io = remote("pedantic.chal.hitconctf.com", 31337)
io.sendline(b"hitcon{a_bad_way_to_compose_multi_round_fiat_shamir_lol}")
io.recvuntil(b"proof:\n")
proof = deserialize_proof(io.recvlineS().strip())

Grs, zs = zip(*proof)
cs = hash_points_to_scalars(Grs, len(Grs))
Y = (G * zs[0] - Grs[0]) * pow(cs[0], -1, q)
print(Y)  # use this as input to the golang solver to get solution_with_z.txt


def compute_seq(s, n):
    ret = []
    for _ in range(n):
        ret.append(s)
        s = (s + 1) % q
    return ret


k = 1 << 15
cs = compute_seq(0, k)

solution = []
zs = []
with gzip.open("solution_with_z.txt.gz") as f:
    for line in f:
        a, b = line.split(b" ")
        solution.append(int(a, 16))
        zs.append(int(b))
assert k == len(solution), "solutuon length different"

Grs = [G * z - Y * c for z, c in zip(zs, cs)]
assert hash_point(Grs[0]) == solution[0], "hash does not match"

proof = list(zip(Grs, zs))
print("proof done")
assert verify(Y, proof) == k, "forgery failed"
print("locally verified")

io.sendline(serialize_proof(proof).encode())
print(io.recvallS().strip())
