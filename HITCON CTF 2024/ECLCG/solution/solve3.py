
from sage.all import *
from Crypto.Cipher import AES
from Crypto.Util.number import getPrime
from fastecdsa.curve import secp256k1
from hashlib import sha256
from lll_cvp import (
    flatter,
    solve_underconstrained_equations_general,
    polynomials_to_matrix,
)
from itertools import combinations
from chall import msgs, verify
from output import sigs, nonce, ct

p = getPrime(0x137)  # wtf


def find_ortho_fp(p, *vecs):
    assert len(set(len(v) for v in vecs)) == 1
    L = block_matrix(ZZ, [[matrix(vecs).T, matrix.identity(len(vecs[0]))], [ZZ(p), 0]])
    print("LLL", L.dimensions())
    nv = len(vecs)
    L[:, :nv] *= p
    L = flatter(L)
    ret = []
    for row in L:
        if row[:nv] == 0:
            ret.append(row[nv:])
    return matrix(ret)


G = secp256k1.G
q = secp256k1.q


n = len(sigs)
for i in range(n):
    r, s = sigs[i]
    z = int.from_bytes(sha256(msgs[i]).digest(), "big") % q
    sigs[i] = (z, r, s)

v1 = []
v2 = []

for i in range(n - 1):
    z1, r1, s1 = sigs[i]
    z2, r2, s2 = sigs[i + 1]
    s1i = inverse_mod(s1, q)
    s2i = inverse_mod(s2, q)
    v1.append(s1i * z1 - s2i * z2)
    v2.append(s1i * r1 - s2i * r2)
    # note that s1i * z1 - s2i * z2 + (s1i * r1 - s2i * r2) * d = k1 - k2 (mod q)

v1 = vector(v1)
v2 = vector(v2)


# delta_k = v1 + v2 * d (mod q)
# we want to find a vector lam that lam * k = 0 (over Z) by finding its orthogonal vector of v1, v2 over Z_q
ortho = find_ortho_fp(q, v1[:-1], v2[:-1], v1[1:], v2[1:])
ortho = ortho[:-2]  # arbitrary choice based on testing result

PR = PolynomialRing(ZZ, "x")
polys = []
for row in ortho:
    f = PR(row.list())
    polys.append(f)
# not really used, but show that Stern's attack works
p = gcd([f.resultant(g) for f, g in combinations(polys, 2)])
assert p.is_prime()
F = GF(p)
r0 = set(polys[0].change_ring(F).roots(multiplicities=False))
r1 = set(polys[1].change_ring(F).roots(multiplicities=False))
a = ZZ(r0.intersection(r1).pop())
print(f"{p = }")
print(f"{a = }")


# note that ortho*diff_k[:-1]=0 and ortho*diff_k[1:]=0  (over Z)
nr, nc = ortho.dimensions()
M = ortho.augment(vector([0] * nr)).stack(matrix([0] * nr).T.augment(ortho))
delta_k = M.right_kernel_matrix()[0]
for s in (-1, 1):
    d0 = (s * delta_k - v1)[0] / v2[0] % q
    d1 = (s * delta_k - v1)[1] / v2[1] % q
    if d0 == d1:
        d = d0
        print(f"{d = }")
        break

key = sha256(str(d).encode()).digest()
cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
print(cipher.decrypt(ct))
