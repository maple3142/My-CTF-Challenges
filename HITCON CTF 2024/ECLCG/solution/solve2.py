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

# so we define diff_k = vector([k - k_next for k, k_next in zip(ks, ks[1:])])
# so diff_k = v1 + d * v2 (mod q)
# apply orthogonal lattice attack on v1, v2 to recover a basis of diff_k

ortho = find_ortho_fp(q, v1, v2)
ortho2 = find_ortho_fp(q, *ortho)  # diff_k in row space of ortho2
print("ortho2 dim", ortho2.dimensions())  # (n - 1, n - 1)

# note that a*diff_k[:-1] - diff_k[1:] = 0 (mod p)  (i.e. linear dependent)
# so their kernel are same: v*diff_k[:-1] = 0 (mod p) -> v*diff_k[1:] = 0 (mod p)
# so there would be some v that are small, and still satisfy the equation
# note that the kernel space have 1 larger dimension than in regular ECDSA because the linear dependency
# so short vectors in kernel will be smaller -> smaller v

# and diff_k=ortho2.T*mu  (viewing as column vector here, diff_k in column space of ortho2.T)
# so a*ortho2.T[:-1]*mu = ortho2.T[1:]*mu (mod p)
# since we already know mu is small, we hope to find something that is orthogonal to mu in ZZ
# this can be done by reducing both ortho2.T[:-1] and ortho2.T[1:] at the same time
# i.e. find some l that l*ortho2.T[:-1] and l*ortho2.T[1:] are small
# directly reducing them doesn't work, but chossing a random prime p2 != q and reduce them mod p2 works :shrug:
# and the resulting basis is just a bunch of small vectors that are orthogonal to mu
# while the system is still not full rank, since mu are small, just LLL it!


def reduce_mod_p(p, M):
    Me = M.change_ring(Zmod(p)).echelon_form()
    nr, nc = Me.dimensions()
    L = Me.change_ring(ZZ).stack(
        matrix.zero(nc - nr, nr).augment(matrix.identity(nc - nr) * p)
    )
    return flatter(L)


# can be non-prime either, but it would make echelon_form calculation harder
# just need to be larger than expected values in T
magic_random_prime = 2**255 - 19
T = reduce_mod_p(magic_random_prime, ortho2.T[:-1].augment(ortho2.T[1:]))
L2 = []
for row in T[: n - 4]:
    front = row[: n - 1]
    back = row[n - 1 :]
    # front * mu = back * mu = 0
    L2.append(front)
    L2.append(back)
sol = matrix(L2).T.left_kernel_matrix()[0]  # mu

print(sol)
diff_k = sol * ortho2  # up to sign

dk = diff_k[0]  # k0-k1, up to sign
z0, r0, s0 = sigs[0]
z1, r1, s1 = sigs[1]

# brute force possible signs and recover d
for _ in range(2):
    PR = PolynomialRing(GF(q), ["k1", "d"])
    k1, d = PR.gens()
    k0 = k1 + dk
    I = ideal([s0 * k0 - (z0 + r0 * d), s1 * k1 - (z1 + r1 * d)])
    d = int(I.variety()[0][d])
    P = secp256k1.G * d
    if verify(P, z0, r0, s0):
        break
    dk = -dk
key = sha256(str(d).encode()).digest()
cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
print(cipher.decrypt(ct))
# hitcon{it_is_all_LLL_all_the_way_down?_always_have_been_:)}
