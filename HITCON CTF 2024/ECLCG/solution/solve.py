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


vs = ["a"] + [f"mu{i}" for i in range(n - 1)]  # n variables
PR = PolynomialRing(ZZ, vs)
a_sym = PR.gens()[0]
mu_sym = vector(PR.gens()[1:])  # n - 1 variables
diff_k_sym = (
    mu_sym * ortho2
)  # each of the polynomial is linear in mu, n - 1 polynomials
eqs = []
for dk1, dk2 in zip(diff_k_sym, diff_k_sym[1:]):
    eq = a_sym * dk1 - dk2  # linear in a*mu and mu
    eqs.append(eq)
# eqs: n - 2 polynomials

print(len(vs), len(eqs))


# same idea as coppersmith
# try to find some polynomials that have (a, mu) as roots over ZZ
M, monos = polynomials_to_matrix(eqs)
Me = M.change_ring(GF(p)).echelon_form()
nr, nc = Me.dimensions()
L = Me.change_ring(ZZ).stack(
    matrix.zero(nc - nr, nr).augment(matrix.identity(nc - nr) * p)
)
L = flatter(L)
new_eqs = list(L * monos)


# first n-4 polynomials in new_eqs have roots (a, mu) over ZZ
# and every polynomial in new_eqs can be written as a*f(mu)+g(mu)=0, with (f, g) being linear polynomials
# since g(mu)/f(mu) is most likely not an integer, f(mu)=g(mu)=0 for first n-4 polynomials
# (not sure why n-4 given there are n-2 polynomials in eqs)
# so we can collect another (undertermined) linear system about mu, and mu is known to be small -> LLL!


def split_poly(a, poly):
    # split a polynomial in the form of a*f(.)+g(.) into (f, g)
    g = poly.subs({a: 0})
    f = ((poly - g) / a).numerator()
    return f, g


a_sym_zz = a_sym.change_ring(ZZ)

linsys_in_mu = []
for poly in new_eqs[: n - 4]:
    f, g = split_poly(a_sym_zz, poly)
    linsys_in_mu.append(f)
    linsys_in_mu.append(g)


mubs = p.bit_length() - ortho2[0][0].bit_length()  # estimated
bounds = {s.change_ring(ZZ): 2**mubs for s in mu_sym}
monos, sol = next(
    solve_underconstrained_equations_general(
        None, linsys_in_mu, bounds, reduction=flatter
    )
)
assert monos == mu_sym
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
