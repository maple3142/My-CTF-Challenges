from sage.all import *
from Crypto.Util.number import *
import os, random, time
from functools import reduce
import itertools
from subprocess import check_output
from re import findall
from tqdm import tqdm, trange
from output import *  # rename outupt.txt to output.py


def flatter(M):
    # compile https://github.com/keeganryan/flatter and put it in $PATH
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = check_output(["flatter"], input=z.encode())
    return matrix(M.nrows(), M.ncols(), map(int, findall(b"-?\\d+", ret)))


def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])


def small_polys(
    N,
    f,
    bounds,
    m=1,
    d=None,
    roots=None,
    unknown_divisor=None,
    lattice_reduction=None,
    verbose=False,
):
    verbose = (lambda *a: print("[small_roots]", *a)) if verbose else lambda *_: None

    if d is None:
        d = f.degree()

    R = f.base_ring()
    f = f.change_ring(ZZ)

    # f0 = f
    # f = f.univariate_polynomial().monic()
    # f = f.parent([x % N for x in f]).change_ring(ZZ)
    # f = f0.parent()(f)

    shifts = []
    for i in range(m + 1):
        base = N ** (m - i) * (f**i)
        for sh in itertools.product(range(d), repeat=f.nvariables()):
            g = base * prod(map(power, f.variables(), sh))
            shifts.append(g)

    B, monomials = Sequence(shifts, f.parent()).coefficient_matrix()
    monomials = vector(monomials)

    factors = [monomial(*bounds) for monomial in monomials]
    for i, factor in enumerate(factors):
        B.rescale_col(i, factor)

    verbose("Lattice dimensions:", B.dimensions())
    lattice_reduction_timer = time.time()
    if lattice_reduction:
        B = lattice_reduction(B.dense_matrix())
    else:
        B = B.dense_matrix().LLL(algorithm="NTL:LLL_XD")
    verbose(f"Lattice reduction took {time.time() - lattice_reduction_timer:.3f}s")

    B = B.change_ring(QQ)
    for i, factor in enumerate(factors):
        B.rescale_col(i, 1 / factor)
    B = B.change_ring(ZZ)
    H = Sequence([h for h in B * monomials if not h.is_zero()])
    if roots:
        print("Debug: checking if the polynomials have the given roots over ZZ")
        div = N
        if unknown_divisor:
            div = unknown_divisor
        for h in H:
            of = h(*roots) // div**m
            if of.bit_length() < 5:
                print(h(*roots) == 0, f"{of = }")
            else:
                print(h(*roots) == 0, f"{of.bit_length() = }")
            if h(*roots) == 0:
                print(repr(h)[:300])
    return H


n_msgs = 4
n_keys = 100
e = 11
n_size = 1024
assert len(pubs) == n_keys

P = ZZ(prod(pubs))
T = [
    (P // n) * inverse_mod(P // n, n)
    for n in tqdm(pubs, desc="Compute CRT coefficients")
]
R = PolynomialRing(ZZ, 1, "x")
x = R.gen()
ff = 0
for i in trange(len(pubs), desc="Constructing polynomial"):
    f = 1
    for a, b, c in cts[i]:
        res = (a * x + b) ** e - c
        f *= res
    ff += T[i] * f
ff = ff * inverse_mod(ff.coefficient({x: ff.degree()}), P) % P
print(ff.degree())
H = small_polys(
    P,
    ff,
    bounds=(2**n_size,),
    m=1,
    lattice_reduction=flatter,
    verbose=True,
)
roots = H[0].univariate_polynomial().roots(multiplicities=False)
print(roots)
flag = reduce(xor, map(long_to_bytes, map(int, roots)))
print(flag)
