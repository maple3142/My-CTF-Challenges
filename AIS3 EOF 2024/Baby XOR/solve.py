from sage.all import *
import secrets
from functools import reduce
from operator import xor
from Crypto.Util.number import bytes_to_long, getPrime, isPrime
from subprocess import check_output
from re import findall


def flatter(M):
    # compile https://github.com/keeganryan/flatter and put it in $PATH
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = check_output(["flatter"], input=z.encode())
    return matrix(M.nrows(), M.ncols(), map(int, findall(b"-?\\d+", ret)))


def xorrrrr(nums):
    n = len(nums)
    result = [0] * n
    for i in range(1, n):
        result = [result[j] ^ nums[(j + i) % n] for j in range(n)]
    return result


def problem_gen(n, b, m_bits):
    mods = [getPrime(b) for i in range(n)]
    muls = [getPrime(m_bits) for i in range(n)]
    secret = secrets.randbelow(2**n)
    print(f"{secret = }")
    hint = [secret * muls[i] % mods[i] for i in range(n)]
    return xorrrrr(mods), hint


n, b, m_bits = 1337, 48, 6
out, hint = problem_gen(n, b, m_bits)


def recover_S_candidates(out):
    R = PolynomialRing(GF(3), "x", b)
    S_sym_bits = list(R.gens())

    seq_sym = []
    for o in out:
        o_bits = [int(x) for x in f"{o:0{b}b}"[::-1]]
        o_xor_b_sym = sum(
            [
                2**i * (y if x == 0 else 1 - y)
                for i, (x, y) in enumerate(zip(o_bits, S_sym_bits))
            ]
        )
        seq_sym.append(o_xor_b_sym)

    x0 = 1 - (out[0] & 1)
    xb1 = 1 - (out[0] >> (b - 1))
    for x1 in (0, 1):  # guess
        seq_prod = [(f - 1) * (f - 2) for f in seq_sym]
        quo = (
            [x**2 - x for x in S_sym_bits]
            + [S_sym_bits[0] - x0]
            + [S_sym_bits[b - 1] - xb1]
            + [S_sym_bits[1] - x1]
        )
        Q = seq_prod[0].parent().quotient(quo)
        seq_prod = [Q(f).lift() for f in seq_prod]
        M, monos = Sequence(seq_prod).coefficient_matrix(sparse=False)
        monos = vector(monos)
        kr = M.right_kernel_matrix()
        print(kr.dimensions())

        sol = next(v for v in kr if v[-1] == 1)
        subs = dict(
            [(m.change_ring(ZZ), ZZ(s)) for m, s in zip(monos, sol) if m.degree() == 1]
        )
        subs[S_sym_bits[0].change_ring(ZZ)] = ZZ(x0)
        subs[S_sym_bits[1].change_ring(ZZ)] = ZZ(x1)
        subs[S_sym_bits[b - 1].change_ring(ZZ)] = ZZ(xb1)
        S_sym_bits_zz = [x.change_ring(ZZ) for x in S_sym_bits]
        S_sym_zz = sum([2**i * x for i, x in enumerate(S_sym_bits_zz)])
        yield S_sym_zz.subs(subs)


for S in recover_S_candidates(out):
    mods = [int(S) ^ int(m) for m in out]
    if all(isPrime(m) for m in mods):
        print(f"{S = }")
        break


def solve_mul_noisy_crt(mods, hint, m_bits=6):
    P = prod(mods)
    T = [(P // p) * inverse_mod(P // p, p) for p in mods]
    L = block_matrix(
        ZZ,
        [
            [ZZ(P), ZZ(0)],
            [matrix(t * h for t, h in zip(T, hint)).T, ZZ(1)],
        ],
    )
    M_approx = 2 ** (m_bits * k)
    bounds = [M_approx * 2**n] + [M_approx // (2**m_bits)] * k
    K = max(bounds)
    Q = matrix.diagonal(ZZ, [K // x for x in bounds], sparse=False)
    L *= Q
    L = flatter(L)
    L /= Q
    result = next(v * sign(v[0]) for v in L if all(x > 0 for x in v * sign(v[0])))
    secret = result[0] // reduce(lcm, result[1:])
    return secret


k = 256
secret = solve_mul_noisy_crt(mods[:k], hint[:k])
print(f"{secret = }")
