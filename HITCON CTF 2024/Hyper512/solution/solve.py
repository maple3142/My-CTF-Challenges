from sage.all import *
from sage.matrix.berlekamp_massey import berlekamp_massey
import secrets, random, sys
from hashlib import sha256
from sage.crypto.boolean_function import BooleanFunction
from functools import lru_cache
from tqdm import tqdm, trange
from chall import MASK1, MASK2, MASK3, MASK4, LFSR, Cipher
from binteger import Bin

F2 = GF(2)
PR = PolynomialRing(F2, "x")
x = PR.gen()

output_file = "output.txt" if len(sys.argv) < 2 else sys.argv[1]

with open(output_file) as f:
    stream = Bin(bytes.fromhex(f.readline())).list
    flag_ct = Bin(bytes.fromhex(f.readline())).list

m = len(stream)


def mask_to_poly(mask, n):
    return PR(list(map(int, f"{mask:0{n}b}"[::-1]))) + x**n


def poly_to_eq(poly):
    return [i for i, v in enumerate(poly) if v]


def poly_to_mask(poly):
    return int(poly.change_ring(ZZ)(2) - 2 ** poly.degree())


def vec_to_state(v):
    return int("".join(map(str, v[::-1])), 2)


@lru_cache
def S(p, t):
    if t == 1:
        return p
    return p * S(p, t - 1) + (1 - p) * (1 - S(p, t - 1))


def find_square_eqs(eq, length):
    # find related equations by squaring
    # i.e. a[k]=a[k+3]+a[k+4] -> a[k]=a[k+6]+a[k+8]
    assert eq[0] == 0, "eq must start with 0 (constant term)"
    eqs = [eq]
    cur_eq = eq
    while True:
        if cur_eq[-1] * 2 >= length:
            break
        squared_eq = [2 * x for x in cur_eq]
        eqs.append(squared_eq)
        cur_eq = squared_eq
    return eqs


def build_equations(eqs, length):
    # given a list of base equations, build all possible equations by shifting
    # and return a list of related equations (by index) for each position
    pos_eqs = [[] for _ in range(length)]
    new_eqs = []
    for eq in tqdm(eqs, "Build equations"):
        assert eq[0] == 0, "eq must start with 0 (constant term)"
        for shift in range(length - max(eq)):
            eq_index = len(new_eqs)
            new_eqs.append(eq)
            for pos in eq:
                pos_eqs[pos].append(eq_index)
            eq = [x + 1 for x in eq]
    return new_eqs, pos_eqs


def find_feasibility(prob, t, pos_eqs):
    def V(p, m, h, s):
        r = 0
        for i in range(h + 1):
            r += binomial(m, i) * (p * s**i * (1 - s) ** (m - i))
        return r

    def W(p, m, h, s):
        r = 0
        for i in range(h + 1):
            r += binomial(m, i) * ((1 - p) * (1 - s) ** i * s ** (m - i))
        return r

    def I(p, m, h, s):
        return W(p, m, h, s) - V(p, m, h, s)

    s = S(prob, t)
    avg_eqs = sum(map(len, pos_eqs)) / len(pos_eqs)
    # avg_eqs = ((m // (2 * n)).bit_length() - 1) * (t + 1)

    max_i = -float("inf")
    max_h = -1
    for h in range(max(map(len, pos_eqs)) + 1):
        ival = I(prob, avg_eqs, h, s)
        if ival > max_i:
            max_i = ival
            max_h = h
    if max_i < 0:
        return False, None
    p_thr = (
        p_star_fn(prob, avg_eqs, max_h, s) + p_star_fn(prob, avg_eqs, max_h + 1, s)
    ) / 2  # this doesn't work for some reason
    return True, p_thr


def p_star_fn(p, m, h, s):
    p1 = p * s**h * (1 - s) ** (m - h)
    p2 = (1 - p) * s ** (m - h) * (1 - s) ** h
    return p1 / (p1 + p2)


def find_candidates(eqs, pos_eqs, stream, p_corr):
    # find candidate positions for noise estimation
    # given equations and related equations for each position
    # as well as the stream and the correlation probability
    length = len(stream)
    t = len(eqs[0])
    s = S(p_corr, t)
    candidates = []  # list of (p_star, pos)
    for pos in trange(length, desc="Find candidates"):
        h = 0  # number of satisfied equations at position pos
        for eq_index in pos_eqs[pos]:
            eq = eqs[eq_index]
            tmp = 0
            for i in eq:
                tmp ^= stream[i]
            h += tmp == 0
        m = len(pos_eqs[pos])
        p1 = p_corr * s**h * (1 - s) ** (m - h)
        p2 = (1 - p_corr) * s ** (m - h) * (1 - s) ** h
        p_star = p1 / (p1 + p2)
        candidates.append((p_star, pos))
    candidates.sort(reverse=True)
    return candidates


def get_linsys(feedback_poly, length):
    n = feedback_poly.degree()
    M = companion_matrix(feedback_poly, "bottom")
    Mn = M**n
    rows = []
    I = matrix.identity(n)
    for i in trange(length // n + 1, desc="Get linear system"):
        rows.extend(I.rows())
        I *= Mn
    return rows


def take_linear_system(linsys, candidates, stream, to_take):
    mat = matrix(GF(2), [linsys[pos] for _, pos in candidates[:to_take]])
    target = []
    for p_star, pos in candidates[:to_take]:
        target.append(stream[pos])
    return mat, vector(GF(2), target)


def solve_fca(feedback_poly, eq, prob, stream):
    stream = stream[:]  # copy
    n = feedback_poly.degree()
    m = len(stream)
    t = len(eq)
    print(f"{S(prob, t) = }")
    eqs = find_square_eqs(eq, m)
    eqs, pos_eqs = build_equations(eqs, m)
    # feasible, _ = find_feasibility(prob, t, pos_eqs)
    # if not feasible:
    #     raise ValueError("Not feasible")
    linsys = get_linsys(feedback_poly, m)
    candidates = find_candidates(eqs, pos_eqs, stream, prob)
    for it in range(100):
        p_thr = candidates[-m // 32][0]
        for p_star, pos in candidates:
            if p_star <= p_thr:
                stream[pos] = 1 - stream[pos]
        candidates = find_candidates(eqs, pos_eqs, stream, prob)

        if it >= 5:
            mat, target = take_linear_system(linsys, candidates, stream, 2 * n)
            try:
                return mat.solve_right(target)
            except ValueError:
                continue


f1 = mask_to_poly(MASK1, 128)
f2 = mask_to_poly(MASK2, 128)
f3 = mask_to_poly(MASK3, 128)
f4 = mask_to_poly(MASK4, 128)
g2 = x**612 + x**421 + 1
g3 = x**518 + x**475 + 1
assert g2 % f2 == 0
assert g3 % f3 == 0

key2 = solve_fca(f2, poly_to_eq(g2), 5 / 8, stream)
key3 = solve_fca(f3, poly_to_eq(g3), 5 / 8, stream)

k2 = vec_to_state(key2)
k3 = vec_to_state(key3)
print(f"{k2 = :#x}")
print(f"{k3 = :#x}")
lfsr2 = LFSR(128, k2, MASK2)
lfsr3 = LFSR(128, k3, MASK3)  # 4x of the original
stream2 = [lfsr2() for _ in range(m)]
stream3 = [lfsr3() for _ in range(m)]
print(
    "correlation stream ~ stream2",
    len([1 for x, y in zip(stream, stream2) if x != y]) / m,
)  # 3/8
print(
    "correlation stream ~ stream3",
    len([1 for x, y in zip(stream, stream3) if x != y]) / m,
)  # 3/8


# when y == z == 1, the output is x ^ w, which is linear
# so we a treat it as a 256-bit LFSR

lfsr1tmp = LFSR(128, 48763, MASK1)
lfsr4tmp = LFSR(128, 48763, MASK4)


def combined():
    x = lfsr1tmp() ^ lfsr1tmp() ^ lfsr1tmp()
    w = lfsr4tmp() ^ lfsr4tmp()
    return x ^ w


f1_cube = (companion_matrix(f1, "bottom") ** 3).charpoly()
f14 = berlekamp_massey([F2(combined()) for _ in range(2048)])
assert f14 == f1_cube * f4
linsys_14 = get_linsys(f14, m)

lhs = []
rhs = []
for i in range(m):
    s, s2, s3 = stream[i], stream2[i], stream3[i]
    if s2 == s3 == 1:
        lhs.append(linsys_14[i])
        rhs.append(s)
        if len(lhs) >= 256 + 10:
            break
key14 = matrix(F2, lhs).solve_right(vector(F2, rhs))
mask14 = poly_to_mask(f14)
k14 = vec_to_state(key14)
print(f"{k14 = :#x}")
lfsr14 = LFSR(256, k14, mask14)
stream14 = [lfsr14() for _ in range(m)]
for i in range(m):
    s, s2, s3, s14 = stream[i], stream2[i], stream3[i], stream14[i]
    if s2 == s3 == 1:
        assert s14 == s, "?????"

# then solve a linear system to get the initial states of LFSR1 and LFSR4 from their XOR

M1 = companion_matrix(f1_cube, "bottom")
M4 = companion_matrix(f4, "bottom")
T = F2**256
s1_0_sym = matrix(T.gens()[:128])
s4_0_sym = matrix(T.gens()[128:])
s1_1_sym = M1**128 * s1_0_sym
s4_1_sym = M4**128 * s4_0_sym
sol = (
    (s1_0_sym + s4_0_sym)
    .stack(s1_1_sym + s4_1_sym)
    .solve_right(vector(F2, stream14[:256]))
)
key1 = list(sol[:128])
key4 = list(sol[128:])
k1 = vec_to_state(key1)
k4 = vec_to_state(key4)
print(f"{k1 = :#x}")
print(f"{k4 = :#x}")
lfsr1 = LFSR(128, k1, poly_to_mask(f1_cube))
lfsr4 = LFSR(128, k4, MASK4)
stream1 = [lfsr1() for _ in range(m)]
stream4 = [lfsr4() for _ in range(m)]


def mix(x, y, z, w):
    return sha256(str((3 * x + 1 * y + 4 * z + 2 * w + 3142)).encode()).digest()[0] & 1


rec = [mix(x, y, z, w) for x, y, z, w in zip(stream1, stream2, stream3, stream4)]
assert rec == stream
for i in range(len(flag_ct)):
    flag_ct[i] ^= mix(lfsr1(), lfsr2(), lfsr3(), lfsr4())

print(Bin(flag_ct).bytes)
# hitcon{larger_states_is_still_no_match_of_fast_correlation_attacks!}
