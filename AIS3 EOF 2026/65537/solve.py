from sage.all import *
from output import cs
from tqdm import trange
from sage.groups.generic import bsgs

xs = list(range(65537, 65537 + 87))
M = (
    matrix([[x**i for i in range(37)] for x in xs])
    .left_kernel_matrix(basis="LLL")
    .BKZ()
)
print(M[0])
print(M[1])


def clean(n):
    P = prod(prime_range(2, 2**20))
    while (g := gcd(n, P)) != 1:
        n //= g
    return n


def get_n_mul(row, nmul=None):
    R = ZZ if nmul is None else Zmod(nmul)
    pos = ZZ(prod([R(c) ** x for c, x in zip(cs, row) if x > 0]))
    neg = ZZ(prod([R(c) ** (-x) for c, x in zip(cs, row) if x < 0]))
    return (pos - neg) // gcd(pos, neg)


n0 = get_n_mul(M[0])
print(n0.bit_length())
n1 = get_n_mul(M[1])
print(n1.bit_length())
n = clean(gcd(n0, n1))
print(n.bit_length())

R = Zmod(n)
cs = [R(c) for c in cs]

V = matrix.vandermonde(xs[:37])
d = V.det()
invVd = ~V * d

mdc = [prod([c**x for c, x in zip(cs, row)]) for row in invVd]

mdc0 = mdc[0]
mdc1 = mdc[1]

candidates = []
tbl = {}
t = R(1)
for i in trange(65537):
    tbl[t] = i
    t *= mdc0
t = R(1)
for i in trange(65537):
    if t in tbl and not (i == 0 == tbl[t]):
        c0 = i
        c1 = tbl[t]
        print(f"{c0 = }")
        print(f"{c1 = }")
        candidates.append((c0, c1))
    t *= mdc1

for cand in candidates:
    c0, c1 = cand
    coef = [c0, c1]
    try:
        for mdcx in mdc[2:]:
            cx = bsgs(mdc0, mdcx**c0, bounds=(ZZ(0), ZZ(65537)))
            coef.append(cx)
        print(coef)
        break
    except ValueError:
        pass

f = PolynomialRing(ZZ, "x")(coef)
ys = [f(x) for x in xs]

e0 = ys[0]
i = next(i for i, y in enumerate(ys) if gcd(e0, y) == 1)
ei = ys[i]
_, a, b = xgcd(e0, ei)
m = cs[0] ** a * cs[i] ** b
flag = int(m).to_bytes(1024).strip(b"\x00")
print(flag)
