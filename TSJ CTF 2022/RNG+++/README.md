# RNG+++

* Category: Crypto

> This upgraded version of `RNG++`, so you might want to read it before reading this.

## Description

I encrypted the flag and messages by xoring them with a random number generator again. But it should be harder to break this time.

## Overview

Basically same as `RNG++`, but $M$ is a prime this time.

## Solution

Since we only know some bits in each state $s_i$, it can be written as:

$$
s_i = Y_i + \sum_{j} 2^8 u_{ij}
$$

$Y_i$ is a known part of each state and $0 \leq u_{ij} \leq 15$ are unknowns.This is equivalent to this binary representation:

```
0011????0011????0011????0011????0011????...
```

It is easy to see $A s_i + C - s_{i+1} \equiv 0 \pmod{M}$, and trying to substitute $s_i$ with $u_{ij}$ will find out that it is just some linear combination of $u_{ij}$. And the fact $0 \leq u_{ij} \leq 15$ tells us we need to find something **small**, so it isn't too hard to think about lattice.

Using coefficient matrix of those polynomials ($A s_i + C - s_{i+1}$), we can transform this problem into finding closest vector of a lattice. And using Babai Nearest Plane algorithm on a BKZ reduced basis (LLL reduced basis doesn't work well here) allows you to find the correct $u_{ij}$.

```python
from Crypto.Util.number import *
from operator import xor


with open("output.txt") as f:
    lines = f.readlines()
    M, A, C = [ZZ(x) for x in lines[0].strip().split()]
    sz = round(M.log(2))
    cts = [bytes_to_long(bytes.fromhex(line.strip())) for line in lines[1:]]

flagct = cts[0]
cts = cts[1:1+4]
n = len(cts)

mask1 = sum(
    [
        (1 << (7 + 8 * i))
        + (1 << (6 + 8 * i))
        + (1 << (5 + 8 * i))
        + (1 << (4 + 8 * i))
        for i in range(sz // 8)
    ]
)
mask2 = sum([+(1 << (5 + 8 * i)) + (1 << (4 + 8 * i)) for i in range(sz // 8)])
ys = [xor((mask1 & s), mask2) for s in cts]

F = Zmod(M)
# t = F(C / (1 - A))
unames = ",".join(sum([[f"u_{i}_{j}" for j in range(sz // 8)] for i in range(n)], []))
P = PolynomialRing(F, unames)
U = matrix(n, sz // 8, P.gens())
rs = [ys[i] + sum([2 ^ (8 * j) * U[i, j] for j in range(sz // 8)]) for i in range(n)]
fs = [A * r + C - rr for r, rr in zip(rs, rs[1:])]
# rs = [r - t for r in rs]  # substitution
# fs = [A ^ 1 * r - rr for r, rr in zip(rs, rs[1:])]

B, v = Sequence(fs).coefficient_matrix()
print(vector(v))
B = B.T.dense_matrix().change_ring(ZZ)
target = (-B[-1]).list()
B = B[:-1]
a, b = B.dimensions()
print(a, b)
I = matrix.identity(a)
B = block_matrix([[B, I], [M * matrix.identity(b), matrix.zero(b, a)]])
print(B.dimensions())


def Babai_CVP(mat, target):
    # M = mat.LLL()
    M = mat.BKZ(algorithm="NTL", prune=5)
    G = M.gram_schmidt()[0]
    diff = target
    for _ in range(1):
        for i in reversed(range(G.nrows())):
            diff -= M[i] * ((diff * G[i]) / (G[i] * G[i])).round()
    return target - diff


cvp_target = vector(target + [8] * (n * sz // 8))
rr = Babai_CVP(B, cvp_target)
xx = B.solve_left(rr)
print("CVP")
print(rr)
print(xx)
print((rr - cvp_target).norm().n())
print()
found = xx[: n * (sz // 8)]
print(found)

if all(0 <= x < 16 for x in found):
    print("good")
    mat = matrix(n, sz // 8, found)
    ss = [
        ys[i] + sum([2 ^ (8 * j) * mat[i, j] for j in range(sz // 8)]) for i in range(n)
    ]
    print(ss)
    assert (A * ss[0] + C) % M == ss[1]
    flag = long_to_bytes(xor(ZZ(F(ss[0] - C) / A), flagct)).decode()
    print(f"TSJ{{{flag}}}")
```
