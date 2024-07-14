from sage.all import *
import numpy as np
from lll_cvp import flatter, solve_inequality
import random
from output import ct, shares  # ln -s ./dist/output.txt output.py
from Crypto.Cipher import AES
from hashlib import sha256

p = 65537
n, t = 48, 24

xs, ys = zip(*shares)

# https://mystiz.hk/posts/2022/2022-09-05-balsn/#vss

known = n * 64
unk = n * (2**64 // p).bit_length() + t * p.bit_length()
print(known, unk)
assert known >= unk


A = []
for x in xs:
    A.append([x**i % (2**64) for i in range(t)])
A = matrix(ys).stack(matrix(A).T)
A = A.stack(matrix.identity(n) * -p)
A = A.stack(matrix.identity(n) * 2**64)
# A: (1 + n + 2m) x m
B = matrix.identity(1 + t + n).stack(matrix.zero(n, 1 + t + n))
L = A.augment(B)
print(L.dimensions())
lb = [0] * n + [-1] + [0] * t + [0] * n
ub = [0] * n + [-1] + [p] * t + [2**64 // p + 1] * n
sol = solve_inequality(L, lb, ub)
print(sol)
poly = np.array([int(x) % p for x in sol[n + 1 : n + 1 + t]][::-1])
f = lambda x: int(np.polyval(poly, x) % p)

# not sure why, but constant term often off by one using this method...
diff = [int(f(x)) - y for x, y in shares]
assert len(set(diff)) == 1
poly[-1] -= diff[0]

ks = [f(x) for x in range(t)]
key = sha256(repr(ks).encode()).digest()
cipher = AES.new(key, AES.MODE_CTR, nonce=ct[:8])
print(cipher.decrypt(ct[8:]))
# hitcon{integer_overflow_is_just_a_piece_of_cake_for_LLL!}
