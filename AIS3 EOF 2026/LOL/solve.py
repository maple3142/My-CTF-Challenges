from sage.all import *
import random
import secrets
from binteger import Bin
from Crypto.Cipher import AES
from output import ct, gift

seq = [int.from_bytes(gift[i : i + 16]) for i in range(0, len(gift), 16)]

F = GF(2)
R, x = F["x"].objgen()

b = 8 * 16
n = 16

plys = [R(Bin(x, n=b).list) for x in seq]

# recurrence length: n+1
M = []
for i in range(len(plys) - n):
    M.append(plys[i : i + n + 1])
M = matrix(M)

g = 0
for _ in range(100):
    g = gcd(g, matrix(random.sample(M.rows(), n + 1)).det())
print(f"{g = }")

f_candidates = [f for f in divisors(g) if f.degree() == b]
print(f"{f_candidates = }")


def qr_right_kernel(M, f):
    F = f.base_ring()
    assert M[0, 0].base_ring() == F, "M and f must be over the same field"
    x = f.parent().gen()

    n = f.degree()

    def el2blk(el):
        return matrix([(el * x**i % f).padded_list(n) for i in range(n)]).T

    def matrix_map(M, f):
        return [[f(x) for x in row] for row in M]

    MF = block_matrix(F, matrix_map(M, el2blk))
    rk = MF.right_kernel_matrix()

    ker = []
    for i in range(0, rk.nrows(), n):
        v = rk[i]
        row = []
        for i in range(0, len(v), f.degree()):
            row.append(R(v[i : i + f.degree()].list()))
        ker.append(row)
    return matrix(ker).T


for f in f_candidates:
    print(f"{f = }")
    try:
        rk = qr_right_kernel(M, f)
        print(rk.dimensions())
        assert M * rk % f == 0
        rec = rk.T[0]
        rec = rec * rec[-1].inverse_mod(f) % f
        for i in range(len(plys) - n):
            assert vector(plys[i : i + n + 1]) * rec % f == 0
        pred = rec[:-1] * vector(plys[-n:]) % f
        print(f"{pred = }")
        key = Bin(pred.padded_list(b)).bytes
        cipher = AES.new(key, AES.MODE_CTR, nonce=ct[:8])
        flag = cipher.decrypt(ct[8:])
        print(flag)
        break
    except Exception as e:
        print(e)
