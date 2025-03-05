from sage.all import *
from Crypto.Cipher import AES
from subprocess import check_output
import re

p = 2**127 - 1
F = GF(p)
n = 16
b = 63

def flatter(M):
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = check_output(["flatter"], input=z.encode())
    return matrix(M.nrows(), M.ncols(), map(int, re.findall(b"-?\\d+", ret)))

def find_linear_relations(y, r, t):
    assert n < t < r and r + t < len(y)
    Q = matrix(ZZ, [y[i:i+r] for i in range(t)])
    M = block_matrix(ZZ, [[Q.T, 1]])
    return flatter(M)[:3, t:]

def recover_mod(A):
    R = PolynomialRing(ZZ, 'x')
    f1, f2, f3 = [R(row.list()) for row in A]
    r1 = f1.resultant(f2)
    r2 = f1.resultant(f3)
    return ZZ(gcd(r1, r2).factor()[-1][0])

def recover_coefficients(A):
    R = PolynomialRing(F, 'x')
    f1, f2 = R(A[0].list()), R(A[1].list())
    g = f1.gcd(f2)
    return (g.lm() - g).list()

def recover_initial_state(y, c, d):
    C = companion_matrix([-x for x in c] + [1], 'bottom')
    Q = matrix(ZZ, [(C**i)[-1] for i in range(1, d + 1)])
    y = vector(ZZ, y)
    v = 2**b * (Q * y[:n] - y[n:n+d])
    Q = Q.augment(v)
    M = block_matrix(ZZ, [[Q.T, 1], [p, 0]])
    W = diagonal_matrix([2**b] * d + [1] * n + [p])
    L = flatter(M * W) / W
    for z in L:
        if abs(z[-1]) == 1:
            z *= sign(z[-1])
            return vector(F, 2**b * y[:n] + z[d:d+n])

with open('output.py', 'r') as f:
    exec(f.read())

t = 65
r = 175
d = 50

A = find_linear_relations(output, r, t)
c = recover_coefficients(A)
a = recover_initial_state(output, c, d)

C = companion_matrix([-x for x in c] + [1], 'bottom')
k1 = int((C**-2 * a)[0] >> b)
k2 = int((C**-1 * a)[0] >> b)
key = (k1 << 64) + k2

cipher = AES.new(key.to_bytes(16, 'big'), AES.MODE_CTR, nonce=iv)
print(cipher.decrypt(ct))
