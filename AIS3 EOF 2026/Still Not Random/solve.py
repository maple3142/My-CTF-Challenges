from sage.all import *
from functools import partial
from hashlib import sha256
from chall import msgs
from Crypto.Cipher import AES
from fastecdsa.curve import P384
from fastecdsa.point import Point
from lll_cvp import affine_cvp, polynomials_to_matrix, reduce_mod_p, enum_brute
import hmac
from hashlib import sha256
from output import ct, sigs

p = P384.p
q = P384.q
F = GF(q)

rs, ss = zip(*sigs)
# zs = [int(int.from_bytes(sha256(msg).digest()) % q) for msg in msgs]
es = [
    int.from_bytes(hmac.new(r.to_bytes(1337), msg, sha256).digest()) % q
    for r, msg in zip(rs, msgs)
]

d, k1, *dks = polygens(F, ["d", "k1"] + [f"dk{i}" for i in range(len(msgs) - 1)])
ks = [k1] + [k1 + dk for dk in dks]
eqs = []
for k, e, s in zip(ks, es, ss):
    eqs.append(s - (k + d * e))
res = [f.sylvester_matrix(g, d).det() for f, g in zip(eqs, eqs[1:])]
res2 = [f.sylvester_matrix(g, k1).det() for f, g in zip(res, res[1:])]
M, monos = polynomials_to_matrix(res2)
A = M[:, :-1]
b = -vector(M[:, -1])
s0 = A.solve_right(b)
ker = A.right_kernel_matrix()

kqB = reduce_mod_p(ker, q)
sol = affine_cvp(s0.change_ring(ZZ), kqB, vector([2**255] * (len(msgs) - 1)))


def find_sk(sol, basis):
    d, k1 = polygens(F, ["d", "k1"])
    for v in enum_brute(sol, basis):
        if all([x.bit_length() <= 256 for x in v]):
            print(v)
            print([x.bit_length() for x in v])
            for sgn in (1, -1):
                k2 = k1 + sgn * v[0]
                f = ss[0] - (k1 + d * es[0])
                g = ss[1] - (k2 + d * es[1])
                S = f.sylvester_matrix(g, d).det().univariate_polynomial()
                k1_rec = S.roots(multiplicities=False)[0]
                print(k1_rec)
                if (int(k1_rec) * P384.G).x == rs[0] // p:
                    print("k1_rec", k1_rec)
                    print(basis.solve_left(v - sol))
                    d = (ss[0] - k1_rec) * pow(es[0], -1, q) % q
                    return d


sk = int(find_sk(sol, kqB))
key = (sk & ((1 << 128) - 1)).to_bytes(16)
cipher = AES.new(key, AES.MODE_CTR, nonce=ct[:8])
print(cipher.decrypt(ct[8:]))
