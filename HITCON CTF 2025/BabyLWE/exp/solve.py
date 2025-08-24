from sage.all import *
from hashlib import sha256
from Crypto.Cipher import AES
from lll_cvp import reduce_mod_p
from output import A, b, ct

n = 64
m = 200
p = 1048583
F = GF(p)

# idea:
# lwe have b=As+e
# there exists some u,v such e'=u*e+v*one is small, one is vector of all 1
# combine both we have u*b+v*one=u*As+e'
# so e' is a short vector of span(col(A),b,one)

A = matrix(F, m, n, A)
b = vector(F, b)
one = vector(F, [1] * m)

L = A.T.stack(b).stack(one)
rr = reduce_mod_p(L, p)
rr = rr.BKZ(block_size=4, fp="ld")
rr = rr.BKZ(block_size=20)
print(rr[1])  # vector e', small
assert len(set(rr[1])) == 3, "failed QQ"
*_, u, v = L.solve_left(rr[1])
e = (rr[1] - v * one) / u
print(e)  # vector e
s = A.solve_right(b - e)

key = sha256(str(s).encode()).digest()[:24]
aes = AES.new(key[:16], AES.MODE_CTR, nonce=key[-8:])
flag = aes.decrypt(ct)
print(flag)
