from sage.all import *
from output import magic_pi, magic_e, obfuscated_keys, ct, iv
from chall import p, magic_op
from Crypto.Cipher import AES
from lll_cvp import flatter
from tqdm import tqdm

F = GF(p)
K = GF(p**2, "a")


def phi(x):
    # https://www.sciencedirect.com/science/article/abs/pii/S0020019010003170
    # p.5 arccos formula
    return x + sqrt(x**2 - 1)


g_pi = K(314159)
g_e = K(271828)
phi_g_pi = phi(g_pi)
phi_g_e = phi(g_e)
assert magic_op(g_pi, p - 1) == 1
assert magic_op(g_e, p + 1) == 1
pm1 = Factorization(factor(p - 1, limit=2**20)[:-1]).prod()
pp1 = Factorization(factor(p + 1, limit=2**20)[:-1]).prod()
cf_pm1 = (p - 1) // pm1
cf_pp1 = (p + 1) // pp1

h_pi = discrete_log(phi(K(magic_pi)) ** cf_pm1, phi_g_pi**cf_pm1, ord=pm1)  # up to sign
h_e = discrete_log(phi(K(magic_e)) ** cf_pp1, phi_g_e**cf_pp1, ord=pp1)  # up to sign
h = min(
    crt([h_pi, h_e], [pm1, pp1]),
    crt([-h_pi, h_e], [pm1, pp1]),
    crt([h_pi, -h_e], [pm1, pp1]),
    crt([-h_pi, -h_e], [pm1, pp1]),
)  # we know it is a sha512 hash, so it would be the smallest
print(h, h.bit_length())
print(factor(h, limit=2**20))
assert h.bit_length() <= 512

e = h // 4
d1 = inverse_mod(e, p - 1)
d2 = inverse_mod(e, p + 1)


def find_root_4(t):
    x = polygen(F)
    return (magic_op(x, 4) - t).roots(multiplicities=False)


pts = []
for c in map(F, tqdm(obfuscated_keys, desc="obfuscated_keys")):
    if magic_op(c, p - 1) == 1:
        pts.extend(find_root_4(magic_op(c, d1)))
    if magic_op(c, p + 1) == 1:
        pts.extend(find_root_4(magic_op(c, d2)))

L = block_matrix(ZZ, [[ZZ(p), ZZ(0)], [matrix(pts).T, matrix.identity(len(pts))]])
L[:, 1:] *= 2**128
L = flatter(L)
L[:, 1:] /= 2**128
v = next(v * sign(v[0]) for v in L if v[0])
print(v)
key = int(v[0]).to_bytes(16, "big")
cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
flag = cipher.decrypt(ct)
print(flag)
