from sage.all import *
from Crypto.Cipher import AES
from fastecdsa.curve import secp256k1
from hashlib import sha256


G = secp256k1.G
q = secp256k1.q

with open("output.txt") as f:
    exec(f.read())

msgs = [
    b"https://www.youtube.com/watch?v=S8MJvhgjXBY",
    b"https://www.youtube.com/watch?v=wSTbdqo-j74",
    b"https://www.youtube.com/watch?v=dkYHgxfQZBA",
    b"https://www.youtube.com/watch?v=p8ET-m6y6VU",
]

ss = []
for m, (r, s) in zip(msgs, sigs):
    z = int.from_bytes(sha256(m).digest(), "big") % q
    ss.append((z, r, s))

a, b = G.x, G.y
syms = "d," + ",".join([f"k{i}" for i in range(len(ss))])
R = ZZ[syms]
d, *ks = R.gens()
# collect equations
eq_p = []
eq_q = []
for (z, r, s), k in zip(ss, ks):
    eq_q.append(s * k - z - r * d)
eq_q = [f.resultant(g, d) for f, g in zip(eq_q, eq_q[1:])]
for k, kk in zip(ks, ks[1:]):
    eq_p.append(a * k + b - kk)

# build lattice
M, v = Sequence(eq_p + eq_q).coefficient_matrix()
M = M.dense_matrix().T
nr, nc = M.dimensions()
I = matrix.identity(nc)
I[: len(eq_p)] *= p
I[-len(eq_q) :] *= q
M = M.stack(I)
M = M.augment(matrix.identity(nr).stack(matrix.zero(nc, nr)))
M[:, :nc] *= 2**1024
M[:, -1] *= 2**512
# expected vector: [0] * nc + [k0, k1, k2, 2^512]

# LLL!
M = M.LLL()
for row in M:
    if row[-1] < 0:
        row = -row
    if row[:nc] == 0 and row[-1] == 2**512:
        ks = row[-nr:-1]
        assert (a * ks[0] + b) % p == ks[1]
        assert (int(ks[0]) * G).x == sigs[0][0]
        print(ks)
        break

# recover d
z, r, s = ss[0]
k = ks[0]
d = (s * k - z) * pow(r, -1, q) % q
print(d)

# get flag
key = sha256(str(d).encode()).digest()[:16]
cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
print(cipher.decrypt(ct))
