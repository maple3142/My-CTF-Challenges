from sage.all import *
from output import ct, iv, output
from lll_cvp import (
    reduce_mod_p,
    solve_inequality_ex,
    solve_underconstrained_equations_general,
    kannan_cvp_ex,
    flatter,
    BKZ,
)
from functools import partial
from Crypto.Cipher import AES


p = 2**127 - 1
F = GF(p)


def estimate_ortho_size(n, t, m):
    M = random_matrix(F, n, n)
    v = random_vector(F, n)
    seq = [((M**i) * v)[0] for i in range(m)]
    mat = matrix([seq[i : i + n + t] for i in range(len(seq) - n - t)])
    rkb = reduce_mod_p(
        mat.right_kernel_matrix(), p, reduction=lambda M: BKZ(flatter(M))
    )
    # return abs(rkb[t - 1][0]).bit_length()
    s = 0
    for i in range(t):
        for j in range(rkb.ncols()):
            s += abs(rkb[i][j])
    return (s // t // rkb.ncols()).bit_length()


def mask(x):
    return int(x) >> 63


# solution idea:
# first, the mat is constructed by slicing n+t windows from the original random sequence
# considering t=1 case, then the mat.right_kernel_matrix() would have dimension 1
# which is exactly a vector of length n+1 consists of the coefficients of M.charpoly()  (because of M.charpoly()(M)=0)
# in general, the kernel have dimension t, and those t vectors are length n+t M.charpoly() coefficients padded with zeros
# for example, when t=3 the kernel basis are:
# [a0 ... an 0 0]
# [0 a0 ... an 0]
# [0 0 a0 ... an]
# and the shortest vector in the kernel (mod p) gets smaller when t gets larger
# and `estimate_ortho_size` is used to estimate the bit length of the short vectors given parameters n, t, m

# the reason we want to the short vectors in to kernel to be short is due to the folowing:
# the masked sequence is just the original sequence where each element is subtracted by an error term e in (0, 2^63)
# and since the kernel multiply to the original sequence is exactly zero, multiplying the kernel to the masked sequence is only affected by the error terms
# so if we can control the maginitude of the short vectors in the kernel, such that it does not exceed p after multiplying by error terms
# then we can recover to those short vectors by LLL!

output = output[:140]
n = 16
t = 51
m = len(output)
ksz = estimate_ortho_size(n, t, m)
masked = [s << 63 for s in output]
MM = matrix(F, [masked[i : i + n + t] for i in range(len(masked) - n - t)])
tgt = 63 + ksz + 4  # estimated size of kernel * error terms, 4 because 2^4=n=16
assert tgt < p.bit_length(), "target too large"
print(tgt, MM.dimensions())
known = MM.nrows() * (128 - tgt)
unknown = (n + t) * ksz
print(known, unknown, known - unknown)

L = block_matrix(ZZ, [[p, 0], [MM.T, 1]])
lb = [-(2**tgt)] * MM.nrows() + [-(2**ksz)] * (n + t)
ub = [2**tgt] * MM.nrows() + [2**ksz] * (n + t)
cvps, bs = solve_inequality_ex(
    L, lb, ub, cvp_ex=partial(kannan_cvp_ex, reduction=lambda M: BKZ(flatter(M)))
)
assert (
    cvps == 0
)  # because the average of lb and ub are zero, so its cvp are zero vector, which is useless
assert bs[: t + 2, MM.nrows() :].change_ring(GF(p)).rank() == t, (
    "recover failed"
)  # if the recovered short vectors are correct, it should have exactly rank t
rec = (
    bs[:t, MM.nrows() :].change_ring(GF(p)).echelon_form()[-1][t - 1 :]
)  # use echelon form to get vectors of the form [0 0 ... a0 ... an]
print(
    rec
)  # this vector have length n+1, which can zero any length n+1 window from the original sequence

# now, this problem becomes solving a similar problem to truncated LCG, so just construct the system and LLL!
keep = 64
errt = vector(polygens(F, "e", keep))
seq = errt + vector(masked[:keep])
eqs = []
for i in range(len(seq) - n - 1):
    eqs.append(rec * seq[i : i + n + 1])
monos, sol = next(
    solve_underconstrained_equations_general(p, eqs, {e: 2**63 for e in errt})
)
st = sol[:n] + vector(masked[:n])  # first n terms of the original sequence recovered

# find the key
pre1 = rec[1:] * st / -rec[0]
st = vector([pre1] + list(st)[:-1])
pre2 = rec[1:] * st / -rec[0]
key = int((mask(pre2) << 64) + mask(pre1))

aes = AES.new(key.to_bytes(16, "big"), AES.MODE_CTR, nonce=iv)
print(aes.decrypt(ct))
