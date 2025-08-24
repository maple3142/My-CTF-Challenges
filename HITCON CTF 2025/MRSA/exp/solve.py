from sage.all import *
from lll_cvp import *
from output import C, ct
from Crypto.Cipher import AES

k = 16
C = matrix(ZZ, k, k, C)

# idea:
# obviously, C=x0*M^0+x1*M^1+... over Z/nZ for some unknown x0,x1,...
# we can rewrite it as C=n*R+x0*M^0+x1*M^1+... for some unknown matrix R over Z
# it is easy to see that the magnitude of R ~= magnitude of M^(k-1), which is still small compared to n
# so we can easyily solve this using orthogonal lattices

with lattice_context(reduction=flatter):
    ot = find_ortho(
        None, vector(C.list())
    )  # find short vectors orthogonal to flatten(C)
    rr = find_ortho(None, *ot[: k * k - k - 1])  # k*k-k-1 are found by observation

# of course, the identity matrix is a part of the solution
# we still need a small bruteforce to find the key
I, MI = rr[0], rr[1]
if I[0] < 0:
    I = -I
if MI[1] < 0:
    MI = -MI
print(I)
print(MI)  # this is M - ?*I
for _ in range(256):
    MI += I
    if 0 <= min(MI.list()) and max(MI.list()) < 256:
        key = bytes(MI.list())
        aes = AES.new(key[:32], AES.MODE_CTR, nonce=key[-8:])
        flag = aes.decrypt(ct)
        if flag.isascii():
            print(MI)
            print(flag)
            break
