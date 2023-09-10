from Crypto.Util.number import *
from subprocess import check_output
from re import findall
from shlex import quote
import string
import random
from itertools import product


charset = "".join([c for c in string.printable if quote(c) == c])


def randstr(n):
    return "".join(random.choice(charset) for _ in range(n))


def get_cmd(msg):
    return "echo %s" % quote(msg)


def get_exps(base, n):
    exp = []
    for p in base:
        e = 0
        while n % p == 0:
            n //= p
            e += 1
        exp.append(e)
    return n == 1, exp


def enumerate_prod(chs, n):
    for i in range(1, n + 1):
        print("ENUM", i)
        yield from product(chs, repeat=i)


base_size = 512
fac_base = sieve_base[:base_size]

exp_mat = []
msgs = []
for msg in enumerate_prod(charset, 5):
    msg = "".join(msg)
    cmd = get_cmd(msg)
    m = bytes_to_long(cmd.encode())
    good, exp = get_exps(fac_base, m)
    if not good:
        continue
    print(exp)
    exp_mat.append(exp)
    print(len(exp_mat))
    msgs.append(msg)
    A = matrix(ZZ, exp_mat)
    ker = A.left_kernel()
    if ker.dimension() > 40:
        km = ker.basis_matrix().LLL()
        print(km)
        break

save((msgs, A, km), "precomputed.sobj")
