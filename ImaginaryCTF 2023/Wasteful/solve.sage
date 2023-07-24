from Crypto.Util.number import *

with open("output.txt") as f:
    exec(f.read())

proof.arithmetic(False)

n, e = pub
t = next_prime(e // n)
s = (t - e) % n
# _ap suffix stands for approximation
pplusq_ap = s // t
pminusq_ap = isqrt(pplusq_ap**2 - 4 * n)
porq_ap = (pplusq_ap - pminusq_ap) // 2
x = Zmod(n)["x"].gen()
f = porq_ap + x
X = 2 ** (1024 - (2048 // 3) + 5)
beta = 0.499
eps = (beta**2 / f.degree() - log(X, n)).n()
print(f"{eps = }")
r = ZZ(f.small_roots(X=X, beta=beta, epsilon=eps)[0])
p = gcd(f.change_ring(ZZ)(r), n)
q = n // p
assert p * q == n
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
m = pow(c, d, n)
print(long_to_bytes(m))
