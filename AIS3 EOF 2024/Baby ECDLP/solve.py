from sage.all import *
from Crypto.Util.number import *
from output import a, b, C


def clean(n):
    for p in sieve_base:
        while n % p == 0:
            n //= p
    return n


a, b = ZZ(a), ZZ(b)
x, y = C
n = clean(gcd(y**2 - (x**3 + a * x), b))
ps, qs = QQ["p, q"].gens()
I = ideal([ps * qs - n, ps + qs - (ps**2 + ps * qs + qs**2) - a])
sol = I.variety()[0]
p = ZZ(sol[ps])
q = ZZ(sol[qs])

E = EllipticCurve(Zmod(n), [a, b])
G = E(p, p) + E(q, q)
Ep = E.change_ring(Zmod(p))
Eq = E.change_ring(Zmod(q))


def mov_attack(E, P, G):
    k = 2
    p = E.base_ring().characteristic()
    K = GF(p**k, "a")
    EK = E.base_extend(K)
    PK = EK(P)
    GK = EK(G)
    QK = EK.random_point()  # Assuming QK is linear independent to PK
    egqn = PK.tate_pairing(QK, E.order(), k)  # e(P,Q)=e(G,Q)^n
    egq = GK.tate_pairing(QK, E.order(), k)  # e(G,Q)
    odr = ZZ(pari.fforder(egq, p + 1))
    lg = ZZ(pari.fflog(egqn, egq, odr))
    return lg, odr


mp, op = mov_attack(Ep, Ep(C), Ep(G))
mq, oq = mov_attack(Eq, Eq(C), Eq(G))
m = crt([mp, mq], [op, oq])
print(long_to_bytes(int(m)))
