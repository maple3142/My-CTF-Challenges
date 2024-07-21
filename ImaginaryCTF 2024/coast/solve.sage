from Crypto.Cipher import AES
from hashlib import sha256
from output import base_ser, pub_alice_ser, pub_bob_ser, ct, iv

proof.all(False)
# fmt: off
ls = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 929]
# fmt: on
p = 4 * product(ls) - 1
F = GF(p)
E0 = EllipticCurve(F, [1, 0])
G = E0.gen(0)
base = (E0, G)


def keygen():
    return [randint(-1, 1) for _ in range(len(ls))]


def exchange(pub, priv):
    E, G = pub
    es = priv[:]
    while any(es):
        s = +1 if randint(0, 1) else -1
        E.set_order(p + 1)
        P = E.random_point()
        k = prod(l for l, e in zip(ls, es) if sign(e) == s)
        P *= (p + 1) // k
        for i, (l, e) in enumerate(zip(ls, es)):
            if sign(e) != s:
                continue
            Q = k // l * P
            if not Q:
                continue
            Q.set_order(l)
            phi = E.isogeny(Q)
            E, P = phi.codomain(), phi(P)
            G = phi(G)
            es[i] -= s
            k //= l
    return E, G


def deserialize_pub(ser):
    a, b, x, y = ser
    E = EllipticCurve(F, [a, b])
    E.set_order(p + 1)
    G = E(x, y)
    return E, G


E0, G = deserialize_pub(base_ser)
EA, GA = deserialize_pub(pub_alice_ser)
EB, GB = deserialize_pub(pub_bob_ser)

cfA = (p + 1) // GA.order()
ax = [1 if cfA % l == 0 else 0 for l in ls]
assert exchange((E0, G), ax) == (EA, GA)
cfB = (p + 1) // GB.order()
bx = [1 if cfB % l == 0 else 0 for l in ls]
assert exchange((E0, G), bx) == (EB, GB)

S = exchange((EA, GA), bx)
assert S == exchange((EB, GB), ax)

shared_secret = int(S[0].j_invariant() + S[1][0])
key = sha256(str(shared_secret).encode()).digest()
cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
pt = cipher.decrypt(ct)
print(pt)
