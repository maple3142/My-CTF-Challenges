from tqdm import tqdm
from itertools import combinations, product
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha256

with open("output.txt") as f:
    exec(f.read())

enc = chimera


def recover_mod(P1, P2, P3):
    # https://hackmd.io/@mystiz/uiuctf-2020-nookcrypt gives a nice explicit formula
    x1, y1 = P1
    x2, y2 = P2
    x3, y3 = P3
    return (y1 ^ 2 - y2 ^ 2 - x1 ^ 3 + x2 ^ 3) * (x2 - x3) - (
        y2 ^ 2 - y3 ^ 2 - x2 ^ 3 + x3 ^ 3
    ) * (x1 - x2)


def ecc(a, b, x, y):
    return y ^ 2 - (x ^ 3 + a * x + b)


def solve_lin(f):
    return ZZ(-f[0] / f[1])


n = reduce(gcd, [recover_mod(*ps) for ps in zip(enc, enc[1:], enc[2:])]).sqrt()
print(f"{n = }")

P.<a, b> = Zmod(n**2)[]
f = ecc(a, b, *enc[0])
g = ecc(a, b, *enc[1])
h1 = f.sylvester_matrix(g, b).det().univariate_polynomial()
h2 = f.sylvester_matrix(g, a).det().univariate_polynomial()
a = solve_lin(h1)
b = solve_lin(h2)
print(f"{a = }")
print(f"{b = }")

E = EllipticCurve(Zmod(n), [a, b])
# find factor by inverse error like ECM
for i in range(2, 100):
    if gift % i == 0:
        try:
            E(*enc[0]) * int(gift // i)
        except ZeroDivisionError as ex:
            v = ZZ(str(ex).split("Inverse of ")[1].split(" does not exist")[0])
            p = gcd(v, n)
            break

q = n // p
assert p * q == n
print(f"{p = }")
print(f"{q = }")


# recover G
# Gy^2 = Gx^3 + a*Gx + b (mod n^2)
# Gy^2 - Gx^3 ~ 32*8*3 bits
# Gx ~ 32*8 bits
# n^2 ~ 384*2*2 bits
L = matrix([[n ^ 2, 0, 0], [a, 1, 0], [b, 0, 1]])
K = 2 ^ 1024
Q = matrix.diagonal([K // 2 ^ (32 * 8 * 3), K // 2 ^ (32 * 8), K // 1])
L *= Q
L = L.LLL()
L /= Q
Gx = L[0][1]
Gy2 = L[0][0] + Gx ^ 3
assert Gy2 % n ^ 2 == (Gx ^ 3 + a * Gx + b) % n ^ 2
# this works because Gy ~ 32*8 bits and p ~ 384 bits is bigger than that
Gy = sorted(GF(p)(Gy2).sqrt(all=True))[0]
print(f"{Gx = }")
print(f"{Gy = }")

E = EllipticCurve(Zmod(n**2), [a, b])
enc = [E(x) for x in enc]
G = E(Gx, Gy)
odp = EllipticCurve(GF(p), [a, b]).order()
odq = EllipticCurve(GF(q), [a, b]).order()
print(f"{odp = }")
print(f"{odq = }")


def dlog(G, Y, p, od):
    # Proposition 19 of https://www.researchgate.net/publication/344971478_The_group_structure_of_elliptic_curves_over_ZNZ
    # https://hackmd.io/@mitsu/ByhK-tZX_
    # https://utaha1228.github.io/ctf-note/2021/07/20/Smart-s-Attack/
    E = EllipticCurve(Qp(p, prec=2), [a, b])
    G = E([ZZ(x) % p**2 for x in G.xy()])
    Y = E([ZZ(x) % p**2 for x in Y.xy()])

    def phi(P):
        x, y = (P * od).xy()
        return x / y

    return (phi(Y) / phi(G)).lift()


def dlogn(G, Y):
    xp = dlog(G, Y, p, odp)
    xq = dlog(G, Y, q, odq)
    return crt([xp, xq], [p, q])


hs = [dlogn(G, Y) for Y in tqdm(enc)]

# solving a hidden subset sum-ish problem
# based on https://eprint.iacr.org/2020/461.pdf
p = n
n = 16
m = 64

B = matrix(hs).T.augment(matrix.identity(m)).stack(vector([p] + [0] * m))
nr = m - n
print("LLL1", B.dimensions())
ortho = B.LLL()[:nr, 1:]

R = ortho.T.augment(matrix.identity(m))
R[:, :nr] *= p
print("LLL2", R.dimensions())
R = R.LLL()

collect = []
for row in R:
    if any([x != 0 for x in row[:nr]]):
        continue
    collect.append(row[nr:])


good = []
for r in range(1, 6):
    for cb in combinations(collect, r):
        for s in product((-1, 1), repeat=r):
            v = sum([a * v for a, v in zip(s, cb)])
            if all([0 <= x < 256 for x in v]):
                good.append(vector(v))
assert len(good) == n
print(good)

M = matrix(Zmod(p), list(good))
sol = M.solve_left(vector(hs))
secrets = [int(x) * G for x in sol]
key = sha256(str(sum(secrets).xy()[0]).encode()).digest()[:16]
cipher = AES.new(key, AES.MODE_CBC, b"\0" * 16)
flag = unpad(cipher.decrypt(flagct), 16)
print(flag)
