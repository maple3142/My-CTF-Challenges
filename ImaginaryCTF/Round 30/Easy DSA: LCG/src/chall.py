from Crypto.Util.number import getPrime
from Crypto.Cipher import AES
from fastecdsa.curve import secp256k1
from hashlib import sha256
from secrets import randbelow


G = secp256k1.G
q = secp256k1.q


def sign(d, z, k):
    r = (k * G).x
    s = (z + r * d) * pow(k, -1, q) % q
    return r, s


def verify(P, z, r, s):
    u1 = z * pow(s, -1, q) % q
    u2 = r * pow(s, -1, q) % q
    x = (u1 * G + u2 * P).x
    return x == r


def lcg(a, b, p, x):
    while True:
        x = (a * x + b) % p
        yield x


if __name__ == "__main__":
    d = randbelow(q)
    P = d * G

    p = getPrime(512)
    print(f"{p = }")
    rng = lcg(G.x, G.y, p, randbelow(p))

    msgs = [
        b"https://www.youtube.com/watch?v=S8MJvhgjXBY",
        b"https://www.youtube.com/watch?v=wSTbdqo-j74",
        b"https://www.youtube.com/watch?v=dkYHgxfQZBA",
        b"https://www.youtube.com/watch?v=p8ET-m6y6VU",
    ]
    sigs = []
    for m, k in zip(msgs, rng):
        z = int.from_bytes(sha256(m).digest(), "big") % q
        r, s = sign(d, z, k)
        assert verify(P, z, r, s)
        sigs.append((r, s))
    print(f"{sigs = }")

    flag = open("flag.txt", "rb").read().strip()
    key = sha256(str(d).encode()).digest()[:16]
    cipher = AES.new(key, AES.MODE_CTR)
    ct = cipher.encrypt(flag)
    nonce = cipher.nonce
    print(f"{ct = }")
    print(f"{nonce = }")
