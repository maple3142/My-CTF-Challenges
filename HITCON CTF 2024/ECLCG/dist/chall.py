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


msgs = [
    b"https://www.youtube.com/watch?v=kv4UD4ICd_0",
    b"https://www.youtube.com/watch?v=IijOKxLclxE",
    b"https://www.youtube.com/watch?v=GH6akWYAtGc",
    b"https://www.youtube.com/watch?v=Y3JhUFAa9bk",
    b"https://www.youtube.com/watch?v=FGID8CJ1fUY",
    b"https://www.youtube.com/watch?v=_BfmEjHVYwM",
    b"https://www.youtube.com/watch?v=zH7wBliAhT0",
    b"https://www.youtube.com/watch?v=NROQyBPX9Uo",
    b"https://www.youtube.com/watch?v=ylH6VpJAoME",
    b"https://www.youtube.com/watch?v=hI34Bhf5SaY",
    b"https://www.youtube.com/watch?v=bef23j792eE",
    b"https://www.youtube.com/watch?v=ybvXNOWX-dI",
    b"https://www.youtube.com/watch?v=dt3p2HtLzDA",
    b"https://www.youtube.com/watch?v=1Z4O8bKoLlU",
    b"https://www.youtube.com/watch?v=S53XDR4eGy4",
    b"https://www.youtube.com/watch?v=ZK64DWBQNXw",
    b"https://www.youtube.com/watch?v=tLL8cqRmaNE",
]

if __name__ == "__main__":
    d = randbelow(q)
    P = d * G

    p = getPrime(0x137)
    a, b, x = [randbelow(p) for _ in range(3)]
    rng = lcg(a, b, p, x)

    sigs = []
    for m, k in zip(msgs, rng):
        z = int.from_bytes(sha256(m).digest(), "big") % q
        r, s = sign(d, z, k)
        assert verify(P, z, r, s)
        sigs.append((r, s))
    print(f"{sigs = }")

    with open("flag.txt", "rb") as f:
        flag = f.read().strip()
    key = sha256(str(d).encode()).digest()
    cipher = AES.new(key, AES.MODE_CTR)
    ct = cipher.encrypt(flag)
    nonce = cipher.nonce
    print(f"{ct = }")
    print(f"{nonce = }")
