import numpy as np
from Crypto.Cipher import AES
from hashlib import sha256
from random import SystemRandom
import sys

p = 65537
rand = SystemRandom()


def share(secret: bytes, n: int, t: int):
    # (t, n) secret sharing
    poly = np.array([rand.randrange(0, p) for _ in range(t)])
    f = lambda x: int(np.polyval(poly, x) % p)

    xs = rand.sample(range(t, p), n)
    ys = [f(x) for x in xs]
    shares = [(int(x), int(y)) for x, y in zip(xs, ys)]

    ks = [f(x) for x in range(t)]
    key = sha256(repr(ks).encode()).digest()
    cipher = AES.new(key, AES.MODE_CTR)
    ct = cipher.nonce + cipher.encrypt(secret)
    return ct, shares


def interpolate(xs: list[int], ys: list[int], x: int):
    n = len(xs)
    assert n == len(ys)
    res = 0
    for i in range(n):
        numer, denom = 1, 1
        for j in range(n):
            if i == j:
                continue
            numer *= x - xs[j]
            denom *= xs[i] - xs[j]
        res += ys[i] * numer * pow(denom, -1, p)
    return res % p


def recover(ct: bytes, shares: list, t: int):
    xs, ys = zip(*shares[:t])
    ks = [interpolate(xs, ys, x) for x in range(t)]
    key = sha256(repr(ks).encode()).digest()
    cipher = AES.new(key, AES.MODE_CTR, nonce=ct[:8])
    return cipher.decrypt(ct[8:])


def sanity_check():
    message = b"hello world"
    ct, shares = share(message, 16, 4)
    assert recover(ct, shares, 4) == message


if __name__ == "__main__":
    sanity_check()
    with open("flag.txt", "rb") as f:
        flag = f.read().strip()
    ct, shares = share(flag, 48, 24)
    print(f"{ct = }")
    print(f"{shares = }")

    if recover(ct, shares, 24) != flag:
        print("Failed to recover flag ???", file=sys.stderr)
