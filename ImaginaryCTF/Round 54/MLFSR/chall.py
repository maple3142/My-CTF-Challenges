from sage.all import *
from Crypto.Cipher import AES

p = 2**127 - 1
F = GF(p)


def mask(x):
    return int(x) >> 63


def mlfsr(n):
    M = random_matrix(F, n, n)
    v = random_vector(F, n)
    while True:
        v = M * v
        yield mask(v[0])


if __name__ == "__main__":
    with open("flag.txt", "rb") as f:
        flag = f.read().strip()
    rng = mlfsr(16)
    key = (next(rng) << 64) + next(rng)
    aes = AES.new(key.to_bytes(16, "big"), AES.MODE_CTR)
    ct = aes.encrypt(flag)
    iv = aes.nonce
    print(f"{ct = }")
    print(f"{iv = }")

    output = []
    for _ in range(140):
        output.append(next(rng))
    print(f"{output = }")
