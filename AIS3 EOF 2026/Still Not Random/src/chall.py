import hmac
from hashlib import sha256

from fastecdsa.curve import P384
from fastecdsa.keys import gen_keypair
from Crypto.Cipher import AES


def p2i(P) -> int:
    return P.x * P.curve.p + P.y


def sign(sk: int, msg: bytes, *, curve=P384, hashfunc=sha256) -> tuple[int, int]:
    key = hashfunc(str(sk).encode()).digest()
    k = int.from_bytes(key + hmac.new(key, msg, hashfunc).digest()) % curve.q
    r = p2i(k * curve.G)
    e = int.from_bytes(hmac.new(r.to_bytes(1337), msg, hashfunc).digest()) % curve.q
    s = (k + sk * e) % curve.q
    return r, s


msgs = [
    b"https://www.youtube.com/watch?v=LaX6EIkk_pQ",
    b"https://www.youtube.com/watch?v=wK4wA0aKvg8",
    b"https://www.youtube.com/watch?v=iq90nHs3Gbs",
    b"https://www.youtube.com/watch?v=zTKADhU__sw",
]


def main():
    with open("flag.txt", "rb") as f:
        flag = f.read().strip()

    sk, pk = gen_keypair(P384)
    sigs = [sign(sk, msg) for msg in msgs]

    key = (sk & ((1 << 128) - 1)).to_bytes(16)
    cipher = AES.new(key, AES.MODE_CTR)
    ct = cipher.nonce + cipher.encrypt(flag)

    print(f"{sigs = }")
    print(f"{ct = }")


if __name__ == "__main__":
    main()
