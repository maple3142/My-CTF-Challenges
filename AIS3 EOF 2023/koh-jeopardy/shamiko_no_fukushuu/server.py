from fastecdsa.curve import secp256k1
from fastecdsa.keys import gen_keypair
from fastecdsa.point import Point
from hashlib import sha256
import hmac
from typing import Tuple


def gen_nonce(msg: bytes, priv: int) -> int:
    bl = (secp256k1.q.bit_length() + 7) // 8
    h = hmac.digest(msg, priv.to_bytes(bl, "big"), sha256)
    return int.from_bytes(h, "big")


def sign(msg: bytes, priv: int) -> Tuple[int, int]:
    k = gen_nonce(msg, priv)
    h = int.from_bytes(sha256(msg).digest(), "big")
    r = (k * secp256k1.G).x
    s = (h + r * priv) * pow(k, -1, secp256k1.q)
    return r, s


def verify(msg: bytes, sig: Tuple[int, int], pub: Point) -> bool:
    r, s = sig
    h = int.from_bytes(sha256(msg).digest(), "big")
    w = pow(s, -1, secp256k1.q)
    u1 = h * w
    u2 = r * w
    x = (u1 * secp256k1.G + u2 * pub).x
    return x == r


if __name__ == "__main__":
    import os, ast

    flag = os.environ.get("FLAG", "flag{test_flag}")
    MENU = """1. Sign
2. Verify
3. Exit
> """
    priv, pub = gen_keypair(secp256k1)
    while True:
        choice = int(input(MENU))
        if choice == 1:
            name = input("Namae: ").encode()
            if name == b"shamiko":
                print("DAME!")
                continue
            print(sign(name, priv))
        elif choice == 2:
            name = input("Namae: ").encode()
            sig = ast.literal_eval(input("sig: "))
            if verify(name, sig, pub):
                print(f"Hello, {name.decode()}")
                if name == b"shamiko":
                    print(flag)
            else:
                print("Uso-tsuki!")
        elif choice == 3:
            break
