#!/usr/bin/env python3
from Crypto.Util.number import getPrime, getRandomRange
from math import floor
import json, random, os

# https://www.di.ens.fr/~stern/data/St84.pdf
A = 2**1000
B = 2**80


def keygen():
    p = getPrime(512)
    q = getPrime(512)
    n = p * q
    phi = (p - 1) * (q - 1)
    return n, phi


def zkpof(z, n, phi):
    # I act as the prover
    r = getRandomRange(0, A)
    x = pow(z, r, n)
    e = int(input("e = "))
    if e >= B:
        raise ValueError("e too large")
    y = r + (n - phi) * e
    transcript = {"x": x, "e": e, "y": y}
    return json.dumps(transcript)


def zkpof_reverse(z, n):
    # You act as the prover
    x = int(input("x = "))
    e = getRandomRange(0, B)
    print(f"{e = }")
    y = int(input("y = "))
    transcript = {"x": x, "e": e, "y": y}
    return json.dumps(transcript)


def zkpof_verify(z, t, n):
    transcript = json.loads(t)
    x, e, y = [transcript[k] for k in ("x", "e", "y")]
    return 0 <= y < A and pow(z, y - n * e, n) == x


if __name__ == "__main__":
    n, phi = keygen()
    print(f"{n = }")

    rand = random.Random(1337)  # public, fixed generator for z
    for _ in range(0x137):
        try:
            z = rand.randrange(2, n)
            t = zkpof(z, n, phi)
            assert zkpof_verify(z, t, n)
            print(t)
            if input("Still not convined? [y/n] ").lower()[0] != "y":
                break
        except Exception as e:
            print(f"Error: {e}")
    print(
        "You should now be convinced that I know the factorization of n without revealing anything about it. Right?"
    )
    for _ in range(floor(13.37)):
        z = rand.randrange(2, n)
        t = zkpof_reverse(z, n)
        assert zkpof_verify(z, t, n)
        print(t)
    print(os.environ.get("FLAG", "flag{test}"))
