from typing import Tuple
from Crypto.Util.number import *
from gmpy2 import powmod
import os

flag = os.environb.get(b"FLAG", b"TSJ{test_flag}")


def pow(a: int, b: int, c: int) -> int:
    # gmpy2.powmod is much faster than pow
    return int(powmod(a, b, c))


def getPrimeOrderGroup(bits) -> Tuple[int, int, int]:
    """
    Generate a prime p with large prime factor q and a generator g
    """
    while True:
        q = getPrime(bits)
        for i in range(2, 257, 2):
            p = q * i + 1
            if isPrime(p):
                g = pow(getRandomRange(2, p), i, p)
                if g != 1:
                    assert pow(g, q, p) == 1
                    return p, q, g


class RSA:
    def __init__(self, bits):
        self.p = getPrime(bits // 2)
        self.q = getPrime(bits // 2)
        self.n = self.p * self.q
        self.e = 65537
        self.d = pow(self.e, -1, (self.p - 1) * (self.q - 1))

    def encrypt(self, m: int) -> int:
        return pow(m, self.e, self.n)

    def decrypt(self, c: int) -> int:
        return pow(c, self.d, self.n)

    def __str__(self) -> str:
        e = self.e
        n = self.n
        return f"RSA({n}, {e})"


class ElGamal:
    def __init__(self, bits):
        self.p, self.q, self.g = getPrimeOrderGroup(bits)
        self.x = getRandomRange(2, self.q)
        self.y = pow(self.g, self.x, self.p)

    def encrypt(self, m: int) -> Tuple[int, int]:
        r = getRandomRange(2, self.q)
        s = pow(self.y, r, self.p)
        c1 = pow(self.g, r, self.p)
        c2 = (s * m) % self.p
        return c1, c2

    def decrypt(self, c1: int, c2: int) -> int:
        s = pow(c1, self.x, self.p)
        m = (pow(s, -1, self.p) * c2) % self.p
        return m

    def __str__(self) -> str:
        p = self.p
        g = self.g
        y = self.y
        return f"ElGamal({p}, {g}, {y})"


elg = ElGamal(1024)
rsa = RSA(1024)

print("Welcome to Cipher Switching Service!")
print()
print("This is our public keys:")
print(rsa)
print(elg)
print()
print("And this is some information about the encrypted flag:")
print(f"{len(flag) = }")
flag += os.urandom(96 - len(flag))  # random padding
flagenc = rsa.encrypt(bytes_to_long(flag))
print(f"{flagenc = }")
print()

for _ in range(1337):
    print("1. RSA to ElGamal")
    print("2. ElGamal to RSA")
    print("3. Quit")
    choice = int(input("> "))
    if choice == 1:
        c = int(input("c = "))
        print(elg.encrypt(rsa.decrypt(c)))
    elif choice == 2:
        c1 = int(input("c1 = "))
        c2 = int(input("c2 = "))
        print(rsa.encrypt(elg.decrypt(c1, c2)))
    elif choice == 3:
        print("Bye")
        break
    else:
        print(f"Unknown choice: {choice}")
else:
    print("To prevent abuse, we limit each session to have only 1337 attempts at most.")
