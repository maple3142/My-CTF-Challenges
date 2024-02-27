from Crypto.Util.number import getPrime, isPrime
import os


def getPp1(x, k):
    while True:
        a = 4
        for _ in range(k):
            a *= getPrime(x // k)
        p = a - 1
        if isPrime(p):
            return p


p, q = getPp1(512, 16), getPp1(512, 16)
flag = os.environ.get(
    "FLAG", "AIS3{easy_integer_factorization_and_an_introduciton_to_MOV_attacks!!!}"
).encode()
