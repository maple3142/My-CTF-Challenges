from Crypto.Util.number import bytes_to_long, getPrime
from hashlib import sha256
import os


def keygen(nbits):
    p = getPrime(1024)
    q = getPrime(1024)
    n = p * q
    e = 65537
    return n, e


def encrypt(pub, msg):
    n, e = pub
    P = Zmod(n)["x"]
    x = P.gen()
    m1 = bytes_to_long(msg)
    m2 = bytes_to_long(sha256(msg).digest())
    f = P.random_element(e) * ((x - m1) * (x - m2)) ^ 2
    return f


pub = keygen(2048)
flag = open("flag.txt", "rb").read().strip()
flag += os.urandom(2048 // 8 - len(flag))
enc = encrypt(pub, flag)
print(pub)
print(list(enc))
