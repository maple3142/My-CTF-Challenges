from sage.all import *
from Crypto.Util.number import getPrime
from Crypto.Cipher import AES
import os


flag = os.environb.get(b"FLAG", b"flag{test_flag}")

n = getPrime(1024) * getPrime(1024)
k = 16
e = 65537

key = os.urandom(k * k)
M = matrix(Zmod(n), k, k, key)
C = M**e

aes = AES.new(key[:32], AES.MODE_CTR, nonce=key[-8:])
ct = aes.encrypt(flag)

print(f"C = {C.list()}")
print(f"{ct = }")
