import os
from hashlib import sha256
from random import SystemRandom

from Crypto.Cipher import AES
from sage.all import *

flag = os.environb.get(b"FLAG", b"flag{test_flag}")


n = 64
m = 200
p = 1048583
F = GF(p)

random = SystemRandom()
errs = random.sample(range(p), 3)
A = matrix(F, [[random.randrange(0, p - 1) for _ in range(n)] for _ in range(m)])
s = vector(F, [random.randrange(0, p - 1) for _ in range(n)])
e = vector(F, [random.choice(errs) for _ in range(m)])
b = A * s + e

key = sha256(str(s).encode()).digest()[:24]
aes = AES.new(key[:16], AES.MODE_CTR, nonce=key[-8:])
ct = aes.encrypt(flag)

print(f"A = {A.list()}")
print(f"b = {b.list()}")
print(f"{ct = }")
