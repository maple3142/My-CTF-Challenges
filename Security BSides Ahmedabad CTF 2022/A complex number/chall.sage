import os
from random import choice
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

bits = 100
P.<x> = ComplexField(bits)[]
key = os.urandom(16)
f = sum([a * x ^ i for i, a in enumerate(key)])
r = choice(f.roots())[0]
print(r)

cipher = AES.new(key, AES.MODE_CBC, b"\x00" * 16)
flag = open("flag.txt", "rb").read()
print(cipher.encrypt(pad(flag, 16)).hex())
