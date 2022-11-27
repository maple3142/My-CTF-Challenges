from sage.all import crt, lcm
import ast
from Crypto.Cipher import AES
from hashlib import sha256

with open("output.txt") as f:
    shares = ast.literal_eval(f.readline())
    ct = ast.literal_eval(f.readline())
    nonce = ast.literal_eval(f.readline())

print(lcm([x for x, y in shares]).nbits())

poly = []
for _ in range(128 + 1):
    const = int(crt([y % x for x, y in shares], [x for x, y in shares]))
    shares = [(x, (y - const) // x) for x, y in shares]
    poly.append(const)


def polyeval(poly, x):
    return sum([a * x**i for i, a in enumerate(poly)])


secret = polyeval(poly, 0x48763)
key = sha256(str(secret).encode()).digest()[:16]
cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
print(cipher.decrypt(ct))
