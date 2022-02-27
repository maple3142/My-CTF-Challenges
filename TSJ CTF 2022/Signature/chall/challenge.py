from fastecdsa.curve import secp256k1 as CURVE
from Crypto.Cipher import AES
from hashlib import sha256
from secrets import randbelow

d = randbelow(CURVE.q)
P = d * CURVE.G


def sign(z):
    k = d ^ z
    r = (k * CURVE.G).x
    s = pow(k, -1, CURVE.q) * (z + r * d) % CURVE.q
    return r, s


messages = [
    "https://www.youtube.com/watch?v=16M9oC-a5bY",
    "https://www.youtube.com/watch?v=QDadz5JZCw8",
    "https://www.youtube.com/watch?v=kyNh7KnsTN0",
    "https://www.youtube.com/watch?v=Lqn42JJxS3I",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://www.youtube.com/watch?v=1Gw_-E784l0",
]

for m in messages:
    z = int(sha256(m.encode()).hexdigest(), 16)
    print(z, *sign(z))


from secret import flag

msg = f"Congrats! This is your flag: {flag}"
key = sha256(str(d).encode()).digest()[:16]
cipher = AES.new(key, AES.MODE_CTR)
print(cipher.encrypt(msg.encode()))
