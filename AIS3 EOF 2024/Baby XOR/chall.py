from Crypto.Util.number import bytes_to_long, getPrime
import secrets, os
from hashlib import sha256
from Crypto.Cipher import AES

flag = os.environ.get("FLAG", "not_flag{fake_flag}")


def xorrrrr(nums):
    n = len(nums)
    result = [0] * n
    for i in range(1, n):
        result = [result[j] ^ nums[(j + i) % n] for j in range(n)]
    return result


mods = [getPrime(48) for i in range(1337)]
muls = [getPrime(6) for i in range(1337)]
secret = secrets.randbelow(2**1337)
hint = [secret * muls[i] % mods[i] for i in range(1337)]

print(xorrrrr(mods))
print(hint)

key = sha256(str(secret).encode()).digest()[:16]
cipher = AES.new(key, AES.MODE_CTR, nonce=b"\x00" * 12)
ct = cipher.encrypt(flag.encode())
print(ct.hex())
