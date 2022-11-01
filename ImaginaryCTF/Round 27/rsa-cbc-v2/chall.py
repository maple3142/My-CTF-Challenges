from Crypto.Util.number import getPrime
from secrets import randbelow


class RSACBC:
    def __init__(self, size):
        self.blk = 16
        self.len = size // 8
        self.n = getPrime(size // 2) * getPrime(size // 2)
        self.e = 9

    def encrypt(self, msg: bytes) -> bytes:
        iv = randbelow(self.n)
        iv0 = iv
        ct = b""
        for i in range(0, len(msg), self.blk):
            m = int.from_bytes(msg[i : i + self.blk], "big")
            c = pow(iv + m, self.e, self.n)
            ct += c.to_bytes(self.len, "big")
            iv = c
        return iv0.to_bytes(self.len, "big"), ct


flag = open("flag.txt", "rb").read().strip()
assert flag.startswith(b"ictf{")
assert flag.endswith(b"}")
flag = flag[5:-1]
cipher = RSACBC(2048)
print(f"n = {cipher.n}")

iv, ct = cipher.encrypt(flag)
print(f"{iv = }")
print(f"{ct = }")
