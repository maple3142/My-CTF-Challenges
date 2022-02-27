from secrets import randbelow
from secret import fast_forward


class Cipher:
    bs = 16
    s = 0x6BF1B9BAE2CA5BC9C7EF4BCD5AADBC47
    k = 0x5C2B76970103D4EEFCD4A2C681CC400D

    def __init__(self, key: int):
        self.key = key

    def _next(self):
        # replacing fast_forward with forward works too
        self.s = fast_forward(self.s, self.key, self.k)

    def ks(self, n):
        ks = b""
        while len(ks) < n:
            self._next()
            ks += self.s.to_bytes(self.bs, "big")
        return ks[:n]

    def encrypt(self, plaintext: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(plaintext, self.ks(len(plaintext))))

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self.encrypt(ciphertext)


def forward(s: int, n: int, k: int) -> int:
    for _ in range(n):
        s = (s >> 1) ^ ((s & 1) * k)
    return s


# fast_forward is **fast** implementation of forward using a proprietary algorithm
# for i in range(1024):
#     assert forward(Cipher.s, i, Cipher.k) == fast_forward(Cipher.s, i, Cipher.k)

if __name__ == "__main__":
    key = randbelow(2 ** 128)
    with open("flag.png", "rb") as f:
        data = f.read()
    with open("flag.png.enc", "wb") as f:
        f.write(Cipher(key).encrypt(data))
