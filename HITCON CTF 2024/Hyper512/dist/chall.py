import secrets
from hashlib import sha256

MASK1 = 0x6D6AC812F52A212D5A0B9F3117801FD5
MASK2 = 0xD736F40E0DED96B603F62CBE394FEF3D
MASK3 = 0xA55746EF3955B07595ABC13B9EBEED6B
MASK4 = 0xD670201BAC7515352A273372B2A95B23


class LFSR:
    def __init__(self, n, key, mask):
        self.n = n
        self.state = key & ((1 << n) - 1)
        self.mask = mask

    def __call__(self):
        b = self.state & 1
        self.state = (self.state >> 1) | (
            ((self.state & self.mask).bit_count() & 1) << (self.n - 1)
        )
        return b


class Cipher:
    def __init__(self, key: int):
        self.lfsr1 = LFSR(128, key, MASK1)
        key >>= 128
        self.lfsr2 = LFSR(128, key, MASK2)
        key >>= 128
        self.lfsr3 = LFSR(128, key, MASK3)
        key >>= 128
        self.lfsr4 = LFSR(128, key, MASK4)

    def bit(self):
        x = self.lfsr1() ^ self.lfsr1() ^ self.lfsr1()
        y = self.lfsr2()
        z = self.lfsr3() ^ self.lfsr3() ^ self.lfsr3() ^ self.lfsr3()
        w = self.lfsr4() ^ self.lfsr4()
        return (
            sha256(str((3 * x + 1 * y + 4 * z + 2 * w + 3142)).encode()).digest()[0] & 1
        )

    def stream(self):
        while True:
            b = 0
            for i in reversed(range(8)):
                b |= self.bit() << i
            yield b

    def encrypt(self, pt: bytes):
        return bytes([x ^ y for x, y in zip(pt, self.stream())])

    def decrypt(self, ct: bytes):
        return self.encrypt(ct)


if __name__ == "__main__":
    with open("flag.txt", "rb") as f:
        flag = f.read().strip()
    key = secrets.randbits(512)
    cipher = Cipher(key)
    gift = cipher.encrypt(b"\x00" * 2**12)
    print(gift.hex())
    ct = cipher.encrypt(flag)
    print(ct.hex())
