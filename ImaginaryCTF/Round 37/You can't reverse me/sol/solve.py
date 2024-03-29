import ctypes

# fmt: off
flag = [0xDE, 0x1C, 0x83, 0x6C, 0x46, 0xDE, 0x4E, 0x08, 0x10, 0xA4, 0x99, 0xB4, 0xD6, 0xC1, 0x33, 0x90, 0x1A, 0x31, 0x1A, 0xD9, 0x1E, 0x36, 0x00, 0xB4, 0xD3, 0x08, 0x57, 0x9C, 0x3A, 0xDF, 0xF4, 0x32, 0x23, 0x08, 0x3E, 0x53, 0xE4, 0x0D]
# fmt: on


# https://git.musl-libc.org/cgit/musl/tree/src/prng/rand.c
class MuslRand:
    def __init__(self, s):
        self.seed = s - 1
        self.mask = (1 << 64) - 1

    def rand(self):
        self.seed = (6364136223846793005 * self.seed + 1) & self.mask
        return self.seed >> 33


rand = MuslRand(int.from_bytes(b"ictf", "little"))
for i in range(len(flag)):
    flag[i] ^= rand.rand() & 0xFF
print(bytes(flag))
