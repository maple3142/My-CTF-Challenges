from sage.all import *
from sage.matrix.berlekamp_massey import berlekamp_massey
from secrets import randbits
from binteger import Bin


class NotLFSR:
    def __init__(self, key, n, taps):
        self.s = list(map(int, f"{key:0{n}b}"))
        self.taps = taps

    def clock(self):
        # definitely not linear :)
        b = 1
        for t in self.taps:
            b ^= self.s[t]
        self.s = self.s[1:] + [b]
        return b

    def getbits(self, n):
        return [self.clock() for _ in range(n)]


n = 128
# fmt: off
taps = [0, 1, 5, 10, 11, 14, 16, 17, 19, 28, 30, 31, 32, 33, 35, 36, 38, 39, 40, 45, 47, 48, 49, 51, 52, 53, 55, 56, 58, 61, 62, 64, 68, 71, 72, 74, 76, 82, 84, 85, 88, 90, 91, 92, 96, 97, 100, 102, 108, 110, 111, 113, 115, 118, 119, 121, 123, 127]
# fmt: on
key = randbits(n)
rng = NotLFSR(key, n, taps)
F = GF(2)
bits = rng.getbits(n * 4)
f = berlekamp_massey([F(b) for b in bits])
print(f)
M = companion_matrix(f, "bottom")
print(M * vector(bits[:129]))
print(vector(bits[1 : 1 + 129]))
Mi = M.inverse()

out = eval(open("output.txt").read())
seq = out[256:]
for _ in range(len(out) - len(seq)):
    b = (Mi * vector(seq[:129]))[0]
    seq.insert(0, int(b))
flag_bits = [x ^ y for x, y in zip(seq[:-256], out[:-256])]
print(Bin(flag_bits).bytes)
