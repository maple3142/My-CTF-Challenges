from secrets import randbits


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


if __name__ == "__main__":
    n = 128
    # fmt: off
    taps = [0, 1, 5, 10, 11, 14, 16, 17, 19, 28, 30, 31, 32, 33, 35, 36, 38, 39, 40, 45, 47, 48, 49, 51, 52, 53, 55, 56, 58, 61, 62, 64, 68, 71, 72, 74, 76, 82, 84, 85, 88, 90, 91, 92, 96, 97, 100, 102, 108, 110, 111, 113, 115, 118, 119, 121, 123, 127]
    # fmt: on
    key = randbits(n)
    rng = NotLFSR(key, n, taps)

    flag = open("flag.txt", "rb").read().strip()
    bits = sum([list(map(int, f"{c:08b}")) for c in flag], [])

    out = [x ^ y for x, y in zip(bits, rng.getbits(len(bits)))]
    out += rng.getbits(256)
    print(out)
