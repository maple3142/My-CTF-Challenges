from Crypto.Cipher import AES
import secrets


class LFSR:
    def __init__(self, mask: int, state: int):
        self.mask = mask
        self.state = state

    def clock(self):
        s = self.state
        self.state = (s >> 1) ^ ((s & 1) * self.mask)


class LOL:
    def __init__(self, sz: int, mask: int, taps: list[int], state: list[int]):
        if len(taps) != len(state):
            raise ValueError("taps and state must have the same length")
        self.sz = sz
        self.taps = taps
        self.lfsrs = [LFSR(mask, s) for s in state]

    def clock(self):
        x = 0
        for t, l in zip(self.taps, self.lfsrs):
            for _ in range(t):
                l.clock()
            x ^= l.state
        self.lfsrs = [LFSR(self.lfsrs[0].mask, x)] + self.lfsrs[:-1]
        return x

    def rand(self) -> bytes:
        return self.clock().to_bytes(self.sz)

    @staticmethod
    def generate(n: int, sz: int):
        mask = secrets.randbits(sz * 8) | (1 << (sz * 8 - 1))
        taps = secrets.token_bytes(n)
        state = [secrets.randbits(sz * 8) for _ in range(n)]
        return LOL(sz, mask, taps, state)


def main():
    with open("flag.txt", "rb") as f:
        flag = f.read().strip()

    lol = LOL.generate(16, 16)
    gift = b"".join(lol.rand() for _ in range(42))
    cipher = AES.new(lol.rand(), AES.MODE_CTR)
    ct = cipher.nonce + cipher.encrypt(flag)
    print(f"{gift = }")
    print(f"{ct = }")


if __name__ == "__main__":
    main()
