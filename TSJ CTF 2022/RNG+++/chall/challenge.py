from Crypto.Util.number import *
from secret import flag

assert flag.startswith(b"TSJ{")
assert flag.endswith(b"}")
flag = flag[4:-1]


class RNG:
    def __init__(self, sz: int):
        self.M = 2 ** sz + 1
        while not isPrime(self.M):
            self.M += 2
        self.A = getPrime(sz)
        self.C = getPrime(sz)
        self.S = getRandomRange(1, self.M)

    def encrypt(self, m: bytes):
        self.S = (self.A * self.S + self.C) % self.M
        return long_to_bytes(bytes_to_long(m) ^ self.S)

    def __repr__(self):
        return f"{self.M} {self.A} {self.C}"


def randmsg(sz: int):
    return str(getRandomRange(1, 2 ** sz)).encode()[: sz // 8]


rng = RNG(len(flag) * 8)
print(rng)

msgs = [flag] + [randmsg(len(flag) * 8) for _ in range(8)]
for m in msgs:
    print(rng.encrypt(m).hex())
