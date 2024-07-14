from sage.all import *
from random import Random, SystemRandom
from hashlib import sha256
from Crypto.Cipher import AES

# https://eprint.iacr.org/2023/1745.pdf


class BaseMatrixProductCryptosystem:
    def __init__(self, n: int, k: int, a: int, p: int):
        self.n = n
        self.k = k
        self.a = a
        self.p = p
        self.F = GF(p)

    def rand_drawf(self, rand: Random, check=True, ring=None):
        if ring is None:
            ring = self.F
        while True:
            M = matrix(
                ZZ,
                self.n,
                self.n,
                [rand.randint(0, self.a) for _ in range(self.n * self.n)],
            )
            det = M.det()
            if not check or det % self.p != 0:
                return M.change_ring(ring)

    def rand_elf(self, rand: Random, check=True, ring=None):
        if ring is None:
            ring = self.F
        while True:
            M = matrix(
                ZZ,
                self.n,
                self.n,
                [rand.randrange(0, self.p) for _ in range(self.n * self.n)],
            )
            det = M.det()
            if not check or det % self.p != 0:
                return M.change_ring(ring)


class DirectMatrixProductCryptosystem(BaseMatrixProductCryptosystem):
    def keygen(self, rand: Random):
        As = [self.rand_drawf(rand) for _ in range(self.k)]
        D = self.rand_drawf(rand)
        E = self.rand_elf(rand)
        Ei = E.inverse()
        priv = (As, D, E, Ei)
        pub = [E * A * D * Ei for A in As]
        return priv, pub

    def encrypt_perm(self, pub, perm):
        M = pub[perm[0]]
        for i in range(1, self.k):
            M = M * pub[perm[i]]
        return M

    def decompose(self, M, As, D, L):
        if len(L) == len(As):
            return
        if len(As) - 1 == len(L):
            idx = next(iter(set(range(len(As))) - set(L)))
            if As[idx] == M:
                return L + [idx]
            return
        threshold = self.n * (self.n - 1)
        for i, A in enumerate(As):
            if i in L:
                continue
            try:
                Mp = D.solve_right(A.solve_right(M))
            except ValueError:
                continue
            # if all(int(x) <= int(y) for x, y in zip(Mp.list(), M.list())):
            # this is a bit different from the paper
            # because the provided decryption algorithm in the paper often fail to decrypt till the end
            smaller_cnt = len(
                [1 for x, y in zip(Mp.list(), M.list()) if int(x) <= int(y)]
            )
            if smaller_cnt >= threshold:
                ret = self.decompose(Mp, As, D, L + [i])
                if ret is not None:
                    return ret

    def decrypt_perm(self, priv, M):
        As, D, E, Ei = priv
        R = Ei * M * E * ~D
        return self.decompose(R, As, D, [])

    def encode(self, m):
        P = Permutations(self.k)
        if m < 0 or m > P.cardinality():
            raise ValueError("Invalid message")
        return [x - 1 for x in P.unrank(m)]

    def decode(self, p):
        P = Permutations(self.k)
        return P.rank([x + 1 for x in p])

    def encrypt(self, pub, m):
        return self.encrypt_perm(pub, self.encode(m))

    def decrypt(self, priv, M):
        ret = self.decrypt_perm(priv, M)
        if ret is not None:
            return self.decode(ret)

    def randmsg(self, rand: Random):
        return rand.randrange(0, factorial(self.k))


class AlternatingMatrixProductCryptosystem(BaseMatrixProductCryptosystem):
    def rand_pair_drawf(self, rand: Random, lookup: dict):
        while True:
            A = self.rand_drawf(
                rand, check=False, ring=ZZ
            )  # computing determinant in ZZ is so much faster than in GF(p) ...
            d = A.det()
            if d == 0:
                continue
            if d in lookup and lookup[d] != A:
                AA = lookup.pop(d)
                return A.change_ring(self.F), AA.change_ring(self.F)
            lookup[d] = A

    def keygen(self, rand: Random):
        lookup = {}
        As = [self.rand_pair_drawf(rand, lookup) for _ in range(self.k)]
        Es = [self.rand_elf(rand) for _ in range(self.k + 1)]
        ABars = []
        for i in range(self.k):
            cur = []
            for b in (0, 1):
                cur.append(Es[i] * As[i][b] * ~Es[i + 1])
            ABars.append(cur)
        priv = (Es[0], Es[self.k], As)
        pub = ABars
        return priv, pub

    def encrypt_bits(self, pub, bits):
        M = pub[0][bits[0]]
        for i in range(1, self.k):
            M = M * pub[i][bits[i]]
        return M

    def decompose(self, M, As):
        threshold = self.n * (self.n - 1)
        bits = []
        for i in range(self.k):
            for b in (0, 1):
                A = As[i][b]
                try:
                    Mp = A.solve_right(M)
                except ValueError:
                    continue
                # if all(int(x) <= int(y) for x, y in zip(Mp.list(), M.list())):
                # this is a bit different from the paper
                # because the provided decryption algorithm in the paper often fail to decrypt till the end
                smaller_cnt = len(
                    [1 for x, y in zip(Mp.list(), M.list()) if int(x) <= int(y)]
                )
                if smaller_cnt >= threshold:
                    bits.append(b)
                    M = Mp
                    break
            else:
                return
        return bits

    def decrypt_bits(self, priv, M):
        E0, Ek, As = priv
        R = ~E0 * M * Ek
        return self.decompose(R, As)

    def encode(self, m):
        if m < 0 or m > 2**self.k:
            raise ValueError("Invalid message")
        return [(m >> i) & 1 for i in range(self.k)]

    def decode(self, p):
        return sum(x << i for i, x in enumerate(p))

    def encrypt(self, pub, m):
        return self.encrypt_bits(pub, self.encode(m))

    def decrypt(self, priv, M):
        ret = self.decrypt_bits(priv, M)
        if ret is not None:
            return self.decode(ret)

    def randmsg(self, rand: Random):
        return rand.getrandbits(self.k)


direct = DirectMatrixProductCryptosystem(
    10, 35, 2, 2**302 + 307
)  # Recommended size, 128-bit security
alternating = AlternatingMatrixProductCryptosystem(
    10, 128, 2, 2**553 + 549
)  # Recommended size, 128-bit security

if __name__ == "__main__":
    rand = SystemRandom()

    H = sha256()
    challenges = []
    for cry in (direct, alternating):
        priv, pub = cry.keygen(rand)
        msg = cry.randmsg(rand)
        M = cry.encrypt(pub, msg)
        if cry.decrypt(priv, M) != msg:
            raise ValueError("Decryption failed")
        H.update(str(msg).encode())
        challenges.append((pub, M))

    with open("flag.txt", "rb") as f:
        flag = f.read().strip()
    cipher = AES.new(H.digest(), AES.MODE_CTR)
    enc_flag = cipher.encrypt(flag)

    save(
        {"challenges": challenges, "enc_flag": enc_flag, "nonce": cipher.nonce},
        "output.sobj",
    )
    # additional note: this script is generated by running the script using SageMath 10.3
