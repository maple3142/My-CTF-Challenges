from pwn import process, remote
from gmpy2 import iroot
from random import Random
from sage.all import Zmod, PolynomialRing
from Crypto.Util.number import long_to_bytes
from tqdm import tqdm

N_BITS = 1024
PAD_SIZE = 64

# io = process(["python", "server.py"], env={"FLAG": "AIS3{bad_padding_and_bad_random}"})
io = remote("localhost", 6007)
io.recvuntil(b"n = ")
n = int(io.recvlineS().strip())
e = 11


def get_enc(x):
    io.sendlineafter(b"> ", x)
    return int(io.recvlineS().strip())


k = 0
for _ in range(N_BITS // PAD_SIZE):
    k = (k << PAD_SIZE) | 1
kinv = pow(k, -e, n)


def get_outputs():
    c = get_enc(b"0")
    r, exact = iroot((kinv * c) % n, 11)
    assert exact
    r = int(r)
    return [r & 0xFFFFFFFF, r >> 32]


# Modified from https://github.com/eboda/mersenne-twister-recover
class MT19937Recover:
    """Reverses the Mersenne Twister based on 624 observed outputs.
    The internal state of a Mersenne Twister can be recovered by observing
    624 generated outputs of it. However, if those are not directly
    observed following a twist, another output is required to restore the
    internal index.
    See also https://en.wikipedia.org/wiki/Mersenne_Twister#Pseudocode .
    """

    def unshiftRight(self, x, shift):
        res = x
        for i in range(32):
            res = x ^ res >> shift
        return res

    def unshiftLeft(self, x, shift, mask):
        res = x
        for i in range(32):
            res = x ^ (res << shift & mask)
        return res

    def untemper(self, v):
        """Reverses the tempering which is applied to outputs of MT19937"""

        v = self.unshiftRight(v, 18)
        v = self.unshiftLeft(v, 15, 0xEFC60000)
        v = self.unshiftLeft(v, 7, 0x9D2C5680)
        v = self.unshiftRight(v, 11)
        return v

    def go(self, outputs, forward=True):
        """Reverses the Mersenne Twister based on 624 observed values.
        Args:
            outputs (List[int]): list of >= 624 observed outputs from the PRNG.
                However, >= 625 outputs are required to correctly recover
                the internal index.
            forward (bool): Forward internal state until all observed outputs
                are generated.
        Returns:
            Returns a random.Random() object.
        """

        result_state = None

        assert len(outputs) >= 624  # need at least 624 values

        ivals = []
        for i in range(624):
            ivals.append(self.untemper(outputs[i]))

        if len(outputs) >= 625:
            # We have additional outputs and can correctly
            # recover the internal index by bruteforce
            challenge = outputs[624]
            for i in range(1, 626):
                state = (3, tuple(ivals + [i]), None)
                r = Random()
                r.setstate(state)

                if challenge == r.getrandbits(32):
                    result_state = state
                    break
        else:
            # With only 624 outputs we assume they were the first observed 624
            # outputs after a twist -->  we set the internal index to 624.
            result_state = (3, tuple(ivals + [624]), None)

        rand = Random()
        rand.setstate(result_state)

        if forward:
            for i in range(624, len(outputs)):
                assert rand.getrandbits(32) == outputs[i]

        return rand


pb = tqdm(desc="Retrieving outputs", total=624)
outputs = []
while len(outputs) < 624:
    outputs += get_outputs()
    pb.n = len(outputs)
    pb.update()
mt = MT19937Recover()
rand = mt.go(outputs)


def generate_padding(rand):
    pad = rand.getrandbits(PAD_SIZE)
    s = 0
    for _ in range(N_BITS // PAD_SIZE):
        s = (s << PAD_SIZE) | pad
    return s


c1 = get_enc(b"flag")
pad1 = generate_padding(rand)
c2 = get_enc(b"flag")
pad2 = generate_padding(rand)

# (flag+pad1)^e=c1
# (flag+pad2)^e=c2
Z = Zmod(n)
P = PolynomialRing(Z, "x")
x = P.gen()
f = (x + pad1) ** e - c1
g = (x + pad2) ** e - c2

# sage doesn't have gcd for polynomial over a ring
# so we need to implement it ourselves
while g:
    f, g = g, f % g
f = f.monic()
print(long_to_bytes(int(-f[0])).decode())
