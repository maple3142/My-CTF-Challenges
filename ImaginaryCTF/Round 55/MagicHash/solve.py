import os
import pickle
import subprocess
from base64 import b64encode
from hashlib import md5, sha3_256
from pathlib import Path
from tempfile import TemporaryDirectory
from zlib import crc32

from sage.all import *
from tqdm import trange


def magic_hash(x):
    h = md5(x).digest()
    h += crc32(h + x).to_bytes(4, "little")
    return sha3_256(h).digest()


def fastcoll(
    prefix=b"", *, fastcool_bin=os.path.expanduser("~/workspace/fastcoll/fastcoll")
):
    with TemporaryDirectory() as dir:
        with open(dir + "/prefix", "wb") as f:
            f.write(prefix)
        subprocess.run(
            [
                fastcool_bin,
                "-p",
                "prefix",
                "-o",
                "out1",
                "-o",
                "out2",
            ],
            cwd=dir,
            stdout=subprocess.DEVNULL,
            check=True,
        )
        with open(dir + "/out1", "rb") as f:
            m1 = f.read()
        with open(dir + "/out2", "rb") as f:
            m2 = f.read()
    return m1[len(prefix) :], m2[len(prefix) :]


def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])


def get_collision_pairs(n: int):
    collisions = Path(__file__).parent / f"collisions_{n}.pkl"
    if collisions.exists():
        with collisions.open("rb") as f:
            return pickle.load(f)
    pairs = []
    prev = b""
    for _ in trange(n):
        ma, mb = fastcoll(prev)
        pairs.append((ma, mb))
        prev += ma
    with collisions.open("wb") as f:
        pickle.dump(pairs, f)
    return pairs


n = 32 + 1
pairs = get_collision_pairs(n)

base = b"".join([ma for ma, _ in pairs])
deltas = []
for i in range(n):
    dt = b"".join(
        [
            b"\x00" * len(ma) if j != i else xor(ma, mb)
            for j, (ma, mb) in enumerate(pairs)
        ]
    )
    deltas.append(dt)
    assert md5(xor(base, dt)).digest() == md5(base).digest()


def i2v(i):
    return vector([int(b) for b in f"{i:032b}"])


cz = crc32(b"\x00" * len(base))
cds = [crc32(dt) ^ cz for dt in deltas]
M = matrix(GF(2), [i2v(cd) for cd in cds])
ker = M.left_kernel()


def compute_delta(zv, deltas):
    t = b"\x00" * len(base)
    for b, dt in zip(zv, deltas):
        if b:
            t = xor(t, dt)
    return t


t0 = compute_delta(ker[0], deltas)
t1 = compute_delta(ker[1], deltas)
m1 = xor(base, t0)
m2 = xor(base, t1)
assert m1 != m2 and magic_hash(m1) == magic_hash(m2)
print(b64encode(m1).decode())
print(b64encode(m2).decode())
