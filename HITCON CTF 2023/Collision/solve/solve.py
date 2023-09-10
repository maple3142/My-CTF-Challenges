from pwn import process, remote, context
import string
from tempfile import NamedTemporaryFile
import subprocess
import struct
import os
import sys
import time

MASK_64 = 0xFFFFFFFFFFFFFFFF
MASK_32 = 0xFFFFFFFF


def rotate(x, b):
    return ((x << b) | (x >> (64 - b))) & MASK_64


def half_round(a, b, c, d, s, t):
    a += b
    c += d
    a &= MASK_64
    c &= MASK_64
    b = rotate(b, s) ^ a
    d = rotate(d, t) ^ c
    a = rotate(a, 32)
    return a, b, c, d


def single_round(v0, v1, v2, v3):
    v0, v1, v2, v3 = half_round(v0, v1, v2, v3, 13, 16)
    v2, v1, v0, v3 = half_round(v2, v1, v0, v3, 17, 21)
    return v0, v1, v2, v3


def siphash13(k0, k1, buf):
    b = len(buf) << 56
    b &= MASK_64
    v0 = k0 ^ 0x736F6D6570736575
    v1 = k1 ^ 0x646F72616E646F6D
    v2 = k0 ^ 0x6C7967656E657261
    v3 = k1 ^ 0x7465646279746573

    while len(buf) >= 8:
        mi = int.from_bytes(buf[:8], "little")
        v3 ^= mi
        v0, v1, v2, v3 = single_round(v0, v1, v2, v3)
        v0 ^= mi
        buf = buf[8:]

    if len(buf) > 0:
        b |= int.from_bytes(buf, "little")
    v3 ^= b
    v0, v1, v2, v3 = single_round(v0, v1, v2, v3)
    v0 ^= b

    v2 ^= 0xFF
    v0, v1, v2, v3 = single_round(v0, v1, v2, v3)
    v0, v1, v2, v3 = single_round(v0, v1, v2, v3)
    v0, v1, v2, v3 = single_round(v0, v1, v2, v3)

    return (v0 ^ v1) ^ (v2 ^ v3)


def lcg_urandom(x0, sz):
    x = x0
    for _ in range(sz):
        x = (214013 * x + 2531011) & MASK_32
        yield x


io = remote("chal-collision.chal.hitconctf.com", 33333)
# io = process(["python", "server.py"])


def oracle(msg: bytes):
    io.sendlineafter(b"m1: ", msg.hex().encode())
    io.sendlineafter(b"m2: ", msg.hex().encode() + b"00")
    return int(io.recvline().split(b" != ")[0])


def get_seed(salt):
    with NamedTemporaryFile() as f:
        subprocess.run(["gcc", "gen_tbl.c", "-O2", "-Wall", "-o", "./gen_tbl"])
        p = subprocess.run(["./gen_tbl", f.name, salt.hex()])
        p.check_returncode()
        tbl = struct.unpack(f"{1 << 24}Q", f.read())
        return tbl.index(oracle(b"") & MASK_64)


for _ in range(8):
    print("=" * 40)
    print(f"Round #{_}")
    io.recvuntil(b"salt: ")
    salt = bytes.fromhex(io.recvlineS().strip())
    print("salt =", salt.hex())

    seed = get_seed(salt)
    print(f"{seed = }")
    siphash_key = bytes([(x >> 16) & 0xFF for x in lcg_urandom(seed, 16)])
    k0 = int.from_bytes(siphash_key[:8], "little")
    k1 = int.from_bytes(siphash_key[8:], "little")

    def rhash(x):
        return siphash13(k0, k1, x)

    # sanity check
    assert rhash(salt + b"peko") == oracle(b"peko") & MASK_64

    prefix = int.from_bytes(salt, "little")
    p = subprocess.run(
        [
            "g++",
            "collide_lambda.cpp",
            "-Ofast",
            "-march=native",
            "-mtune=native",
            "-Wall",
            f"-Dk0={k0}ull",
            f"-Dk1={k1}ull",
            f"-Dprefix={prefix}ull",
            "-o",
            "./collider",
        ]
    )
    # p = subprocess.run(
    #     [
    #         "gcc",
    #         "collide.c",
    #         "-Ofast",
    #         "-march=native",
    #         "-Wall",
    #         f"-Dk0={k0}ull",
    #         f"-Dk1={k1}ull",
    #         f"-Dprefix={prefix}ull",
    #         "-o",
    #         "./collider",
    #     ]
    # )
    p.check_returncode()
    start_t = time.time()
    p = subprocess.run(
        ["./collider"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=40
    )
    p.check_returncode()
    print("time =", time.time() - start_t)
    m1h, m2h = p.stdout.split()
    m1 = int(m1h, 16).to_bytes(8, "little")
    m2 = int(m2h, 16).to_bytes(8, "little")
    assert rhash(salt + m1) == rhash(salt + m2)
    print(m1.hex(), rhash(salt + m1))
    print(m2.hex(), rhash(salt + m2))

    io.sendlineafter(b"m1: ", m1.hex().encode())
    io.sendlineafter(b"m2: ", m2.hex().encode())
print(io.recvallS().strip())
