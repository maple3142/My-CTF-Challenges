#!/usr/bin/env python3
import os
from base64 import b64decode
from hashlib import md5, sha3_256
from zlib import crc32


def magic_hash(x):
    h = md5(x).digest()
    h += crc32(h + x).to_bytes(4, "little")
    return sha3_256(h).digest()


def input_bytes(prompt):
    return b64decode(input(prompt).strip(), validate=True)


if __name__ == "__main__":
    flag = os.environ.get("FLAG", "flag{test}")
    m1 = input_bytes("m1: ")
    m2 = input_bytes("m2: ")
    if max(len(m1), len(m2)) <= 4321 and m1 != m2 and magic_hash(m1) == magic_hash(m2):
        print(flag)
