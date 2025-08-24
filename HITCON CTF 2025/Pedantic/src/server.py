#!/usr/bin/env python3
import hashlib
import json
import os
import secrets

from fastecdsa.curve import secp256k1
from fastecdsa.point import Point

p = secp256k1.p
q = secp256k1.q
G = secp256k1.G
field_bytes = (p.bit_length() + 7) // 8
scalar_bytes = (q.bit_length() + 7) // 8


def encode_point(pt: Point):
    return pt.x.to_bytes(field_bytes, "big") + pt.y.to_bytes(field_bytes, "big")


def decode_point(data: bytes):
    if len(data) != 2 * field_bytes:
        raise ValueError("Invalid point encoding")
    x = int.from_bytes(data[:field_bytes], "big")
    y = int.from_bytes(data[field_bytes:], "big")
    return Point(x, y, secp256k1)


def hash_point(pt: Point):
    h = hashlib.sha256(encode_point(pt)).digest()
    return int.from_bytes(h, "big") % q


def hash_points_to_scalars(pts: list[Point], n: int):
    s = sum([hash_point(pt) for pt in pts]) % q
    ret = []
    for _ in range(n):
        ret.append(s)
        s = (1337 * s + 7331) % q
    return ret


ProofType = list[tuple[Point, int]]


def prove(x: int, n: int) -> ProofType:
    rs = [secrets.randbelow(q) for _ in range(n)]
    Grs = [G * r for r in rs]
    cs = hash_points_to_scalars(Grs, n)
    zs = [(r + c * x) % q for r, c in zip(rs, cs)]
    return list(zip(Grs, zs))


def verify(Y: Point, proof: ProofType):
    Grs, zs = zip(*proof)
    n = len(Grs)
    cs = hash_points_to_scalars(Grs, n)
    return all(G * z == Gr + Y * c for Gr, z, c in zip(Grs, zs, cs)) * n


def serialize_proof(proof: ProofType):
    return json.dumps([(encode_point(pt).hex(), z) for pt, z in proof])


def deserialize_proof(s: str) -> ProofType:
    return [(decode_point(bytes.fromhex(pt)), z) for pt, z in json.loads(s)]


def main():
    flag = os.environ.get("FLAG", "flag{test}")

    sk = int.from_bytes(hashlib.sha256(flag.encode()).digest(), "big") % q
    pk = G * sk

    print("Hey, I know the flag!")
    proof = prove(sk, 10)
    assert verify(pk, proof) == 10, "wtf"
    print("Here is the proof:")
    print(serialize_proof(proof))
    print("Do you know it too?")
    proof = deserialize_proof(input("proof:"))
    n = verify(pk, proof)
    if n >= 42:
        print("I am convined :D")
        print(f"Here is it: {flag}")
    elif n > 0:
        print("Hmm, not sure about that... :thinking:")
    else:
        print("I think you don't :(")


if __name__ == "__main__":
    main()
