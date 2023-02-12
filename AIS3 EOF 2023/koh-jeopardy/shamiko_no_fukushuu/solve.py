from pwn import process, remote, context
from server import sign, verify
from fastecdsa.curve import secp256k1
from hashlib import sha256
import ast

# context.log_level = "debug"
io = process(["python", "server.py"])
# io = remote("localhost", 10006)


def remote_sign(name: bytes):
    io.sendlineafter(b">", b"1")
    io.sendlineafter(b": ", name)
    return ast.literal_eval(io.recvlineS())


def H(m: bytes):
    return int.from_bytes(sha256(m).digest(), "big")


m1 = b"peko"
m2 = m1 + b"\x00"
r1, s1 = remote_sign(m1)
r2, s2 = remote_sign(m2)
assert r1 == r2
q = secp256k1.q
k = ((H(m1) - H(m2)) * pow(s1 - s2, -1, q)) % q
x = ((s1 * k - H(m1)) * pow(r1, -1, q)) % q

sig = sign(b"shamiko", x)
io.sendlineafter(b">", b"2")
io.sendlineafter(b": ", b"shamiko")
io.sendlineafter(b": ", repr(sig).encode())
io.interactive()
