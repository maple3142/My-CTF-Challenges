from pwn import process, remote, context
from server import *
from binteger import Bin
from tqdm import trange

trunc = 12
state_bits = PUBLIC_KEY_SIZE * 8 - trunc
#io = process(["python", "server.py"])
io = remote("34.90.212.120", 1337)
io.sendline(b"\n".join(b"1" for _ in range(2 * state_bits)))

bits = []
for i in range(2 * state_bits):
    io.recvuntil(b"> ")
    bits.append(int(b"win" in io.recvline()))
o1 = Bin(bits[:state_bits][::-1]).int
o2 = Bin(bits[state_bits:][::-1]).int

phi = priv_from([-x for x in leet])
for r in trange(2**trunc):
    try:
        O1 = pub_from((o1 + (r << state_bits)).to_bytes(PUBLIC_KEY_SIZE, "little"))
        l3 = hash_to_priv(apply_iso(O1, phi))
    except RuntimeError:
        pass
    try:
        O2 = pub_from((o2 + (r << state_bits)).to_bytes(PUBLIC_KEY_SIZE, "little"))
        r3 = hash_to_priv(apply_iso(O2, phi))
    except RuntimeError:
        pass

rng2 = RNG(c1, c2, l3, r3)
bits = Bin(
    int.from_bytes(bytes(apply_iso(apply_iso(c2, r3), l3)), "little"),
    n=PUBLIC_KEY_SIZE * 8,
).list[::-1][:state_bits]
bits += [rng2.bit() for _ in range(13337 - len(bits))]
io.sendline("\n".join(map(str, bits)).encode())
io.recvuntil(b"$13337 left.\n")
io.interactive()
