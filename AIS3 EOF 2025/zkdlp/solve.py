from pwn import process, remote
from server import p, q, g
from gf2bv.crypto.mt import MT19937
from gf2bv import LinearSystem


def get_batch(io, n):
    io.send(b"1\n1\n" * n)
    for _ in range(n):
        io.recvuntil(b"c = ")
        yield int(io.recvline().strip())


N = 32
cut = 10
prob = q / 2 ** q.bit_length()
print("prob", prob)
print("success probability", prob**cut)


attempts = 0
while True:
    print("attempt", attempts)
    attempts += 1
    io = process(["python", "server.py"])
    # io = remote("localhost", 11337)
    io.recvuntil(b"y = ")
    y = int(io.recvline().strip())
    outs = list(get_batch(io, N))
    lin = LinearSystem([32] * 624)
    mt = lin.gens()
    rng = MT19937(mt)
    zeros = [mt[0] ^ 0x80000000] + [
        rng.getrandbits(q.bit_length()) ^ o for o in outs[:cut]
    ]
    sol = lin.solve_one(zeros)
    if sol:
        print("Success")
        break
    print("Failed")
    io.close()

print("start iterative solving")
skips = [0] * cut
while len(skips) < N:
    for i in range(100):
        new_skips = skips + [i]
        rng = MT19937(mt)
        zeros = [mt[0] ^ 0x80000000]
        for c, sk in zip(outs, new_skips):
            for _ in range(sk + 1):
                t = rng.getrandbits(q.bit_length())
            zeros.append(c ^ t)
        print(new_skips)
        print("solving...")
        space = lin.solve_raw_space(zeros)
        if not space:
            continue
        break
    print("dim", space.dimension)
    sol = lin.convert_sol(space.origin)
    skips = new_skips
    if space.dimension == 0:
        break

rand = MT19937(sol).to_python_random()
for c in outs:
    assert rand.randrange(q) == c

for _ in range(10):
    c = rand.randrange(q)
    s = 48763
    t = pow(g, s, p) * pow(y, -c, p) % p
    io.sendlineafter(b"t = ", str(t).encode())
    io.sendlineafter(b"s = ", str(s).encode())
io.interactive()
