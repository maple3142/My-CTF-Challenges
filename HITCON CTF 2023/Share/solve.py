from pwn import process, remote
from Crypto.Util.number import sieve_base, long_to_bytes
import ast
from sage.all import GF, crt

primes = list(sieve_base[6:46])  # product > 2**256

# io = process(["python", "server.py"])
io = remote("chal-share.chal.hitconctf.com", 11111)


def batch_oracle(queries):
    payload = "".join([f"{p}\n{n}\n" for p, n in queries])
    io.send(payload.encode())
    ret = []
    for _ in range(len(ps)):
        io.recvuntil(b"shares = ")
        ys = ast.literal_eval(io.recvlineS().strip())
        ret.append(ys)
    return zip(ps, ret)


n = 14
tbl = {p: set(range(p)) for p in primes}
while not all(len(tbl[p]) == 1 for p in primes):
    # a kinda stupid prime selection strategy
    ps = []
    for p in primes:
        if len(tbl[p]) > 1:
            ps += [p] * len(tbl[p]) * 2
    while len(ps) < 4 * max(ps):
        ps += ps
    print("query", len(ps))
    for p, ys in batch_oracle([(p, n) for p in ps]):
        # f(x)=-x^(n-1)+g(x)
        # find g(x) by interpolating (x, y + x^(n - 1)), then we have f(x)
        # note that the coefficient of f(x) must not be -1, so f(0) will be a impossible value of the real F(0)
        R = GF(p)["x"]
        g = R.lagrange_polynomial([(i + 1, y + (i + 1) ** (n - 1)) for i, y in enumerate(ys)])
        f = -R.gen() ** (n - 1) + g
        for i, y in enumerate(ys):
            assert f(i + 1) == y
        tbl[p].discard(f(0))
    for p in primes:
        print(p, tbl[p])

ms = [next(iter(tbl[p])) for p in primes]
secret = int(crt(ms, primes))
io.send(b"0\n0\n")
io.sendlineafter(b"secret = ", str(secret).encode())
print(io.recvallS().strip())
