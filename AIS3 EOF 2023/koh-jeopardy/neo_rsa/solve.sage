from Crypto.Util.number import long_to_bytes
import itertools

with open("output.txt") as f:
    exec(f.read())

P = Zmod(n)["x"]
x = P.gen()
f = power_mod(c2, n, n) - x
# r = ZZ(small_roots(f, (2 ** 256,), m=4, t=8)[0][0])
r = ZZ(f.monic().small_roots(X=2**256, beta=0.49)[0])
fz = f.change_ring(ZZ)
q = gcd(fz(r), n)
p = n // q
print(long_to_bytes(power_mod(c1, p, n)))
