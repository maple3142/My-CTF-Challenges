from Crypto.Util.number import long_to_bytes
import gmpy2

with open("output.txt") as f:
    exec(f.read())

xy = gmpy2.iroot(n, 2)[0] - 1
phi = xy**2
d = gmpy2.invert(e, phi)
m = pow(c, d, n)
print(long_to_bytes(m))
