from Crypto.Util.number import *

R = RealField(1100)  # log2(10^-320) ~= 320/0.301 ~= -1063
Decimal = R  # for exec

with open("output.txt") as f:
    exec(f.read())


def approx(ab: R):
    for c in continued_fraction(QQ(ab)).convergents():
        a = c.numer()
        b = c.denom()
        if a == 0 or b == 0:
            continue
        yield a, b


def solve(a, b, c):
    D = b ^ 2 - 4 * a * c
    if is_square(D):
        return (-b + sqrt(D)) // (2 * a), (-b - sqrt(D)) // (2 * a)


e = 65537

for p, qmr in approx(k):
    if p != 1 and n % p == 0:
        qr = n // p
        # (x-48763q)(x+r)=x^2-(48763q-r)x-48763qr
        q, r = solve(1, -qmr, -48763 * qr)
        q //= 48763
        r *= -1
        print(p, q, r)
        assert p * q * r == n
        phi = (p - 1) * (q - 1) * (r - 1)
        d = inverse(e, phi)
        m = power_mod(c, d, n)
        assert power_mod(m, e, n) == c
        print(long_to_bytes(m))
