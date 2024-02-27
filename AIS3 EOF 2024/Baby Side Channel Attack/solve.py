import gzip
import gmpy2
from Crypto.Util.number import sieve_base


def clean(n):
    for p in sieve_base:
        while n % p == 0:
            n //= p
    return n


def get_bits(f):
    bits = []
    for line in f:
        if "return r" in line:
            break
        if "if b & 1:" in line:
            nl = next(f)
            if "r = r * a % c" in nl:
                bits.append(1)
            elif "a = a * a % c" in nl:
                bits.append(0)
    return int("".join(map(str, bits[::-1])), 2)


with gzip.open("trace.txt.gz", "rt") as f:
    for line in f:
        if "c = powmod(m, e, n)" in line:
            break
    e = get_bits(f)
    for line in f:
        if "assert powmod(c, d, n) == m" in line:
            break
    d = get_bits(f)

    print(f"{e = }")
    print(f"{d = }")

    for line in f:
        if (
            line.startswith("c = ")
            or line.startswith("ed = ")
            or line.startswith("de = ")
        ):
            exec(line)

    n = int(clean(gmpy2.gcd(gmpy2.mpz(ed) ** e - e, gmpy2.mpz(d) ** e - de)))
    print(f"{n = }")

    m = pow(c, d, n)
    flag = m.to_bytes(-(-m.bit_length() // 8), "big")
    print(flag)
