from Crypto.Util.number import getPrime, bytes_to_long
import os


def powmod(a, b, c):
    r = 1
    while b > 0:
        if b & 1:
            r = r * a % c
        a = a * a % c
        b >>= 1
    return r


def keygen(b):
    p = getPrime(b // 2)
    q = getPrime(b // 2)
    n = p * q
    e = 65537
    d = pow(e, -1, (p - 1) * (q - 1))
    return n, e, d


def main():
    flag = os.environ.get("FLAG", "not_flag{just_test}").encode()

    n, e, d = keygen(2048)
    m = bytes_to_long(flag)

    c = powmod(m, e, n)
    assert powmod(c, d, n) == m
    print(f"{c = }")

    ed = powmod(e, d, n)
    de = powmod(d, e, n)
    print(f"{ed = }")
    print(f"{de = }")


if __name__ == "__main__":
    main()
    # to generate trace.txt.gz:
    # execute `python -m trace --ignore-dir=$(python -c 'import sys; print(":".join(sys.path)[1:])') -t chall.py | gzip > trace.txt.gz`
