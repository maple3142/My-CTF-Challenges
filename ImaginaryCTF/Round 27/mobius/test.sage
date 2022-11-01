from Crypto.Util.number import *


def getSmoothPrime(n, b):
    x = 2 * product([getPrime(b) for _ in range(n // b)])
    while True:
        xx = x * getPrime(n - x.bit_length())
        p = xx + 1
        if isPrime(p):
            return p


# p = getSmoothPrime(512, 20)
# p = 11154565239377417572227960096490077907071771644338898410399665966279877320650175062389127631246804195722261468253469000475391065387075323577166903606791749
p = getPrime(1024)
print(f"{p = }")
flag = b"FLAG{test_flag_hello_world_1234}"
flag = b"ictf{test_flag_hello_world_1234}"
flag = b"ictf{it_is_always_about_matrix!}"
assert len(flag) == 32
x = ZZ(int.from_bytes(flag[: len(flag) // 2], "big"))
y = ZZ(int.from_bytes(flag[len(flag) // 2 :], "big"))


def f(x):
    return (1 * x + 3) / (3 * x + 7) % p


r = (x / y) % p
M = matrix(GF(p), [[1, 3], [3, 7]])
od = product([p ^ 2 - p ^ i for i in range(2)])
d = 1337
u, v = M ^ power_mod(2, (1 << d), od) * vector([r, 1])
target = (u / v) % p
print(f"{target = }")
