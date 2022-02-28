# Cipher Switching Service

* Category: Crypto
* Score: 416/500
* Solves: 4/854

## Description

You can freely swap the encrypted flag between two cryptosystem, but you still don't know what is the flag.

## Overview

The server prints one 1024 bits RSA public key and one 1024 bits ElGamal public key on connection, and gives an RSA encrypted randomly padded flag (padded length is 96 bytes). The length of the flag is 20.

Server supports two operations, allowing you to decrypt a RSA ciphertext and encrypt it using ElGamal, and vice versa.

## Solution

> Note: There is a much more simpler unintended solution idea from @Mystiz, scroll to the bottom to see

Using the homomorphic property of RSA, we can get any ciphertext of $am \bmod{n}$. ElGamal is encrypted as $c_1=g^r, c_2=y^r m$ for some random number $r$ and public key $y=g^x$.

I use $L(x,y)$ to denote [Legendre Symbol](https://en.wikipedia.org/wiki/Legendre_symbol) here because it is hard to type in Latex. Obviously, $L(c_2,p)=L(y^r,p) L(m,p)=L(g,p)^{rx} L(m,p)$. Also, by how $g$ is generated, it is easy to see $L(g,p)=1$, so we have $L(m,p)=L(c_2,p)$.

When it decrypts $a^e m^e$ with RSA private, it actually gives $am \bmod{n}$, so it is $L(c_2,p)=L(am \bmod{n},p)$ actually.

Suppose $am \lt n$, $am \bmod{n}$ is just $am$, so $L(c_2,p)=L(a,p) L(m,p)$ should hold. If $am \ge n$, $L(c_2,p)=L(a,p) L(m,p)$ might not hold. From this, it is possible find $a$ such that $am \approx n$ with binary search, so the flag $m$ is approximately $\lfloor\frac{n}{a}\rfloor$.

Since the oracle is not really robust, might need to use some heuristic to make it more stable.

```python
from pwn import *
import ast
from Crypto.Util.number import *
from gmpy2 import powmod as pow


def to_elgamal(c):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"c = ", str(c).encode())
    return ast.literal_eval(io.recvlineS())


def to_rsa(c1, c2):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"c1 = ", str(c1).encode())
    io.sendlineafter(b"c2 = ", str(c2).encode())
    return int(io.recvlineS())


def legendre(a, p):
    return pow(a, (p - 1) // 2, p)


io = remote("localhost", 8763)
io.recvuntil(b"RSA")
n, e = ast.literal_eval(io.recvlineS())
io.recvuntil(b"ElGamal")
p, g, y = ast.literal_eval(io.recvlineS())
io.recvuntil(b"len(flag) = ")
flagln = ast.literal_eval(io.recvlineS())
io.recvuntil(b"flagenc = ")
c = ast.literal_eval(io.recvlineS())
assert legendre(g, p) == 1


def legendre(a, p):
    r = pow(a, (p - 1) // 2, p)
    return r if r != p - 1 else -1


cnt = 0


def get_legendre(a):
    # get legendre((a * m) % n, p)
    global cnt
    cnt += 1
    ca = pow(a, e, n)
    cc = (ca * c) % n
    c1, c2 = to_elgamal(cc)
    lc2 = legendre(c2, p)
    return lc2


ln = 96
k_lb = int.from_bytes(b"TSJ{" + b"\x00" * (ln - 4), "big")
k_ub = int.from_bytes(b"TSJ{" + b"\xff" * (ln - 4), "big")
a_lb = n // k_ub
a_ub = n // k_lb

expected = get_legendre(1)


def oracle(a, b):
    # return True if a * k < n
    # no guarantee
    for i in range(a - b, a + b):
        if get_legendre(i) * legendre(i, p) != expected:
            return False
    return True


b = 3  # 3~4 is the best
t = 10
until = (a_ub - a_lb).bit_length() - (flagln - 4) * 8 - 5


def search(l, r, hist):
    # dfs with some pruning
    global b
    if (r - l).bit_length() < until:
        for aa in range(l, r):
            f = long_to_bytes(n // aa)
            if f.startswith(b"TSJ{"):
                print(f)
                break
        print(f"{cnt = }")
        exit()
    if sum(hist[-t:]) >= t or sum(hist[-t:]) <= -t:
        # because oracle may have false positive
        # discard current branch if it is search on a single direction
        print("bad", f"{t = }")
        b = min(b + 1, 10)  # increase bruteforcing window
        return t  # rewind t recursive call
    print((r - l).bit_length(), b)
    m = (r + l) // 2
    while True:
        if oracle(m, b):
            r = search(m, r, hist + [1])
            if r is not None and r > 0:
                return r - 1
        else:
            r = search(l, m, hist + [-1])
            if r is not None and r > 0:
                return r - 1
        if r != 0:
            break


search(a_lb, a_ub, [])
```

An unintended solution by @Mystiz is to find a $k$ such that $km$ is just *slightly* above $p$, this means $km \bmod{p}$ is $km-p$. By using homomorphic property of ElGamal you can get the RSA ciphertext of $km \bmod{p}$, which is just $(km-p)^e$. And you can just do $\gcd(m^e-c,(km-p)^e-c')$ to find the plaintext.
