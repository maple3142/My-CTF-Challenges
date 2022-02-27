# Futago

* Category: Crypto, CSC (Cursed Shaman Challenges, guessy challenges in TSJ CTF)

## Description

Who need source for RSA challenges?

## Overview

See the [README of this challenge](chall/README.md).

## Solution

### Stage 1

Guess that two public keys shares a prime, so you can factor it with gcd.

### Stage 2

Found out that $n_1=n_2$, but $e_1 \neq e_2$. Using common modulus attack with found that $\gcd(e_1,e_2)=3$, so you need to take the cube root over integers to decrypt the message.

### Stage 3

You got two seemingly normal 2048 bits RSA public key $n_1,n_2$, but it is easy to see $|n_1-n_2|$ is about 1024 bits only.

If you write them like this:

$$
\begin{aligned}
n_1 &= pq \\
n_2 &= (p+a)(q+b)
\end{aligned}
$$

Then substracting them:

$$
|n_1-n_2|=|pb+qa+ab|
$$

Suppose $p,q$ are balanced, this means $a,b$ needs to be really small to keep $|n_1-n_2|$ about 1024 bits only. So we have $p \approx p+a$ and $q \approx q+b$.

Then you can multiply them together:

$$
n_1 n_2 = pq(p+a)(q+b)
$$

It is easy to see $pq \approx (p+a)(q+b)$ and $p(q+b) \approx q(p+a)$ too. Running fermat factorization on $n_1 n_2$ will output these two pairs, and you can factor them with gcd.

```python
from Crypto.PublicKey import RSA
from Crypto.Util.number import *


def read_stage(stage):
    with open(f"{stage}/key1.pub", "rb") as f:
        key1 = RSA.import_key(f.read())
    with open(f"{stage}/key2.pub", "rb") as f:
        key2 = RSA.import_key(f.read())
    with open(f"{stage}/flag.txt.key1.enc", "rb") as f:
        c1 = bytes_to_long(f.read())
    with open(f"{stage}/flag.txt.key2.enc", "rb") as f:
        c2 = bytes_to_long(f.read())
    ret = (key1.n, key1.e, c1, key2.n, key2.e, c2)
    return map(ZZ, ret)


def solve1():
    n1, e1, c1, n2, e2, c2 = read_stage("stage1")
    p = gcd(n1, n2)
    q = n1 // p
    d = inverse_mod(e1, (p - 1) * (q - 1))
    m = power_mod(c1, d, n1)
    return long_to_bytes(m)


def solve2():
    n1, e1, c1, n2, e2, c2 = read_stage("stage2")
    g, a, b = xgcd(e1, e2)
    mg = power_mod(c1, a, n1) * power_mod(c2, b, n1) % n1
    m = mg.nth_root(g)
    return long_to_bytes(m)


def solve3():
    n1, e1, c1, n2, e2, c2 = read_stage("stage3")

    def fermat(x, mx):
        a = floor(sqrt(x))
        b2 = a * a - x
        cnt = 0
        while True:
            if is_square(b2):
                b = floor(sqrt(b2))
                yield a + b, a - b
            a += 1
            cnt += 1
            if cnt == mx:
                return
            b2 = a * a - x

    ar = list(fermat(n1 * n2, 1000000))
    # print(ar)
    assert len(ar) == 2
    assert set(ar[1]) == set([n1, n2])
    p1 = gcd(ar[0][1], n1)
    # print(p1)
    p2 = gcd(ar[0][0], n2)
    # print(p2)

    q1 = n1 // p1
    d1 = inverse_mod(e1, (p1 - 1) * (q1 - 1))
    m = power_mod(c1, d1, n1)
    return long_to_bytes(m)


print(solve1() + solve2() + solve3())
```
