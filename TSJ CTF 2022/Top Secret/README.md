# Top Secret

* Category: Crypro
* Score: 325/500
* Solves: 9/428

## Description

In year 2087, the TSJ corporation invented a new patented stream cipher to protect their communication. One day, another member stole an important file from the CEO's computer, but it turns out to be encrypted. Fortunately, the script used to encrypt the file were stolen too. You, as a member of Nantou Resistance, accept the challenge to decrypt it.

## Overview

This is a weird stream cipher that has an internal state `s`, and it will update its state using the `forward`/`fast_forward` function:

```python
def forward(s: int, n: int, k: int) -> int:
    for _ in range(n):
        s = (s >> 1) ^ ((s & 1) * k)
    return s
```

The `k` is a known constant, and the `n` is the key of the cipher. The initialize state of the cipher is fixed too. The objective is to decrypt a PNG encrypted by it.

## Solution

First, it is necessary to understand the meaning of `s = (s >> 1) ^ ((s & 1) * k)`. If you ever tried to read the implementation of AES, you may find that it is pretty similar to the `xtime` operation. ([An example in C](https://github.com/kokke/tiny-AES-c/blob/f06ac37fc31dfdaca2e0d9bec83f90d5663c319b/aes.c#L294))

`xtime` operation means multiplying an $GF(2^8)$ element by $x$, and each element is represented by a polynomial of $x$, modulo $x^8+x^4+x^3+x+1$. In AES, the lowest bit represents $x^0$, and the highest bit represents $x^7$.

In this challenge, the order of bits are swapped, so the bit shifting direction are different. And the constant `k` obvious represents a 128 degree polynomial...?

Actually, `key = randbelow(2 ** 128)` is meant to confuse people. If you try to construct the polynomial by `f'{k:0128b}1'` you will see it is not a prime polynomial, because its leftmost bit is `0`. The correct degree is 127, so you can construct the field in Sage and implements `fast_forward` like this:

```python
from sage.all import GF, var


def fast_forward(s, n, k):
    x = var("x")
    coefs = [int(x) for x in (f"{k:0127b}1")]
    poly = sum(c * x ** i for i, c in enumerate(coefs))
    F = GF(2 ** 127, "a", modulus=poly)
    a = F.gen()
    s_coefs = [int(x) for x in f"{s:0127b}"]
    ss = sum(c * a ** i for i, c in enumerate(s_coefs))
    sn = ss * a ** n
    return int("".join(map(str, sn.polynomial().list())).ljust(127, "0"), 2)
```

The next step is to observe that the first 16 bytes of PNG is known, not just 8 bytes, because of the IHDR chunk. Xor the first chunk of ciphertext and the first 16 bytes of PNG gives second state of the cipher. This can be written as:

$$
s_1 = x^{key} s_0 \implies s_1 s_0^{-1} = x^key
$$

So this is a discrete log problem in $GF(2^{127})$. Unfortunately, $2^{127}-1$ is a mersenne prime, so you can't use Pohlig–Hellman to compute $key$.

The intended way is to use [Fast Evaluation of Logarithms in Fields of Characteristic Two ](https://pages.cs.wisc.edu/~cs812-1/coppersmith.pdf), which can solve discrete log in this size easily, and it is [implemented in pari](https://pari.math.u-bordeaux.fr/dochtml/html/Arithmetic_functions.html#fflog) too.

In Sage, you can just use `pari.fflog(e, g)` to find `x` such that `g^x == e`. In newer version of Sage (9.5 or above), `e.log(g)` works too.

```python
from sage.all import var, GF, pari

s = 0x6BF1B9BAE2CA5BC9C7EF4BCD5AADBC47
k = 0x5C2B76970103D4EEFCD4A2C681CC400D

x = var("x")
coefs = [int(x) for x in (f"{k:0127b}1")]
poly = sum(c * x ** i for i, c in enumerate(coefs))
F = GF(2 ** 127, "a", modulus=poly)
alpha = F.gen()


def int2el(r):
    return sum(c * alpha ** i for i, c in enumerate(int(x) for x in f"{r:0127b}"))


with open("flag.png.enc", "rb") as f:
    data = f.read()

pngheader = bytes.fromhex("89504E470D0A1A0A0000000d49484452")

ks = bytes(x ^ y for x, y in zip(data, pngheader))
A = int2el(s)
B = int2el(int.from_bytes(ks, "big"))
key = int(pari.fflog(B / A, alpha))  # https://trac.sagemath.org/ticket/32842

from challenge import Cipher

with open("flag.png", "wb") as f:
    f.write(Cipher(key).decrypt(data))
```

By the way, @Utaha tells me that it is not necessary to compute the discrete log to solve this challenge. Because the key stream is just $x^{key}s_0, (x^{key})^2 s_0, (x^{key})^3 s_0 \cdots$ like a geometric progression. And $x^{key}$ can be simply computed by $s_0 s_1^{-1}$, so it is enough to decrypt the flag actually.
