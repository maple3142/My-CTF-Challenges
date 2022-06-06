# Fast Cipher

* Category: Crypto
* Score: 100/500
* Solves: 125/286
* Score(MFCTF): 340/500
* Solves(MFCTF): 20/124

## Description

![還要更快](fast.png)

## Overview

題目有個自創的 stream cipher，key 足足有 1024 bits 的大小。加密方法是透過取 key 的 lowest 8 bits 和 plaintext 的字元 xor，然後使用 `key = f(key)` 更新之。

## Solution

解題關鍵在於函數 `f(x)` 的設計:

```python
M = 2**1024


def f(x):
    # this is a *fast* function
    return (
        4 * x**4 + 8 * x**8 + 7 * x**7 + 6 * x**6 + 3 * x**3 + 0x48763
    ) % M
```

可以知道 $f(x)$ 是個多項式 mod M，其中 M 是 2 的次方。這邊需要用到一個數論中很基本的定理:

$$
x \equiv y \pmod{ab} \implies x \equiv y \pmod{a}
$$

> 這很容易直接用定義證明: $ab|(x-y) \implies a|(x-y)$

而加密的時候 xor 都只取了最後 8 bits，也就相當於說我們只在意 $\text{key} \bmod{2^8}$ 的值。而 $2^8$ 又是 $M$ 的一個因數，所以:

$$
k_{n+1} \equiv f(k_{n}) \pmod{M} \implies k_{n+1} \equiv f(k_{n}) \pmod{2^8}
$$

也就是說**只要知道 lowest 8 bits 就能推得下個 key 的 lowest 8 bits**。同時利用 flag prefix 是 `AIS3{` 的這個事實就能推出原本的 `key & 0xff`，然後解密整個 flag。

```python
from cipher import encrypt

ct = bytes.fromhex(open("output.txt").read())
k = ct[0] ^ b"A"[0]
print(encrypt(ct, k))
```

另外因為 $k_0$ 其實也只有 256 個選擇，直接爆破也行。
