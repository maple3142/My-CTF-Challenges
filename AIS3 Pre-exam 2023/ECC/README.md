# ECC

* Category: Crypto
* Score: 500/500
* Solves: 3/247

## Description

I rolled my own public-key encryption scheme using [Elliptic-curve cryptography](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography), but my friend said there is a critical implementation mistake that compromise the security. Can you find it?

## Overview

這題在 secp256k1 上用了一個類似 [ElGamal](https://en.wikipedia.org/wiki/ElGamal_encryption) 或 [IES](https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme) 的方法對 flag 字元一個一個加密，其中 `nonce` 的部分是使用 `itertools.count(randbelow(secp256k1.q), randbelow(secp256k1.q))` 生成的。

## Solution

顯然 `nonce` 是一個未知的等差數列，為了方便把它記為 $k_i$ 符合 $k_i-k_{i-1}=d$ 為一定值。

如果要解密的話關鍵在於 `s = nonce * pk` 那個點，把 `pk` 記為 `P` 的話各個加密的 `s` 會是 $k_0 P, k_1 P, k_2 P, \cdots$。

利用等差數列的性質可得 $k_1 P - k_0 P = (k_1 - k_0)P = dP$，而在有了 $dP$ 之後我們就能算出任何 $k_i P$ 了，也就能推出之後的 `s` 了。

不過要達成這個的前提是要知道 $k_1 P, k_0 P$ 的值，這邊會利用到 Flag prefix 是 `AIS3{` 的這個事實[^1]可以回推前面幾個 `s` 的 `s.x`，再利用 secp256k1 的等式用二次剩餘能算出對應的 `s.y`[^2]，也就能知道 $k_1 P, k_0 P$ 這兩個點了。

[^1]: 就算不知道 Flag prefix 的話也能爆 $256^2$ 種可能
[^2]: `s.y` 會有兩個可能，兩個都測試看看就好了
