# prsa

* Category: Crypto
* Score: 3/11

## Description

Hybrid public key cryptosystem based on RSA and Paillier

## Overview

這題給了一個混和 RSA 和 Paillier 的 cryptosystem，使用相同的 modulus $n$，並提供可以把兩個的 ciphertext 互相轉換的功能。為了方便下面會把兩個 oracle 分別叫 $\text{r2p}$ 和 $\text{p2r}$ (RSA to Paillier 和 Paillier to RSA)。

## Solution

首先是要先找方法求 $n$，因為這題沒直接把 $n$ 給你。我的方法是利用 paillier decrypt 相當於取 log 的性質，所以可得以下等式在 $\mod{n}$ 下成立：

$$
\text{p2r}(x^2)=(\log{x^2})^e=2^e (\log{x})^e=2^e \text{p2r}(x)
$$

因此把等式左右相減得 $n$ 的倍數，取多個值後取 gcd 即可得到 $n$。

再來是找方法解出 flag，這部分的關鍵是利用 paillier 的 additive homomorphic 性質能讓我們得到 $(x+k)^e$ (k 是已知的任意值)，結合原本有的 $x^e$ 就變成了 Franklin-Reiter related message 的問題。也就是只要把兩個寫成多項式求 gcd 即可。

由於這題的 $e=65537$ 用一般的 gcd 要花不少時間，會需要改使用 Half-GCD 來計算會快很多。

我的 solver 在 [solve.py](./solve.py)。
