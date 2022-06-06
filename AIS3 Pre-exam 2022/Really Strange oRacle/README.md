# Really Strange orAcle

* Category: Crypto
* Score: 480/500
* Solves: 18/286
* Solves(MFCTF): 0/124

## Description

You have a RSA(-like) encryption oracle to use, but you know literally nothing about the public key. Can you still decrypt the flag with it?

## Overview

這題公鑰的 $n=p^2$ 未知，$e$ 也一樣是未知的值。目標是想辦法
利用 $E(x)=x^e \bmod{n}$ 的 oracle  還原 $n,e$ 然後解密 flag。

## Solution

### 還原 n

用基本的指數運算可知:

$$
(x^2)^e \equiv (x^e)^2 \pmod{n} \implies (x^2)^e-(x^e)^2 \equiv 0 \pmod{n}
$$

由此可知 $n$ 整除 $E(x^2)-E(x)^2$，所以任取多個 $x$ 然後用 oracle 得到 $E(x), E(x^2)$ 的值之後使用 $\gcd$ 有高機率可以獲得正確的 $n$。

有 $n$ 之後直接開根號也可獲得 $p$。

### 還原 e

這題雖然 $\varphi(n)=p(p-1)$ 很好求得，仍需知道 $e$ 的值才能夠算出 $d$ 以解密 flag。而求出 $e$ 的問題就是 [DLP](https://en.wikipedia.org/wiki/Discrete_logarithm)，在正常情況下是個相當困難的問題。

不過並不是每個 DLP 都很困難，像是這題的情況其實相當簡單:

$$
(1+p)^x \equiv 1+\binom{x}{1}p+\binom{x}{2}p^2+\cdots \equiv 1+xp \pmod{p^2}
$$

因此利用 oracle 計算 $y=E(1+p)$ 之後用 $y-1 \over p$ 即可求得 $e$，之後算出 $d$ 解密 flag 即可。

詳見 [solve.py](solve.py)。

這個使用二項式定理的技巧也在 [Paillier cryptosystem](https://en.wikipedia.org/wiki/Paillier_cryptosystem) 中有使用到。
