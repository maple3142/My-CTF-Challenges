# Baby ECDLP

* Category: Crypto
* Score: 469/500

## Description

A simple and straightforward ECDLP challenge!

## Overview

在 $\mathbb{Z}/n\mathbb{Z}$ ($n=pq$) 上有個橢圓曲線 $E: y^2 = x^3 + ax + b$ 過 $(p,p)$ 和 $(q,q)$，給予兩點 $G=(p,p)+(q,q),C=x_\text{flag}G$ 求 flag。已知的參數有 $a,b,C$。

## Solution

可知 $a, b$ 中 $b$ 是 $n$ 的倍數，然後和曲線上一點 $C$ 結合可以用 gcd 求出 $n$。然後就得到了二元未知數的方程式，直接聯立求解即可得 $p,q$。

然後考慮 $E(\mathbb{F}_p)$ 的話可發現它的 embedding degree 只有 2，也就是 $\# E(\mathbb{F}_p) | (p^2 - 1)$，所以可以用 MOV Attack 把它變成 $\mathbb{F}_{p^2}$ 上的 DLP，然後發現說 $p+1$ 相當的 smooth，所以直接套 Pohlig-Hellman 就可以解出 $x_\text{flag} \mod \operatorname{ord}(G_p)$。用相同方法套用在 $q$ 上也能成，然後 CRT 合併就得到 flag。

另外是因為我造 $p,q$ 的時候有點選太 smooth 的數了，所以直接用 Pohlig-Hellman 解 ECDLP 也可行。應該說大部分人都是這樣解的。

最後是 $\# E(\mathbb{F}_p) = p + 1$ 這個其實不是巧合，而是因為 $E$ 在 $\mathbb{F}_p$ 和 $\mathbb{F}_q$ 上的形式都是 $y^2 = x^3 + ax$，而在 $p \equiv 3 \pmod 4$ 的時候時候 order 必然是 $p+1$。這部分的數學細節可以參考 [On Orders of Elliptic Curves over Finite Fields - 3.2.1](https://yujinhkim.github.io/data/orders-elliptic-curves.pdf)
