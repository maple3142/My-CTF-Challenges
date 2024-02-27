# Baby XOR

* Category: Crypto
* Score: 500/500

## Description

edu-ctf HW0 but with a twist

## Overview

自己看 code :P

## Solution

1. 記 `out = xorrrr(mods)`，可以發現 `out[i]^S == mods[i]`
2. 把 `S` 表示成 48 個未知的 `s[i]`，每個都是 0 or 1
3. xor 在這個情況下可以變成 linear equation，然後在 GF(3) 下會得到一堆 `lhs = 1` or `lhs = 2` 的等式
4. `(lhs-1)(lhs-2)=0`，然後 linearization 之後可以用高斯消去法求 `s[i]`
5. 得到 `mods`
6. 用 CRT 構造 lattice LLL -> secret

LLL 的部分可參考 [A](https://users.monash.edu.au/~rste/MultCRT.pdf) or [B](https://mystiz.hk/posts/2021/2021-11-07-bsides-ahmedabad/#they-were-eleven)。
