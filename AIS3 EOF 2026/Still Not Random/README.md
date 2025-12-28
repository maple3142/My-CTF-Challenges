# Still Not Random

* Category: Crypto
* Score: 100/500
* Solves: 32

## Description

I still don't trust random because there is no true randomness.

## Solution

注意到任兩個 nonce 的差大約只有 256 bits，比 384 bits 的 $q$ 小，所以記 $\Delta_i=k_{i+1}-k_1$ 然後用 LLL 求出 $\Delta_i$ 的值，然後再解聯立方程得到 secret key。不過這題由於 bound 比較緊，所以要對 LLL 出來的結果 bruteforce 一些小的 linear combination。

解法可參考 [solve.py](solve.py)。
