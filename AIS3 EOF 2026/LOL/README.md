# LOL

* Category: Crypto
* Score: 491/500
* Solves: 4

## Description

LOL - LFSR Of LFSRs

## Solution

關鍵是注意到 LFSR 的多項式 $f(x)$ 如果不可約，那它每次 step 的操作其實等價於 $\mathbb{F}_{2^n} \approxeq \mathbb{F}_2[x]/f(x)$ 上乘以 $x$ 的操作。如果 $f(x)$ 可約那就變成一個 quotient ring 而已。

這樣用代數的角度來看 `LOL` 其實也是個 LFSR，它的 register 都來自一個多項式 (`mask`) 未知的 quotient ring $R$ 而已，因此只要知道 `mask` 那一樣可以用一般標準的 LFSR 破解方法來做 (e.g. Berlekamp-Massey / Gaussian elimination 等等)。

至於求 `mask` 的方法有很多種，我這邊預期的做法是把連續 $n+1$ 的輸出拿去湊一個矩陣，即 $n+1$ 大小的 hankel matrix。由於 LOL 的輸出在 $R$ 下是個 linear recurrence，因此這個 hankel matrix 肯定非 full rank，因此其 det 為 0。也就是說它 det 出來的多項式 $d(x) \equiv 0 \mod f(x)$，因此我們可以用 gcd 的方法求出 `mask`。

之後得到 mask 之後就很簡單了，因為 recurrence 長度已知所以直接在 $R$ 下解 linear system 即可。不過這部分實作比較麻煩，因為 sage 內建不支援在 quotient ring 下解線性方程，所以我這邊是自己把它轉換成 $\mathbb{F}_2$ 下的線性方程來解。

參考 [solve.py](solve.py)。
