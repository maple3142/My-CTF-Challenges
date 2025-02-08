# zkdlp

* Category: Crypto
* Score: 3/11

## Description

Just solve the DLP and prove it to me with ZKP

## Overview

這題要想辦法透過 ZKP 的 [Schnorr's identification protocol](https://www.zkdocs.com/docs/zkdocs/zero-knowledge-protocols/schnorr/) 向 server 證明自己知道 $g^x=y$ 的 $x$，但 $x$ 是 flag 的 hash 所以顯然是個未知的值。

## Solution

顯然直接求解 DLP 是不可能的，所以問題一定出在 protocol 的實作上。這邊的問題在於 verifier 給的 challenge $c$ 是用 `random.randrange(q)` 生成的，來自 Python 的 MT19937 所以有可能可以預測出 $c$ 的值。

而在這個 protocol 中 $c$ 如果可以被 prover 在傳送 $t$ (commitment) 之前預測出來的話會出問題，因為此時 prover 就能選定任意的 $s$ 然後求 $t=g^s y^{-c}$ 傳送過去，然後讓 verifier 成功接受。

因此這題的目標就是要利用 `random.randrange(q)` 去回推整個 MT19937。求解 MT19937 實質上就只是解一個 $\mathbb{F}_2$ 下的線性方程組 $Ax=b$ 而已。這邊我是利用我之前寫的一個 library [gf2bv](https://github.com/maple3142/gf2bv) 來處理，具體方法可以參考那裡面提供的 examples 而已。

這題主要的困難點是在於 `random.randrange(q)` 實際上是透過 `random.getrandbits(q.bit_length())` 後透過 rejection sampling 來實作的，而我們沒辦法知道 rejection sampling 到底會 reject 幾次，所以會導致沒辦法直接知道每次輸出給的 bits 到底是在 output stream 的哪個位置。

我這邊的做法是先假設前 $k=10$ 次 `random.randrange(q)` 的過程都沒有任何 rejection，那就能直接利用前 $k$ 次輸出來嘗試解出 MT19937 的 initial state。成功機率是:

$$
P=(\frac{q}{\lceil \log_2{q} \rceil})^k \approx 0.7^k \approx 2.8\%
$$

因此 $k=10$ 相當可行，大概 50 次內就能成功一次了。

再來會遇到的另一個問題是只使用 $k=10$ 得到的系統是 under-determined，導致解出來的 initial state 不是唯一解，會導致後面的輸出錯誤。經過實驗大概需要 $k \geq 15$ 才能得到 unique solution，但太大的 $k$ 讓成功機率降低又是一個問題。

一個方法是先取 $k=10$，然後用 $0,1,2,\cdots$ 猜第 10 和第 11 次中間有幾次 `random.getrandbits(q.bit_length())` 的間隔，之後再以此類推。之所以這樣可行是因為如果猜的間隔不對就很可能導致整個系統是 inconsistent 的，導致無解，這樣就能慢慢地把解的空間縮小。

我的 solver 在 [solve.py](./solve.py)。
