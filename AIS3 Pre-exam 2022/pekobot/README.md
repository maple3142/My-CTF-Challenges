# pekobot

* Category: Crypto
* Score: 500/500
* Solves: 0/286

## Description

こんぺこ！I am a bot imitating Pekora. You can talk with me through Elliptic-curve Diffie–Hellman protocol!

https://www.youtube.com/watch?v=HP3Xu3QO-f4

## Overview

這題有個有個純 python 的 elliptic curve impl。連接上 bot 之後會提供 public key 之後顯示 menu，這邊可以選擇要使用 ECDH 和對方通訊，通訊內容是一些已知的 quotes 和 shared secret 去 xor 加密的結果。menu 的另一個選項則是可以獲取
加密的 flag，
加密方法是以同個 public key 透過類似 [ElGamal](https://en.wikipedia.org/wiki/ElGamal_encryption)/[IES](https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme) 的方法加密的。

## Solution

解題關鍵在於 `elliptic_curve.py` 中的 `Point.__init__`:

```python
class Point:
    def __init__(self, curve, x, y):
        if curve == None:
            self.curve = self.x = self.y = None
            return
        self.curve = curve
        self.x = x % curve.p
        self.y = y % curve.p
```

可以發現它並沒有檢查 $(x,y)$ 是否為 `curve` 的一點，所以這就能透過 [Invalid Curve Attack](https://github.com/ashutosh1206/Crypton/blob/master/Diffie-Hellman-Key-Exchange/Attack-Invalid-Curve-Point/README.md) 去做攻擊。

### Oracle

要能攻擊的一個條件是要有個 oracle 能傳送一個不一定在原本曲線 $E$ 上的 $P$，然後要有辦法得到 $dP$ (scalar multiplication) 的值才行。在這題的情形下它的 $G$ 是固定的，所以只能透過傳送自己的 public key 過去之後計算 shared secret 的這部分作為 oracle。

因為這邊的加密是很單純的 xor，所以如果知道 `choice(quotes)` 的結果就能 xor 回原本的 $S=dP$ 的點。但是問題在於 `choice` 是隨機的，在這題的情況下想預測 MT19937 也不太實際。

解決方法其實很簡單，就是把每個 `quotes` 的 $m$ 都試過一次，看看 xor 之後的 $S$ 是否是橢圓曲線 $E$ 上面的一點。這是因為若是測試到錯誤的 $m$，得到的 $(x,y)$ 高機率不會符合 $y^2 \equiv x^3+ax+b \pmod{p}$ 的。

所以在擁有這個 oracle 的情況下，就只需要把 Invalid Curve Attack 實作出來就能拿到 private key 了，不過這也是這個題目主要的難點。

### Invalid Curve Attack

這邊我會嘗試用簡單的講法把這個攻擊簡述一遍，詳細還是建議 [Crypton](https://github.com/ashutosh1206/Crypton/blob/master/Diffie-Hellman-Key-Exchange/Attack-Invalid-Curve-Point/README.md) 或是其他地方的說明。

Invalid Curve Attack 大致上來說利用的是當一個不在原本曲線 $E$ 上的 $P$ 進行 scalar multiplication 的一些特性，使用類似 [Pohlig–Hellman algorithm](https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm) 的辦法在不同的 subgroup 解 [DLP](https://en.wikipedia.org/wiki/Discrete_logarithm) 然後用 [CRT](https://en.wikipedia.org/wiki/Chinese_remainder_theorem) 解回原本的 private key。

一個 Short Weierstrass curve 長這樣:

$$
y^2 = x^3 + ax + b
$$

而它的 point doubling formula ($R=2P$) 是:

$$
\begin{aligned}
s &= \frac{3x_P^2+a}{2y_P} \\
x_R &= s^2 - 2x_P \\
y_R &= y_P + s(x_R - x_P)
\end{aligned}
$$

由此可見一個 Short Weierstrass curve 在做 scalar multiplication 時並沒有使用到 $b$，
因此對一個 $P \notin E$ 的點做 scalar multiplication 相當於在另一個 $b' \neq b$ 的 $E': y^2 = x^3 + ax + b'$ 上運算。

這會帶來的問題是 $E'$ 通常和特別選過的 $E$ 不同，它的 curve order $\#(E')=n$ 分解後不一定都有個 large prime order subgroup 存在。當 $E'$ 上存在一個 order 為 $f$ 的 small subgroup 時，我們可以將原本 $Q=dP$ 的問題轉換成 $(n/f)Q=d((n/f)P)$，然後就能在短時間內解出 $d \bmod{f}$ 的值。

所以只要有多個夠小的 $f_1, f_2, f_3, \cdots$，利用上面的方法找出 $d_i \equiv d \pmod{f_i}$，然後利用 CRT 就能算出 $d \bmod{\prod_{i=1}^{b} f_i}$ 的結果。因此要得到真正的 $d$ 就得找出足夠多的 $f_i$ 使得 $\prod_{i=1}^{b} f_i > n > d$ 才行。

當然，一個 $E'$ 通常不會提供這麼多的 $f_i$ 能達成這個條件，所以會有多個 $E', E'', E''', \cdots$ 分別提供不同的 $f_i$，然後用一樣的方法在 subgroup 中解 DLP，最後應用 CRT 即可求出需要的 $d$。

這題原先的曲線 $E$ 是 NIST P-256，所以我先將 $a$ 固定，然後暴力搜尋其他不同的 $b'$ 得到 $E'$，把夠小的 $f_i$ 紀錄下來。這部分可以參考 [find_curves.sage](find_curves.sage)。

為了減少之後的計算量，我把 $b'$, $E'$ 上的 generator $G'$, $\#(E')$ 還有 $f_i$ 都記錄了下來

剩下就是利用這些預先計算好的參數，將各個 $E'$ 的 $G'$ 當作 public key $P$ 傳給 oracle，然後得到 $Q=dP$，然後用前面的方法得到 $d \equiv d \pmod{f_i}$ 的值，最後使用 CRT 求回 $d$ 即可。

### Decrypt flag

Flag 加密的方法就如同前面所說，是個類似 ElGamal/IES 的方法。首先取個隨機數 $r$，然後以 $C_1=rG$ 和 $C_2=(rP \oplus m)$ 作為密文，其中 $P$ 是 public key。解密的話就 $dC_1 = drG = rP$，所以將它和 $C_2$ xor 即可得到 flag。

完整的解法詳見 [solve.sage](solve.sage)。
