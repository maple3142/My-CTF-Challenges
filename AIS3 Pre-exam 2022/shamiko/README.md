# shamiko

* Category: Crypto
* Score: 500/500
* Solves: 4/286
* Solves(MFCTF): 1/124

## Description

![shamiko](shamiko.png)

Recommended readings: https://en.wikipedia.org/wiki/Digital_Signature_Algorithm https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm

## Overview

這題可以使用 DSA sign 任意的資料 16 次，目標是要取得 private key 把 flag 解密。DSA nonce k 的部分使用的是一個特殊的方法生成的 deterministic nonce:

```python
def H(m: bytes):
    return sha1(m).digest()


def gen_k(m: bytes, x: int):
    # generate a deterministic nonce
    k = H(m + long_to_bytes(x))
    while len(k) < 256:
        # ensure k is long enough to prevent lattice attacks
        k += H(k + long_to_bytes(x))
    return bytes_to_long(k) % q
```

## Solution

DSA 中只要知道一個 signature 的 $k$ 就能夠讓人還原 private key $x$，但是這邊的 $k$ 的生成方式表明了 $k$ 是 $m, x$ 的函數，在不知道 $x$ 的情況下令人無從下手。

解題關鍵在於 $H(x)$ 使用的是 sha1，而且在計算最初始的 $k$ 的時候是 $k_0=H(m||x)$。之後反覆 $k_{n+1}=k_n||H(k_n||x)$ 直到 $k$ 足夠長為止。

可見 $m$ 在計算的過程中只被使用了一次，使用已知的 [SHA1 Collision](https://shattered.io/) 就能得到 $H(m_1)=H(m_2)$，然後利用 [Merkle–Damgård](https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction) 的性質可知 $H(m_1||x)=H(m_2||x)$，然後剩下反覆運算也還是會讓等式成立，因此就能有重複的 $k$ 產生。

儘管 server 限制了訊息的長度不可超過 512 bytes，這限制了你直接把整個 pdf 當作訊息傳給 server。但從[這邊的圖片](https://github.com/corkami/collisions#shattered-sha1=)可以知道其實 collision 的是 pdf 的前 320 bytes 而已，因此將兩個 pdf 的前 320 bytes 作為 $m_1, m_2$ 傳給 server 即可獲得相同 $k$ 的 signatures。

而出現重複的 $k$ 在 (EC)DSA 中是相當致命的一件事，因為:

$$
\begin{aligned}
s_1 k \equiv h_1 + r_1 x \pmod{q} \\
s_2 k \equiv h_2 + r_2 x \pmod{q}
\end{aligned}
$$

其中 $h,r,s$ 都是已知的值，所以只有唯二的未知數 $k,x$，因此這就變成了國中數學的二元一次聯立方程式，在 $\bmod{q}$ 的情況下解出 $x$ 即可。

唯一要注意的一個小地方是 $p=2q+1$，而 $x$ 在生成的時候是取到 $[1,p)$ 範圍的，所以真正的 private key 也可能是 $x+q$。

詳見 [solve.py](solve.py)。
