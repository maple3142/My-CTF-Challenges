# pettan

* Category: Crypto
* Score: 500/500
* Solves: 2/286

## Description

![manachan](manachan.png)

## Overview

題目給了個 RSA 的加密 oracle ($e = 11$)，可以自己選擇是要加密 flag 還是自己選擇的數。加密時會額外加上另一個隨機產生的 padding，而生成 padding 的函數如下:

```python
from random import getrandbits

N_BITS = 1024
PAD_SIZE = 64
def generate_padding():
    pad = getrandbits(PAD_SIZE)
    s = 0
    for _ in range(N_BITS // PAD_SIZE):
        s = (s << PAD_SIZE) | pad
    return s
```

## Solution

這題的第一個問題在於這行: `from random import getrandbits`。因為 python 的 `random` 使用的是 MT19937，是一個可以在擁有夠多的輸出後就能被預測的 PRNG。

Google 一下可以找到像是 [randcrack](https://github.com/tna0y/Python-random-module-cracker) 之類的東西，可以知道它一共需要 624 的輸出才能預測 random，每個輸出為 32 bits。

### 取得 padding

首先第一關在於怎麼取得 padding。應該不難發現 generate padding 的時候是拿同樣的 64 bits 結合 bit shifting 弄出來的 1024 bits 數字。在 16 進位下也能發現它是一個重複的 pattern 反覆出現，所以當原本的 64 bits padding 為 $x$ 時，完整的 padding 可以表示為 $kx$，其中 $k$ 是一個常數。

所以輸入 $m=0$ 的就能得到 $c \equiv (kx)^e \pmod{n}$。接下來將 $k$ 乘到另一側變成 $x^e \equiv k^{-e}c \pmod{n}$。

因為 $64 \times 11 < 1024$，代表整數下的 $x^e$ 是小於 $n$ 的，所以直接將 $k^{-e}c$ 開十一次方根就能得到 $x$。

再來是因為 $x$ 是 64 bits 的數字，代表它其實是由 MT19937 的兩個輸出構成的。這邊可以選擇直接讀 CPython 的 [source code](https://github.com/python/cpython/blob/0d8500c739dc5ea926b2ec1ec02e400738225dac/Modules/_randommodule.c#L480-L526) 看它是怎麼做的，或是直接用下面的 Python 測試一下它的輸出規則:

```python
random.seed(8763); hex(random.getrandbits(64))
random.seed(8763); hex(random.getrandbits(32)), hex(random.getrandbits(32))
```

可以知道它是類似 Little Endian 的方式來輸出的，所以是先底部的 32 bits 之後才是頂部的 32 bits。

> PS: 其實 $m \neq 0$ 的時候也能透過 Coppersmith attack 還原 $x$

### 預測隨機數

等蒐集到了 624 個 32 bits 的輸出之後可以預測未來的輸出，這邊可以直接用 [randcrack](https://github.com/tna0y/Python-random-module-cracker) 之類的解決，不用自己實作。

我個人是喜歡使用 [eboda/mersenne-twister-recover](https://github.com/eboda/mersenne-twister-recover)，因為它可以 return 一個 Python 內建的 random 物件，api 用起來比較方便。

### Related Message Attack

能夠預測 padding 之後又能做什麼呢? 如果取得兩個 flag 的 ciphertext $c_1, c_2$ 的話可以寫出以下兩個等式:

$$
\begin{aligned}
c_1 \equiv (m+a)^e \pmod{n} \\
c_2 \equiv (m+b)^e \pmod{n}
\end{aligned}
$$

其中的 $a,b$ 都是 padding，因為可以預測 padding 所以可將它們視為已知資訊。而像是這樣的情況可以運用 Related Message Attack 去解開我們想要的 $m$。

Related Message Attack 大致上可以這麼解釋:

$$
\begin{aligned}
c_1 \equiv f_1(m)^e \pmod{n} \\
c_2 \equiv f_2(m)^e \pmod{n}
\end{aligned}
$$

其中的 $f_1(x), f_2(x)$ 都是**多項式**，此時可以將它改寫為另外兩個多項式:

$$
\begin{aligned}
f(x)=f_1(x)^e-c_1 \\
g(x)=f_2(x)^e-c_2
\end{aligned}
$$

> 此處一律在 $\mathbf{Z}_n$ 下做運算

顯然 $f(x), g(x)$ 都有一根為 $m$，所以按照餘式定理可以寫出:

$$
\begin{aligned}
f(x)=(x-m)q_1(x) \\
g(x)=(x-m)q_2(x)
\end{aligned}
$$

假設 $q_1(x), q_2(x)$ 沒有共同因式(絕大多數情況下都成立)，此時可得 $\gcd(f(x),g(x))=x-m$。因此只要知道兩個 $c_1, c_2$ 所對應的 $m$ 的關聯就能透過 $\gcd$ 將 $m$ 給找出來。

而這題是 $f_1(x)=x+a, f_2(x)=x+b$ 的 case，所以以上的攻擊確實能有效地還原出 flag。

> 當然，實際上要完成這些事需要對 Sage 有一定的熟悉才能做到

詳見 [solve.py](solve.py)。

> 此題靈感來源來自 [RaRCTF 2021 - randompad](https://blog.maple3142.net/2021/08/09/rarctf-2021-writeups/#randompad)，姑且算是它的簡化版
