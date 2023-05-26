# Not Wiener

* Category: Crypto
* Score: 500/500
* Solves: 0/247

## Description

I generated my RSA key pair in a way that it is absolutely not vulnerable to [Wiener's attack](https://en.wikipedia.org/wiki/Wiener%27s_attack).

## Overview

這題的 RSA public key 所對應的 $d = \varphi(n)-D$，其中 $D$ 是個未知的 540 bits 的質數，而 $p,q$ 都是 1024 bits。

## Solution

列出 RSA $e,d$ 的等式可得:

$$
ed \equiv e(\varphi(n)-D) \equiv -eD \equiv 1 \pmod{\varphi(n)}
$$

多引入一個未知數 $k$ 把 mod 拿掉可得另一等式:

$$
-eD=1+k\varphi(n)
$$

因為 $e$ 大致上和 $\varphi(n)$ 是同個大小的，所以 $k$ 的大小應該與 $D$ 差不多。

如果這題 $D$ 夠小的話因為

$$
\frac{-e}{n} \approx \frac{k}{D}
$$

> 這個等式是先拿 $n$ 去近似 $\varphi(n)=n-(p+q)+1$ 然後再左右同除 $nD$ 得到的

所以能用連分數展開算出 $D$，而這其實就是 Wiener's attack 的一個變種而已。

然而這題 $D$ 顯然不夠小 ($<\frac{1}{3}n^{1/4}$)，所以 Wiener's attack 不可用，不過還有個和 Wiener's attack 又還算有名的攻擊叫 [Boneh-Durfee Attack](https://cryptohack.gitbook.io/cryptobook/untitled/low-private-component-attacks/boneh-durfee-attack)，可對 $d<N^{0.292}$ 的情況下產生作用，所以在這題 $D$ 只有 540 bits 的情況下，Boneh-Durfee Attack 應該也是可行的。

不過因為多了一個負號所以這邊當然也不能用原本的 Boneh-Durfee Attack，而是要理解它的概念然後微調一下才能解決這題。

首先是回到:

$$
-eD=1+k\varphi(n)
$$

兩邊同 mod $e$ 可得:

$$
-1 \equiv k\varphi(n) \equiv k(n-s) \pmod{e}
$$

其中 $s=p+q-1 \approx 2\sqrt{n} \approx 2\sqrt{e}$，而 $k$ 是個和 $D$ 差不多大的負數。

所以考慮以下的二元多項式

$$
f(x,y)=1+x(n-y)
$$

可得 $f(k,s) \equiv 0 \pmod{e}$，所以 $(k,s)$ 是 $f$ 的一個根。因為 $(k,s)$ 兩個數都遠比 $e$ 要小，這邊可以利用 Multivariate Coppersmith 去找到這組根。

基本上利用現成的 Coppersmith implementation (e.g. [defund/coppersmith](https://github.com/defund/coppersmith)) 然後當個 script kiddie 就能解出需要的答案了。(可能會需要調點參數)

這個流程其實就是 Boneh-Durfee Attack 的概念，不過因為有個負號所以要微調一下，還有[原版](https://staff.emu.edu.tr/alexanderchefranov/Documents/CMSE491/Fall2019/BonehIEEETIT2000%20Cryptanalysis%20of%20RSA.pdf)的 attack 因為為了要把可攻擊的範圍擴大，還有做一些額外的變數代換壓低目標根的上界。

另外是這個題目其實也是有對應論文的 XD: [(Very) Large RSA Private Exponent Vulnerabilities](https://cacr.uwaterloo.ca/techreports/2004/cacr2004-01.pdf)。
