# 65537

* Category: Crypto
* Score: 356/500
* Solves: 13

## Description

https://www.youtube.com/watch?v=sdG5pvtXpuI

## Solution

題目給了 $c_i \equiv m^{f(x_i)} \pmod{n}$ 但沒給 RSA 的 $n$，所以要找方法還原 $n$。首先可以先找出一些 $y_i=f(x_i)$ 的一些線性關係，也就是 $\vec{v} \cdot \vec{y} = 0$，這部分可以用 vandermonde matrix 的 kernel 或差分 (finite difference) 來做，反正都會得到一組 basis B 與 $\vec{y}$ 垂直。

要求 $n$，只需要拿 $c_i$ 以 $\vec{v}$ 當作 exponent 做乘法就能找到一個 mod n 為 1 的數，但因為這些乘法都在整數下做的，所以 $\vec{v}$ 中的數不能太大，所以可以先對 basis B 做 LLL 然後找前兩個短的向量來求，然後 gcd 即可得到 $n$ (或 n 的小倍數)。

之後直接插值 (lagrange 或 vandermonde matrix inverse) 就能得到 $t_i \equiv m^{a_i} \pmod{n}$，其中 $a_i$ 是 $f(i)$ 的係數，符合 $0 \leq a_i < 65537$ 還算小。這邊可以用 $t_0^{a_1} = t_1^{a_0}$ 的等式做 MITM 得到 $a_0,a_1$，然後之後直接用 $t_0^{a_i}=t_i^{a_0}$ 解 DLP 求 $a_i$ 就能獲得全部係數。

然後係數已知的話這個問題就變成了基本的 common modulus attack，然後就能求 flag 了。參考 [solve.py](solve.py)。
