# Baby Side Channel Attack

* Category: Crypto
* Score: 475/500

## Description

I implemented a simple RSA encryption & decryption routine in Python and used the [trace](https://docs.python.org/3/library/trace.html) module to debug it.  I hope it doesn't leak any important info.

## Overview

這題自己用 square-and-multiply 實作 RSA，然後測試了加解密後給你 flag 的密文，且提供了使用 python 的 trace module 生成的 log。另外這題沒直接給 $n$，而是給了 $a = e^d \mod{n}$ 和 $b = d^e \mod{n}$。

## Solution

直接看 `trace.txt` 可發現它有紀錄每一行的執行過程，因此可以判斷 `powmod` 中的 `r = r * a % c` 那行有沒有執行到就能得出 $e$ 和 $d$。

求 $n$ 的話其實就用 RSA 的同餘公式寫一下就能得到了:

$$
\begin{aligned}
a^e \equiv (e^d)^e \equiv e \pmod{n} &\rightarrow n | a^e - e \\\\
b \equiv d^e \pmod{n} &\rightarrow n | b - d^e
\end{aligned}
$$

> 這邊之所以不用 $e^d-a$ 的原因是 $d$ 太大了，在不知道 $n$ 的情況下是沒辦法算的
>
> 不過如果真的要用這個也不是不行，就是取 $kn=b-d^e$ 作為一個 $n$ 的倍數，然後算 $e^d-a \mod{kn}$，然後用得到的數做 gcd 就能得到 $n$。

然後做 gcd 就能得到 $n$。不過因為這題 $e=65537$，用 python `int` 會太慢，要用底層呼叫 GMP 的 `gmpy2` 或是 sagemath 才行。
