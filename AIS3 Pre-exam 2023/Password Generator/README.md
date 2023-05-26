# Password Generator

* Category: Pwn
* Score: 500/500
* Solves: 1/247

## Description

A simple password generator written in C.

Server runs on **Ubuntu 22.04**.

> 這題沒提供 source code，需要自己 reverse [binary](src/chall)

## Overview

這題 binary 是 O0 編譯的，所以不管是 IDA 或是 Ghidra 直接反編譯出來都和 source 差不多，所以其實當成是有 [source code](src/chall.c) 的情況就好。

基本上就一個 password generator，可以使用裡面預先定義好的 charset 或是自己輸入 charset，然後再指定一個長度就會隨機生成一個 password。

## Solution

有個非常明顯的 buffer overflow 在讀取 charset 的地方: `scanf("%s", charset);`，但這題有 PIE 所以 ROP 沒那麼容易。

另一個關鍵在於 `rand64` 其實是寫壞的:

```c
long rand_num;

uint64_t rand64() {
	syscall(SYS_getrandom, &rand_num, sizeof(rand_num), 0);
	return &rand_num;
}
```

可以發現它回傳的不是 `rand_num`，而是 `rand_num` 的 address，所以如果能得到 `rand64()` 回傳值的話就能知道 program base。另外這個就算沒從 code 看出來，只要生成多個相同長度的 password 就會發現它們都是一樣的，這樣也很容易看出它根本就不 random。

至於要 leak `rand64()` 的回傳值主要要關注這邊:

```c
for (int i = 0; i < len; i++) {
    password[i] = charset[(rand64() * i + len) % strlen(charset)];
}
```

在 `i == 0` 的時候無法知道任何關於 `rand64()` 的資訊，但 `i == 1` 時代表 `charset.index(password[1]) == (rand64() + len) % strlen(charset)`，其中 `len` 已知所以也能推得 `rand64() % strlen(charset)` 的值。

這邊 `rand64()` 是個 64 bits 的數 [^1]，所以如果要一次 leak 整個值出來的話勢必要讓 `strlen(charset)` 超過 `2**64`，但這明顯不可能做到。

這邊的預期作法是透過蒐集多個 `rand64() % strlen(charset)` 在不同 `strlen(charset)` 下的值，這樣可以列出一組系統:

$$
x \equiv a_1 \pmod{m_1} \\
x \equiv a_2 \pmod{m_2} \\
\vdots
$$

其中 $m_i$ 就是 `strlen(charset)`，$a_i$ 就是 `rand64() % strlen(charset)`，$x$ 就是 `rand64()`。

看到這個就能發現只要使用 [Chinese remainder theorem](https://en.wikipedia.org/wiki/Chinese_remainder_theorem) 了就能解出 `rand64()` 的值了。要最有效率的取得 `rand64()` 的值的話要最大化 $m_i$ 的 LCM，所以最好是要兩兩互值。一個最簡單的方法就是取前幾個小質數當作 $m_i$ 就能搞定了。

之後在知道 prog base 的情況下就能串 ROP 了，而拿 shell 的方法也很簡單，就是先用一串 ROP 去 `puts(puts@got)` 再回到 main 可得 libc base，接著再用一串 ROP ret2libc 就能拿到 shell 了。

這題題目靈感來源來自 [ImaginaryCTF 2021 - inkaphobia](https://blog.maple3142.net/2021/07/28/imaginaryctf-2021-writeups/#inkaphobia)

[^1]: 實際上因為 address 的範圍有限，未知的部分少於 48 bits
