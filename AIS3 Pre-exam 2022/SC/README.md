# SC

* Category: Crypto
* Score: 100/500
* Solves: 224/286
* Score(MFCTF): 100/500
* Solves(MFCTF): 82/124

## Description

SC? SuperChat?

## Overview

一個很簡單的 [Substitution cipher](https://en.wikipedia.org/wiki/Substitution_cipher)，使用了同個替換同時加密了 `cipher.py` 和 `flag.txt`。

## Solution

利用 `cipher.py` 和 `cipher.py.enc` 可以找出那個替換，將它反過來就能解密 `flag.txt`。

```python
Ti = str.maketrans(open('cipher.py.enc').read(), open('cipher.py').read())
print(open('flag.txt.enc').read().translate(Ti).strip())
```
