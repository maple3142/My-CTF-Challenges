# MagicHash 

* Round: 55 (2024/03)
* Category: Crypto
* Points: 100
* Solves: 5

## Description

Do you think combining weak hash functions can make it stronger?

## Solution

TL;DR: this challenge wants you to find a simultaneous collision for both `hashlib.md5` and `zlib.crc32`.

To do this, we can use an important fact that `crc32` is an affine function. First find a $2^{33}$ collision for md5 using `fastcoll` by chaining it. Then to $2^{33}$ collisions for md5 equivalent to an affine space. Applying crc to it is still affine, so all we need to do is to find the kernel of it, which does exist since $33>32$. See my [solver](./solve.py) for details. The idea is pretty similar to [DownUnderCTF 2023 - hhhhh](https://blog.maple3142.net/2023/09/03/downunderctf-2023-writeups/#hhhhh).
