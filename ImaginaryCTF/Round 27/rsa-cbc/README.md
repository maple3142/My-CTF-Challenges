# RSA-CBC

* Round: 27 (2022/10)
* Category: Crypto
* Points: 75
* Solves: 35

## Description

I fixed the problem of the previous attempt in mixing RSA and block ciphers.

## Solution

The iv of each block is always known, so you can bruteforce the characters by checking

$$
(\text{iv}+x)^e \stackrel{?}{\equiv} \text{ct} \pmod{n}
$$
