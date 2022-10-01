# Box

* Round: 26 (2022/10)
* Category: Crypto
* Points: 50
* Solves: 22

## Description

`ciphertext=magic(flag)(flag)`

## Solution

The `box` is actually an affine function $f(x)=ax+b$, so you can solve for $a,b$ with the two outputs and decrypt the flag.
