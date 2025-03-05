# MDLP

* Round: 54 (2024/02)
* Category: Crypto
* Points: 150
* Solves: 6

## Description

Following the steps of @moai_man, I made another masked linear feedback shift register challenge! Except the register is a bit bigger than what you might expect 😛

## Solution

From Cayley-Hamilton theorem, we can see each untruncated `v[0]` satify a linear recurrence with its coefficients being the characteristic polynomial of the matrix. Since we are only given its truncated output, it is basically equivalent to truncated lcg parameter recovery. Just adapt the idea of stern's attack on lcg and apply a bunch of LLL to solve it.

See my solver for details and some explainations: [solve.py](./solve.py) (Also [solve_140.py](./solve_140.py) is an attempt to solve the same problem with less (only 140) outputs)

This [paper](https://eprint.iacr.org/2022/1134) also provides a better approach to solve this kind of problem generally. @lydxn also made a clear implementation of it in [solve_lyndon.py](./solve_lyndon.py).
