# First RSA

* Round: 26 (2022/10)
* Category: Crypto
* Points: 100
* Solves: 17

## Description

Alice tried to implement RSA in Python the first time, but there is a critical bug preventing Alice from getting her flag back.

## Solution

The `^` in Python is not power (`**`), but xor operator. So `pow(m, e, n)` is basically computing a degree 5 polynomial. (5 is the hamming weight of `e`) So you can bruteforce the $2^5$ possibilities of that polynomial and solve for the root.

As for solving the polynomial, more people are using bruteforce combined with binary search to solve it. But it turns out if you are using binary search then you don't even need to bruteforce the $2^5$ possibilities, I think it is because $m$ is so big that $m^5$ dominates the other terms.
