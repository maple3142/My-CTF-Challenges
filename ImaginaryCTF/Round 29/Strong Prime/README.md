# Strong Prime

* Round: 29 (2022/12)
* Category: Crypto
* Points: 100
* Solves: 9

## Description

Discrete log can be broken if the prime isn't strong enough, and that's why I use `getStrongPrime`.

## Solution

`getStrongPrime` doesn't guarantee $p$ to be [safe](https://en.wikipedia.org/wiki/Safe_and_Sophie_Germain_primes), so it is easy to see $p-1$ have many small prime factors. For each prime factor $q$ we can solve discrete log in that subgroup to get $\text{flag} \equiv x \pmod{q}$ then use CRT to recover the flag.
The padding can be handled by guessing the flag length to get another equation to the CRT system.
