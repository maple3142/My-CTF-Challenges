# Integrity

* Round: 34 (2023/05)
* Category: Crypto
* Points: 125
* Solves: 6

## Description

I signed the hash of the flag to ensure the integrity of my encrypted flag. I hope I didn't make any mistake in my implementation.

## Solution

There is a typo in `sq = pow(m, dp, q)` so the signature is faulty, therefore `gcd(pow(s, e, n) - h, n) = `p, but we still don't know `h` here. We can use the fact that `h<2**256` to apply coppersmith method to find it and recover `p`.
