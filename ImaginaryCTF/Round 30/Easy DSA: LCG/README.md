# Easy DSA: LCG

* Round: 30 (2023/01)
* Category: Crypto
* Points: 200
* Solves: 2

## Description

There are a lot of DSA challenges this month, so why not end this round with yet another (EC)DSA challenge?

## Solution

You can get 3 linear equations modulo `q` by eliminating `d` from ECDSA equations, and you can get another 3 linear equations modulo `p` using the LCG relations. Build a lattice with these 6 equations being columns then use LLL to find `k` and recover `d`.
