# BrokenShare

* Category: Crypto
* Score: 265/500
* Solves: 26

## Description

I implemented another secret sharing this year, but it doesn’t recover the flag correctly. Can you help me fix it and recover the flag?

## Overview

It implements a threshold SSSS with $t=24, n=48, p=65537$, and all shares are given. But due to integer overflow with numpy arrays, it can't recover to the original polynomial by Lagrange interpolation.

## Solution

Since numpy use 64-bit signed integer by default, the $f(x)$ actually computes:

$$
f(x)=\left( \left( \sum_{i=0}^{t-1} a_i x^i \right) \mathop{\text{bmod}}{M} \right) \mod{p}
$$

where $a_i$ are the polynomial coefficients, $M=2^{64}$ and `bmod` denotes *balanced modulo* operation. (modulo $M$ and subtract $M$ if the result is greater than $M/2$)

For each share $(x_j,y_j)$, we can write down an equation:

$$
y_j = \left( \sum_{i=0}^{t-1} a_i x_j^i \right) - t_j M - k_j p
$$

Notice that the result of $\mathop{\text{bmod}}{M}$ is always in $[-M/2, M/2]$, the size of $k_j$ would not be too large (apprixmately bounded by $\lceil M/p \rceil$). Since $a_i$ and $k_j$ are are relatively small compared to $M$, we can construct a lattice based on :

$$
y_j \equiv \left( \sum_{i=0}^{t-1} a_i x_j^i \right) - k_j p \pmod{M}
$$

and solve it by LLL.

The reason it works is because each equation provides $\log_2(M)=64$ bits of information, so we have $64n=3072$ bits of known bits. And the unknowns are $t$ coefficients $a_i$ and $n$ $k_j$'s, which are $16t+48n=2688$ bits. Since we have more known bits than unknowns, LLL can likely determine the unique solution to it.

See [solve.py](./solution/solve.py) for the solver.
