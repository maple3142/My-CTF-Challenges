# Superprime

* Category: Crypto
* Score: 248/500
* Solves: 33

## Description

Yet another cool prime generation method.

## Overview

Let $f(x)$ be `bytes_to_long(str(p).encode())`, `getSuperPrime` generates a pair of prime $(p, f(p))$.

And we are given five RSA semiprimes to factor:

$$
\begin{aligned}
n_1 &= p_1 f(p_1) \\
n_2 &= p_2 p_3 \\
n_3 &= f(p_2) f(p_3) \\
n_4 &= p_4 f(p_5) \\
n_5 &= p_5 f(p_4)
\end{aligned}
$$

## Solution

This challenge can be split into 3 levels: $n_1$, $(n_2, n_3)$ and $(n_4, n_5)$

### Level 1

It is easy to see $x f(x)$ is a strictly increasing function, so we can binary search

$$
x f(x) \stackrel{?}{<} n_1
$$

to factor it.

### Level 2

$p_2, p_3$ can be written as

$$
\begin{aligned}
p_2 &= a_0 + a_1 10 + a_2 10^2 + \cdots \\
p_3 &= b_0 + b_1 10 + b_2 10^2 + \cdots
\end{aligned}
$$

where $a_i, b_i$ are digits (in base 10) of $p_2, p_3$.

So $f(p_2), f(p_3)$ will be:

$$
\begin{aligned}
f(p_2) &= (48 + a_0) + (48 + a_1) 256 + (48 + a_2) 256^2 + \cdots \\
f(p_3) &= (48 + b_0) + (48 + b_1) 256 + (48 + b_2) 256^2 + \cdots
\end{aligned}
$$

Substitute them back to $n_2, n_3$:

$$
\begin{aligned}
n_2 &= p_2 p_3 \\
    &= (a_0 + a_1 10 + a_2 10^2 + \cdots) (b_0 + b_1 10 + b_2 10^2 + \cdots) \\
n_3 &= f(p_2) f(p_3) \\
    &= ((48 + a_0) + (48 + a_1) 256 + (48 + a_2) 256^2 + \cdots) ((48 + b_0) + (48 + b_1) 256 + (48 + b_2) 256^2 + \cdots)
\end{aligned}
$$

It is easy to observe that $n_2 \equiv a_0 b_0 \pmod{10}$ and $n_3 \equiv (48+a_0) (48+b_0) \equiv{256}$, so we can factor $n_2, n_3$ by a simple prune and search modulo the powers of $10$ and $256$ respectively.

### Level 3

Modulo $10$ and $256$ no longer works in this case, and modulo $\gcd(10, 256) = 2$ is not enough for us to use prune and search here.

We need to turn this:

$$
\begin{aligned}
n_4 &= p_4 f(p_5) \\
n_5 &= p_5 f(p_4)
\end{aligned}
$$

into

$$
\begin{aligned}
n_4 &= p_4 f(p_5) \\
    &= p_4 f(n_5 / f(p_4))
\end{aligned}
$$

first.

And we can notice that $f(p)$ changes much faster than $p$ does, so $g(p_4) = p_4 f(n_5 / f(p_4))$ is strictly increasing in $p_4$ when `len(str(p4))` is a constant. So we only need to bruteforce the top few bits to ensure `len(str(p4))` stay constant, and a simple binary search to factor them.

Crediting @lyc for finding this trick.
