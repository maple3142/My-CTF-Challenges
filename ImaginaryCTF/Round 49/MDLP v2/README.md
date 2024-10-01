# MDLP v2

* Round: 49 (2024/09)
* Category: Crypto
* Points: 125
* Solves: 2

## Description

A more secure multi-dimensional DLP challenge?!

## Solution

Solving DLP directly isn't possible, but you can see that the bases is small, this means $y_r=\prod{g_i^{x_i}}$ over integers isn't that big ($g_i$ is $i$-th prime) and it is pretty smooth. So you can apply coppersmith (or "Finding Smooth Integers in Short Intervals Using CRT Decoding") to solve for the flag.

The core idea is pretty simple, since the given $y$ satisfy $y_r \equiv y \pmod{p}$, we can write $y_r=y+kp$ for some unknown $k$. And another thing to notice is that $y_r$ is a divisor of $M=\prod{g_i^{122}}$ (122 is the ascii value of the largest lowercase letter), therefore we arrive at the following polynomial:

$$
f(x) = y + xp  \mod{M}
$$

And the $f(x)$ have a small root $k$ modulo an unknown divisor $y_r$ of $M$, so this is exactly an application of coppersmith.

That said, the small root $k$ isn't that small if you directly applied coppersmith like this. You have to incorporate the info that each character is a letter or a digit, so $x_i$ is in $[48, 122]$. So you can remove $\prod{g_i^{48}}$ from $y_r$ and $M$, then $k$ will be much smaller.

The required coppersmith parameter $X,\beta$ isn't easy to decide in this case, but you can just generate some instances locally with some fake flags and estimate the parameters yourself.

See [solve.py](./solve.py).

## Another Solution by @redender64

We know $y_r \equiv y \pmod{p}$ and $y_r \equiv 0 \pmod{\prod{g_i^{48}}}$, but applying CRT does not give us the flag because $L=p\cdot\prod{g_i^{48}}$ is not bigger than the $y_r$. And a naive bruteforce by adding $L$ iteratively does not work either.

What works is to guess to position of lowercase letters (and underscore `_`) in the `secret`, and we can replace $\prod{g_i^{48}}$ with $\prod{g_i^{e_i}}$, where $e_i=95$ (`ord('_')`) if the $i$-th character is a lowercase letter, and $e_i=48$ otherwise. For each guess, just compute crt and check if the flag is valid.

This attacks only has $2^{23}$ complexity, so it is quite feasible.
